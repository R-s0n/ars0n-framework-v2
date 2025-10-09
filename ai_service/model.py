from typing import Dict, Any, List, Optional
import json
import requests
from io import BytesIO
import logging
import time
import threading
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
try:
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, T5ForConditionalGeneration
    HAS_TRANSFORMERS = True
except Exception:
    AutoModelForSeq2SeqLM = None
    AutoTokenizer = None
    T5ForConditionalGeneration = None
    HAS_TRANSFORMERS = False

try:
    import torch
except Exception:
    torch = None
import sqlite3
from collections import OrderedDict
import multiprocessing
import queue as _queue  # for Queue.Empty

# Optional BeautifulSoup for robust HTML parsing
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    BeautifulSoup = None
    HAS_BS4 = False

# Top-level helper used as a multiprocessing target so it's pickleable
def _child_inference_process(result_queue, model_name, input_text, question):
    """Child process target that loads model/tokenizer locally and runs inference.

    This is intentionally defensive: it imports transformers inside the child and
    returns error messages via the result_queue if imports or inference fail.
    """
    try:
        from transformers import AutoTokenizer, T5ForConditionalGeneration
    except Exception as e:
        try:
            result_queue.put(f"Model inference failed: transformers not available: {e}")
        except Exception:
            pass
        return

    try:
        # Import torch locally if available
        try:
            import torch as _torch
        except Exception:
            _torch = None

        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = T5ForConditionalGeneration.from_pretrained(model_name)

        # Prepare concatenated input; keep simple to avoid tokenizer issues
        prompt = (input_text or "") + "\n" + (question or "")
        inputs = tokenizer.encode(prompt, return_tensors="pt")
        # Run generation (use small max_length to limit time/memory)
        outputs = model.generate(inputs, max_length=256)
        answer = tokenizer.decode(outputs[0], skip_special_tokens=True)
        try:
            result_queue.put(answer)
        except Exception:
            pass
    except Exception as e:
        try:
            result_queue.put(f"Model inference error: {e}")
        except Exception:
            pass


def _inference_worker(in_q: multiprocessing.Queue, model_name: str):
    """Long-lived inference worker that loads model/tokenizer once and processes requests.

    Each request is a tuple (payload_dict, response_queue) where response_queue is a
    multiprocessing.Queue the caller created for this request. The worker puts the
    result into response_queue.
    """
    # Load model/tokenizer inside worker if available
    tokenizer = None
    model = None
    if HAS_TRANSFORMERS:
        try:
            from transformers import AutoTokenizer, T5ForConditionalGeneration
            try:
                import torch as _torch
            except Exception:
                _torch = None

            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = T5ForConditionalGeneration.from_pretrained(model_name)
        except Exception as e:
            # If we cannot load, log and continue; callers will receive errors
            logging.error(f"Inference worker failed to load model: {e}")

    while True:
        try:
            item = in_q.get()
            if item is None:
                # Sentinel to shut down
                break
            payload, resp_q = item
            input_text = payload.get("input_text")
            question = payload.get("question")

            # If tokenizer/model not available, return error
            if tokenizer is None or model is None:
                try:
                    resp_q.put(f"Model not available in worker")
                except Exception:
                    pass
                continue

            try:
                prompt = (input_text or "") + "\n" + (question or "")
                # Use tokenizer(...) with truncation to avoid OOM
                inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512)
                outputs = model.generate(**inputs, max_length=256)
                answer = tokenizer.decode(outputs[0], skip_special_tokens=True)
                try:
                    resp_q.put(answer)
                except Exception:
                    pass
            except Exception as e:
                try:
                    resp_q.put(f"Model inference error: {e}")
                except Exception:
                    pass

        except Exception as e:
            logging.error(f"Inference worker loop error: {e}")
            # small sleep to avoid tight loop on persistent failure
            time.sleep(0.1)

# NOTE: timeout flag is now instance-level (self.timeout_occurred)

class LlamaDocumentProcessor:
    def __init__(self, load_model: bool = True, cache_db_path: str = "llama_cache.db"):
        # Use T5 small model which is better for text generation from HTML
        self.model_name = "t5-small"
        self.loaded = False
        self.model = None
        self.tokenizer = None
        self._load_time = None
        self._init_time = time.time()
        logging.info(f"LlamaDocumentProcessor initializing with model: {self.model_name}")
        # Cache configuration
        self.cache_enabled = True
        self.cache_ttl = 300  # seconds
        self.cache_backend = "memory"  # "memory" or "sqlite"
        # In-memory cache as an OrderedDict for LRU eviction: key -> {"response": ..., "ts": ...}
        self.cache_max_entries = 1000
        self._cache = OrderedDict()
        self._cache_lock = threading.Lock()
        # Lock for sqlite access (if used)
        self._sqlite_lock = threading.Lock()
        self._sqlite_conn = None
        self.cache_db_path = cache_db_path
        self._init_cache()

        # Prepare a requests Session with retries/backoff
        try:
            self._session = requests.Session()
            retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retries)
            self._session.mount("https://", adapter)
            self._session.mount("http://", adapter)
        except Exception:
            self._session = requests

        # Instance-level timeout flag (thread/process-safe per instance)
        self.timeout_occurred = False

        # Allow skipping model load during tests/dev
        # Start a long-lived inference worker if requested
        self._in_q = None
        self._worker = None
        if load_model:
            try:
                self._in_q = multiprocessing.Queue()
                self._worker = multiprocessing.Process(target=_inference_worker, args=(self._in_q, self.model_name))
                self._worker.daemon = True
                self._worker.start()
                logging.info("Inference worker started")
            except Exception as e:
                logging.error(f"Failed to start inference worker: {e}")
        
    def _load_model(self):
        """Load the model and tokenizer"""
        # Defensive: ensure transformers is available before trying to load
        if not HAS_TRANSFORMERS:
            logging.error("Cannot load model: 'transformers' package is not installed.")
            self.loaded = False
            self.tokenizer = None
            self.model = None
            return

        try:
            logging.info(f"Loading model: {self.model_name}")
            start_time = time.time()

            # Initialize tokenizer
            logging.debug("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            logging.debug("Tokenizer loaded successfully")

            # Initialize model
            logging.debug("Loading model weights...")
            self.model = T5ForConditionalGeneration.from_pretrained(
                self.model_name,
                torch_dtype=(torch.float32 if torch is not None else None),
                device_map="auto"
            )
            logging.debug("Model weights loaded successfully")

            self._load_time = time.time() - start_time
            self.loaded = True
            logging.info(f"Successfully loaded {self.model_name} in {self._load_time:.2f} seconds")

            # Log device information (guard torch presence)
            if (torch is not None) and getattr(torch, 'cuda', None) is not None and torch.cuda.is_available():
                try:
                    device_name = torch.cuda.get_device_name(0)
                    memory_allocated = torch.cuda.memory_allocated(0) / (1024 ** 3)
                    memory_reserved = torch.cuda.memory_reserved(0) / (1024 ** 3)
                    logging.info(f"Model loaded on CUDA device: {device_name}")
                    logging.info(f"GPU memory allocated: {memory_allocated:.2f} GB")
                    logging.info(f"GPU memory reserved: {memory_reserved:.2f} GB")
                except Exception:
                    logging.info("Model loaded but failed to query CUDA details")
            else:
                logging.info("Model loaded on CPU or torch not available")

        except Exception as e:
            logging.error(f"Error loading model: {str(e)}")
            self.loaded = False
            self.tokenizer = None
            self.model = None

    def health_check(self) -> Dict[str, Any]:
        """Return the health status of the model"""
        logging.debug("Performing health check")
        status = {
            "model_name": self.model_name,
            "is_loaded": self.loaded,
            "init_time": self._init_time,
            "load_time": self._load_time
        }
        
        if not self.loaded:
            status["error"] = "Model failed to load. Check logs for details."
        
        # If running on CUDA, add GPU info
        if self.loaded and (torch is not None) and getattr(torch, 'cuda', None) is not None and torch.cuda.is_available():
            status["cuda_available"] = True
            try:
                status["cuda_device"] = torch.cuda.get_device_name(0)
                status["cuda_memory"] = {
                    "allocated": f"{torch.cuda.memory_allocated(0) / 1024**3:.2f} GB",
                    "reserved": f"{torch.cuda.memory_reserved(0) / 1024**3:.2f} GB"
                }
            except Exception:
                status["cuda_device"] = "unknown"
                status["cuda_memory"] = {}
        else:
            status["cuda_available"] = False
            
        return status

    def _init_cache(self):
        """Initialize cache backend (memory or sqlite)"""
        if not self.cache_enabled:
            return
        if self.cache_backend == "sqlite":
            try:
                db_path = self.cache_db_path
                self._sqlite_conn = sqlite3.connect(db_path, check_same_thread=False)
                cur = self._sqlite_conn.cursor()
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS cache (cache_key TEXT PRIMARY KEY, response TEXT, timestamp REAL)"
                )
                # Create index on timestamp for efficient cleanup/queries
                cur.execute("CREATE INDEX IF NOT EXISTS idx_ts ON cache(timestamp)")
                # Use WAL for better concurrent performance when possible
                try:
                    cur.execute("PRAGMA journal_mode=WAL")
                except Exception:
                    pass
                self._sqlite_conn.commit()
                logging.info(f"SQLite cache initialized at {db_path}")
            except Exception as e:
                logging.error(f"Failed to initialize sqlite cache: {e}. Falling back to memory cache.")
                self.cache_backend = "memory"

    def _cache_key(self, url: str, question: str) -> str:
        # Use a fixed-length hash to avoid very long keys
        import hashlib
        # Include model name so cache is invalidated when model changes
        key_raw = f"{url}||{question}||{self.model_name}"
        return hashlib.sha256(key_raw.encode('utf-8')).hexdigest()

    def _get_cached_answer(self, url: str, question: str):
        """Return cached answer or None if expired/not found"""
        if not self.cache_enabled:
            return None
        key = self._cache_key(url, question)
        now = time.time()

        if self.cache_backend == "memory":
            with self._cache_lock:
                entry = self._cache.get(key)
                if entry and (now - entry["ts"]) <= self.cache_ttl:
                    # Promote this key to most-recently-used
                    try:
                        self._cache.move_to_end(key)
                    except Exception:
                        pass
                    logging.debug(f"Cache hit (memory) for key: {key}")
                    return entry["response"]
                # stale or missing
                if entry:
                    logging.debug(f"Cache expired for key: {key}")
                    del self._cache[key]
            return None

        # sqlite backend
        try:
            with self._sqlite_lock:
                cur = self._sqlite_conn.cursor()
                cur.execute("SELECT response, timestamp FROM cache WHERE cache_key = ?", (key,))
                row = cur.fetchone()
            if row:
                resp_json, ts = row
                if (now - ts) <= self.cache_ttl:
                    logging.debug(f"Cache hit (sqlite) for key: {key}")
                    return json.loads(resp_json)
                else:
                    logging.debug(f"Cache expired (sqlite) for key: {key}")
                    cur.execute("DELETE FROM cache WHERE cache_key = ?", (key,))
                    self._sqlite_conn.commit()
        except Exception as e:
            logging.error(f"Error reading sqlite cache: {e}")
        return None

    def _set_cached_answer(self, url: str, question: str, response):
        """Store answer in cache"""
        if not self.cache_enabled:
            return
        key = self._cache_key(url, question)
        now = time.time()

        if self.cache_backend == "memory":
            with self._cache_lock:
                # If key exists, remove it so we can re-insert and mark as most-recently-used
                if key in self._cache:
                    try:
                        del self._cache[key]
                    except Exception:
                        pass
                self._cache[key] = {"response": response, "ts": now}
                # Evict oldest entries if we exceed the configured max
                while len(self._cache) > self.cache_max_entries:
                    try:
                        evicted_key, _ = self._cache.popitem(last=False)
                        logging.debug(f"Evicted cache key due to size limit: {evicted_key}")
                    except Exception:
                        break
            logging.debug(f"Cached answer in memory for key: {key}")
            return

        try:
            resp_json = json.dumps(response)
            with self._sqlite_lock:
                cur = self._sqlite_conn.cursor()
                cur.execute(
                    "INSERT OR REPLACE INTO cache(cache_key, response, timestamp) VALUES(?,?,?)",
                    (key, resp_json, now)
                )
                self._sqlite_conn.commit()
            logging.debug(f"Cached answer in sqlite for key: {key}")
        except Exception as e:
            logging.error(f"Error writing to sqlite cache: {e}")

    def _cleanup_expired_cache(self):
        """Remove expired rows from sqlite cache. Callable periodically."""
        if not self.cache_enabled or self.cache_backend != "sqlite" or self._sqlite_conn is None:
            return
        try:
            cutoff = time.time() - self.cache_ttl
            with self._sqlite_lock:
                cur = self._sqlite_conn.cursor()
                cur.execute("DELETE FROM cache WHERE timestamp < ?", (cutoff,))
                self._sqlite_conn.commit()
        except Exception as e:
            logging.debug(f"Failed to cleanup expired cache: {e}")

    def fetch_url_content(self, url: str, request_id: str = "") -> str:
        """
        Fetch content from a URL
        
        Args:
            url: URL to fetch content from
            request_id: Unique identifier for the request for logging purposes
            
        Returns:
            String containing the fetched content
        """
        logging.debug(f"[{request_id}] Fetching content from URL: {url}")
        start_time = time.time()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        logging.debug(f"[{request_id}] Sending HTTP request to {url}")
        try:
            resp = self._session.get(url, headers=headers, timeout=10, stream=False)
            resp.raise_for_status()
            content = resp.text
            content_length = len(content)
            fetch_time = time.time() - start_time
            logging.debug(f"[{request_id}] Successfully fetched {content_length} characters in {fetch_time:.2f} seconds")
            return content
        except Exception as e:
            fetch_time = time.time() - start_time
            logging.error(f"[{request_id}] Error fetching URL after {fetch_time:.2f} seconds: {str(e)}")
            raise RuntimeError(f"Failed to fetch {url}: {e}")

    def close(self):
        """Cleanly shut down the inference worker and database connections."""
        # Shutdown worker
        try:
            if self._in_q is not None:
                try:
                    self._in_q.put(None)
                except Exception:
                    pass
            if self._worker is not None:
                try:
                    self._worker.join(timeout=2)
                except Exception:
                    pass
        except Exception:
            pass

        # Close sqlite
        try:
            if self._sqlite_conn is not None:
                try:
                    self._sqlite_conn.close()
                except Exception:
                    pass
                self._sqlite_conn = None
        except Exception:
            pass

        # Close requests session
        try:
            if hasattr(self, "_session") and self._session is not None and isinstance(self._session, requests.Session):
                try:
                    self._session.close()
                except Exception:
                    pass
        except Exception:
            pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
    
    def clean_html(self, html_content):
        """Clean HTML content to make it more suitable for text processing.

        Prefer using BeautifulSoup when available for robust parsing; otherwise
        fall back to the existing regex-based approach.
        """
        if HAS_BS4 and BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(html_content, "html.parser")
                # Remove script/style tags from DOM for cleaner text
                for s in soup(["script", "style"]):
                    s.extract()
                text = soup.get_text(separator=" ", strip=True)
                return text
            except Exception:
                # Fall back to regex method on any parsing error
                pass

        # Fallback: lightweight regex cleaning
        # Remove DOCTYPE declaration
        html_content = re.sub(r'<!DOCTYPE[^>]*>', '', html_content, flags=re.IGNORECASE)
        # Remove script and style elements
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        # Replace tags with spaces to preserve text boundaries
        html_content = re.sub(r'<[^>]*>', ' ', html_content)
        # Remove extra whitespace
        html_content = re.sub(r'\s+', ' ', html_content).strip()
        return html_content
    
    def extract_meta_info(self, html_content):
        """Extract useful metadata from HTML"""
        meta_info = ""
        
        # Extract title
        title_match = re.search(r'<title>(.*?)</title>', html_content, re.IGNORECASE)
        if title_match:
            meta_info += f"Title: {title_match.group(1).strip()}\n"
        
        # Extract meta description
        desc_match = re.search(r'<meta\s+name=["|\']description["|\'][^>]*content=["|\']([^"|\']*)["|\']', html_content, re.IGNORECASE)
        if desc_match:
            meta_info += f"Description: {desc_match.group(1).strip()}\n"
        
        # Extract common app identifiers
        if re.search(r'login|sign in|password', html_content, re.IGNORECASE):
            meta_info += "The page contains authentication elements (login forms or password fields).\n"
            
        return meta_info
    
    def inference_with_timeout(self, input_text, question, timeout=30):
        """Run model inference inside a separate process with a timeout.

        NOTE: this implementation starts a new process which will load the model
        and tokenizer inside the child. That ensures the parent can terminate the
        child on timeout, but it also means the model is re-loaded in the child
        (costly). If you prefer cancellation without re-loading, consider an
        alternative design (e.g. send inputs to a dedicated inference worker process).
        """
        # Reset instance flag
        self.timeout_occurred = False

        # Prefer sending the request to a long-lived worker if available
        self.timeout_occurred = False
        if self._worker is not None and self._worker.is_alive() and self._in_q is not None:
            resp_q = multiprocessing.Queue()
            payload = {"input_text": input_text, "question": question}
            try:
                self._in_q.put((payload, resp_q))
            except Exception as e:
                logging.error(f"Failed to submit to inference worker: {e}")
                try:
                    resp_q.close()
                    resp_q.join_thread()
                except Exception:
                    pass
                # Fallback to spawning a child process
            else:
                try:
                    # Wait for worker response
                    result = resp_q.get(timeout=timeout)
                    try:
                        resp_q.close()
                        resp_q.join_thread()
                    except Exception:
                        pass
                    return result
                except _queue.Empty:
                    # Worker did not respond in time
                    self.timeout_occurred = True
                    try:
                        resp_q.close()
                        resp_q.join_thread()
                    except Exception:
                        pass
                    return "Inference timed out. The model took too long to respond."
                except Exception as e:
                    logging.error(f"Error getting response from worker: {e}")
                    try:
                        resp_q.close()
                        resp_q.join_thread()
                    except Exception:
                        pass
                    # Fall through to child-process fallback

        # Fallback: spawn a short-lived child that loads model locally
        result_queue = multiprocessing.Queue()
        proc = multiprocessing.Process(
            target=_child_inference_process,
            args=(result_queue, self.model_name, input_text, question),
        )
        proc.start()
        proc.join(timeout)

        if proc.is_alive():
            try:
                proc.terminate()
            except Exception:
                pass
            proc.join()
            self.timeout_occurred = True
            try:
                result_queue.close()
                result_queue.join_thread()
            except Exception:
                pass
            return "Inference timed out. The model took too long to respond."

        # Try to get result from queue
        try:
            result = None
            try:
                result = result_queue.get_nowait()
            except Exception:
                result = None
            try:
                result_queue.close()
                result_queue.join_thread()
            except Exception:
                pass
            return result
        except Exception as e:
            logging.error(f"Error retrieving inference result from child process: {e}")
            return f"Error: {e}"

    def analyze_html_content(self, content, question, request_id=""):
        """
        Analyze HTML content using simple pattern matching for basic website questions
        This fallback is useful when the model fails to provide good answers
        """
        logging.debug(f"[{request_id}] Performing pattern-based HTML analysis")
        
        # Make search case-insensitive
        content_lower = content.lower()
        question_lower = question.lower()
        
        # Check if this is an authentication page
        if "authentication" in question_lower or "login" in question_lower or "sign in" in question_lower:
            if "login" in content_lower or "signin" in content_lower or "password" in content_lower:
                return "Yes, this page appears to have authentication. It contains login or password elements."
            else:
                return "No, this page doesn't appear to have authentication elements."
                
        # Check what kind of application it is
        if "what is this" in question_lower or "what is the purpose" in question_lower:
            # Look for title
            title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
            meta_desc_match = re.search(r'<meta\s+name=["|\']description["|\'][^>]*content=["|\']([^"|\']*)["|\']', content, re.IGNORECASE)
            
            if title_match:
                title = title_match.group(1).strip()
                if meta_desc_match:
                    desc = meta_desc_match.group(1).strip()
                    return f"This appears to be {title}. {desc}"
                return f"This appears to be {title}."
            
            # If there's a login form 
            if "login" in content_lower:
                return "This appears to be a login page for an application."
                
        # Check for specific elements
        if "dashboard" in content_lower:
            return "This appears to be a dashboard or admin interface."
        
        # Check for technologies
        if "technology" in question_lower or "technologies" in question_lower or "framework" in question_lower:
            techs = []
            
            # Common JS frameworks
            if "react" in content_lower:
                techs.append("React")
            if "angular" in content_lower:
                techs.append("Angular")
            if "vue" in content_lower:
                techs.append("Vue.js")
            if "jquery" in content_lower:
                techs.append("jQuery")
                
            # Server side techs
            if "asp.net" in content_lower:
                techs.append("ASP.NET")
            if "laravel" in content_lower:
                techs.append("Laravel")
            if "django" in content_lower:
                techs.append("Django")
            if "express" in content_lower or "node.js" in content_lower:
                techs.append("Node.js")
                
            if techs:
                return f"This web application appears to use: {', '.join(techs)}"
        
        # For "what does this app do" questions
        if "what does" in question_lower and ("do" in question_lower or "purpose" in question_lower):
            # Look for title and metadata
            title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()
                if "login" in content_lower:
                    return f"This is the login page for {title}. It appears to be an application that requires authentication."
                return f"This appears to be {title}."
            
            if "login" in content_lower or "sign in" in content_lower:
                return "This appears to be a login page for a web application that requires authentication."
        
        # Default fallback
        return None
    
    def process_question(self, url: str, question: str, request_id: str = "") -> Dict[str, Any]:
        """
        Process a question about content from a URL using T5
        
        Args:
            url: URL to fetch content from
            question: Question to ask about the content
            request_id: Unique identifier for the request for logging purposes
            
        Returns:
            Dictionary with answer key containing the model's response
        """
        logging.debug(f"[{request_id}] Starting to process question")
        
        try:
            # Check cache first
            cached = self._get_cached_answer(url, question)
            if cached:
                logging.info(f"[{request_id}] Returning cached answer")
                return {"answer": cached}

            # Fetch content from URL
            content = self.fetch_url_content(url, request_id)
            content_length = len(content)
            logging.debug(f"[{request_id}] Processing content of length {content_length}")
            
            # First try pattern-based analysis for common simple questions
            pattern_answer = self.analyze_html_content(content, question, request_id)
            if pattern_answer:
                logging.info(f"[{request_id}] Using pattern-based answer")
                # cache pattern answer
                self._set_cached_answer(url, question, pattern_answer)
                return {"answer": pattern_answer}
            
            # If model isn't loaded, try to load it
            if not self.loaded:
                if self.model is None:
                    logging.info(f"[{request_id}] Model not loaded, attempting to load now...")
                    self._load_model()
                
                # If still not loaded, return simple analysis
                if not self.loaded:
                    logging.error(f"[{request_id}] Model still not loaded after retry")
                    return {
                        "answer": "Based on the page content, I can't provide a definitive answer without the AI model."
                    }
            
            # Extract metadata from HTML for additional context
            meta_info = self.extract_meta_info(content)
            
            # Clean HTML content for better processing
            cleaned_content = self.clean_html(content)
            
            # Combine meta info with cleaned content
            processed_content = meta_info + "\n" + cleaned_content
            
            logging.debug(f"[{request_id}] Starting model inference with timeout")
            inference_start = time.time()
            
            result = self.inference_with_timeout(
                input_text=processed_content,
                question=question,
                timeout=30  # 30 second timeout
            )
            
            inference_time = time.time() - inference_start
            
            if self.timeout_occurred:
                logging.error(f"[{request_id}] Inference timed out after 30 seconds")
                return {"answer": "The model took too long to process your request. Please try a simpler question or a different URL."}
            
            logging.debug(f"[{request_id}] Model inference completed in {inference_time:.2f} seconds")
            
            # Process the result
            if isinstance(result, str):
                if "Error:" in result:
                    # If there was an error, try the fallback
                    if "Numpy is not available" in result:
                        fallback_answer = "This appears to be a web application with a login page."
                        logging.info(f"[{request_id}] Using fallback answer due to model error")
                        return {"answer": fallback_answer}
                    else:
                        logging.error(f"[{request_id}] Model error: {result}")
                        return {"answer": "I encountered an issue analyzing this page. " + result}
                else:
                    # Good response from model
                    answer = result.strip()
                    
                    # Post-process answer to clean up any remaining HTML tags
                    answer = re.sub(r'<[^>]*>', '', answer)
                    answer = re.sub(r'\s+', ' ', answer).strip()
            else:
                # Unexpected result type
                answer = "Based on the content, I couldn't find a specific answer to your question."
            
            # If the answer is too short or looks like HTML, provide a fallback
            if len(answer) < 10 or re.search(r'</?[a-z]+>', answer):
                if "login" in content.lower():
                    answer = "This appears to be a login page for a web application."
                else:
                    title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()
                        answer = f"This appears to be {title}."
                    else:
                        answer = "This is a web page that requires further analysis to determine its purpose."
            
            logging.info(f"[{request_id}] Total processing time: {inference_time:.2f} seconds")
            
            # Cache the final answer
            try:
                self._set_cached_answer(url, question, answer)
            except Exception:
                logging.debug("Failed to cache the final answer; continuing without cache.")

            # Only return the answer for a cleaner response
            return {"answer": answer}
        
        except Exception as e:
            logging.error(f"[{request_id}] Error processing document question: {str(e)}")
            return {"answer": f"Error processing your question: {str(e)}"}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Return information about the model"""
        return {
            "name": self.model_name,
            "type": "t5-seq2seq",
            "description": "T5-small model for HTML understanding and question answering",
            "is_loaded": self.loaded
        }

class AIModelProcessor:
    def __init__(self, model_name: str = "default"):
        self.model_name = model_name
        self.models = self._load_available_models()
        
    def _load_available_models(self) -> Dict[str, Any]:
        return {
            "default": {
                "name": "Default Extractor",
                "type": "rule-based",
                "capabilities": ["general extraction"]
            },
            "general-extractor": {
                "name": "General Information Extractor",
                "type": "transformer",
                "capabilities": ["entity extraction", "categorization", "summarization"]
            },
            "vulnerability-analyzer": {
                "name": "Vulnerability Analyzer",
                "type": "specialized",
                "capabilities": ["vulnerability detection", "severity assessment"]
            }
        }
    
    def process_text(self, text: str, data_type: str = "general", 
                     extraction_fields: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Process unstructured text data and return structured information
        
        In a real implementation, this would use transformers or other ML models
        to extract structured information from the text.
        """
        
        # Mock implementation - would be replaced with actual AI model
        if extraction_fields:
            result = {}
            for field in extraction_fields:
                result[field] = self._extract_field(text, field)
            return result
        
        if data_type == "vulnerability":
            return self._extract_vulnerability_info(text)
        
        # Default to general extraction
        return self._extract_general_info(text)
    
    def _extract_field(self, text: str, field: str) -> Any:
        # Mock field extraction based on field name
        field_mapping = {
            "ip_addresses": ["192.168.1.1", "10.0.0.1"],
            "urls": ["https://example.com"],
            "email": "sample@example.com",
            "date": "2023-01-01",
            "organizations": ["ACME Corp", "Example LLC"],
            "people": ["John Smith", "Jane Doe"],
            "locations": ["New York", "San Francisco"]
        }
        
        return field_mapping.get(field, f"Extracted content for {field}")
    
    def _extract_general_info(self, text: str) -> Dict[str, Any]:
        # Mock general information extraction
        return {
            "entities": ["Sample Entity 1", "Sample Entity 2"],
            "categories": ["Sample Category"],
            "summary": "This is a sample summary of the provided text.",
            "sentiment": "neutral",
            "key_phrases": ["key phrase 1", "key phrase 2"]
        }
    
    def _extract_vulnerability_info(self, text: str) -> Dict[str, Any]:
        # Mock vulnerability information extraction
        return {
            "cve_id": "CVE-2023-XXXX",
            "severity": "High",
            "affected_systems": ["System X", "System Y"],
            "description": "Sample vulnerability description",
            "mitigation": "Update to latest version",
            "references": ["https://example.com/cve/reference"]
        }
    
    def get_model_info(self) -> Dict[str, Any]:
        return self.models.get(self.model_name, self.models["default"]) 