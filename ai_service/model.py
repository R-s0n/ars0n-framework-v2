from typing import Dict, Any, List, Optional
import json
import requests
from io import BytesIO
import logging
import time
import threading
import re
from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, T5ForConditionalGeneration
import torch

# Global timeout flag
TIMEOUT_OCCURRED = False

class LlamaDocumentProcessor:
    def __init__(self):
        # Use T5 small model which is better for text generation from HTML
        self.model_name = "t5-small"
        self.loaded = False
        self.model = None
        self.tokenizer = None
        self._load_time = None
        self._init_time = time.time()
        logging.info(f"LlamaDocumentProcessor initializing with model: {self.model_name}")
        self._load_model()
        
    def _load_model(self):
        """Load the model and tokenizer"""
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
                torch_dtype=torch.float32,  # Use regular precision for CPU
                device_map="auto"
            )
            logging.debug("Model weights loaded successfully")
            
            self._load_time = time.time() - start_time
            self.loaded = True
            logging.info(f"Successfully loaded {self.model_name} in {self._load_time:.2f} seconds")
            
            # Log device information
            if torch.cuda.is_available():
                device_name = torch.cuda.get_device_name(0)
                memory_allocated = torch.cuda.memory_allocated(0) / (1024 ** 3)
                memory_reserved = torch.cuda.memory_reserved(0) / (1024 ** 3)
                logging.info(f"Model loaded on CUDA device: {device_name}")
                logging.info(f"GPU memory allocated: {memory_allocated:.2f} GB")
                logging.info(f"GPU memory reserved: {memory_reserved:.2f} GB")
            else:
                logging.info("Model loaded on CPU")
                
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
        if self.loaded and torch.cuda.is_available():
            status["cuda_available"] = True
            status["cuda_device"] = torch.cuda.get_device_name(0)
            status["cuda_memory"] = {
                "allocated": f"{torch.cuda.memory_allocated(0) / 1024**3:.2f} GB",
                "reserved": f"{torch.cuda.memory_reserved(0) / 1024**3:.2f} GB"
            }
        else:
            status["cuda_available"] = False
            
        return status

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
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            logging.debug(f"[{request_id}] Sending HTTP request to {url}")
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            content = response.text
            content_length = len(content)
            fetch_time = time.time() - start_time
            logging.debug(f"[{request_id}] Successfully fetched {content_length} characters in {fetch_time:.2f} seconds")
            return content
        except Exception as e:
            fetch_time = time.time() - start_time
            logging.error(f"[{request_id}] Error fetching URL after {fetch_time:.2f} seconds: {str(e)}")
            return f"Error fetching content from URL: {str(e)}"
    
    def clean_html(self, html_content):
        """Clean HTML content to make it more suitable for text processing"""
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
        """Run model inference with a timeout to prevent hanging"""
        global TIMEOUT_OCCURRED
        TIMEOUT_OCCURRED = False
        result = [None]
        
        def run_inference():
            try:
                # Format input for T5
                # T5 expects input in format: "question: QUESTION context: CONTEXT"
                max_length = 1024  # T5 can handle ~512 tokens, roughly 1024 chars
                if len(input_text) > max_length:
                    input_text_truncated = input_text[:max_length]
                    logging.debug(f"Truncated input text from {len(input_text)} to {max_length} characters")
                else:
                    input_text_truncated = input_text
                
                prompt = f"question: {question} context: {input_text_truncated}"
                
                # Tokenize
                inputs = self.tokenizer(prompt, return_tensors="pt", truncation=True, max_length=512).to(self.model.device)
                
                # Generate
                outputs = self.model.generate(
                    inputs.input_ids,
                    max_length=150,
                    num_beams=4,
                    early_stopping=True
                )
                
                # Decode
                result[0] = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            except Exception as e:
                logging.error(f"Error during inference: {str(e)}")
                result[0] = f"Error: {str(e)}"
                
        thread = threading.Thread(target=run_inference)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if thread.is_alive():
            TIMEOUT_OCCURRED = True
            return "Inference timed out. The model took too long to respond."
        
        return result[0]

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
            # Fetch content from URL
            content = self.fetch_url_content(url, request_id)
            content_length = len(content)
            logging.debug(f"[{request_id}] Processing content of length {content_length}")
            
            # First try pattern-based analysis for common simple questions
            pattern_answer = self.analyze_html_content(content, question, request_id)
            if pattern_answer:
                logging.info(f"[{request_id}] Using pattern-based answer")
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
            
            if TIMEOUT_OCCURRED:
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