from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import os
import json
import logging
import time
from model import AIModelProcessor, LlamaDocumentProcessor

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Document Question Answering Service")

# Initialize model processor once at startup
logger.info("Starting model initialization...")
model_processor = LlamaDocumentProcessor()
logger.info(f"Model initialized at startup: {model_processor.model_name}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DocumentQuestionRequest(BaseModel):
    url: str
    question: str

@app.get("/")
async def root():
    logger.debug("Root endpoint called")
    return {"status": "healthy", "service": "AI Document Question Answering"}

@app.get("/health")
async def health_check():
    """
    Check the health of the model and service
    """
    logger.debug("Health check endpoint called")
    health_info = model_processor.health_check()
    
    # Add additional service info
    health_info["service"] = "AI Document Question Answering"
    health_info["endpoints"] = ["/", "/health", "/question", "/models"]
    
    # If the model is not loaded, return a 503 Service Unavailable
    if not health_info.get("is_loaded", False):
        logger.warning("Health check reporting model not loaded")
        raise HTTPException(status_code=503, detail="Model not loaded properly")
    
    logger.debug(f"Health check result: {health_info}")    
    return health_info

@app.post("/question")
async def answer_document_question(request: DocumentQuestionRequest):
    """
    Process a question about content from a URL using T5
    """
    request_id = f"req_{int(time.time())}"
    logger.info(f"[{request_id}] Processing question for URL: {request.url}")
    logger.debug(f"[{request_id}] Question: {request.question}")
    
    start_time = time.time()
    
    try:
        logger.debug(f"[{request_id}] Starting to fetch URL content")
        
        # Use the globally initialized model processor instead of creating a new one
        result = model_processor.process_question(request.url, request.question, request_id=request_id)
        
        process_time = time.time() - start_time
        logger.info(f"[{request_id}] Successfully processed question in {process_time:.2f} seconds")
        logger.debug(f"[{request_id}] Answer length: {len(result.get('answer', ''))}")
        return result
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"[{request_id}] Error processing question after {process_time:.2f} seconds: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models")
async def list_available_models():
    logger.debug("Models endpoint called")
    models = []
    
    # Add model info using the global model_processor
    model_info = model_processor.get_model_info()
    models.append({
        "id": "t5-small",
        "name": model_info["name"],
        "type": model_info["type"],
        "description": model_info["description"]
    })
    
    return {"models": models}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 