# Document QA AI Service

A FastAPI service that uses T5-small to answer questions about web documents, including HTML structure analysis.

## Features

- Fetches raw HTML content from web URLs
- Preserves HTML structure for technical analysis
- Answers questions about document content using T5-small sequence-to-sequence model
- Simple API endpoint for document question answering
- Pattern-based fallbacks for common technical questions

## API Endpoints

- `GET /`: Health check endpoint
- `GET /health`: Detailed health check with model status
- `GET /models`: List available AI models
- `POST /question`: Answer questions about document content from URLs

## Example Usage

```bash
# Ask a question about a document
curl -X POST "http://localhost:8000/question" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://floqast.app",
    "question": "does this application have authentication?"
  }'

# Expected response:
# {"answer": "Yes, this page appears to have authentication. It contains login or password elements."}
```

## Integration

This service can be used by other components in the ars0n framework to:

1. Extract information from web content including HTML structure
2. Answer technical questions about web applications
3. Analyze application architecture and security features

## Development

To run the service locally:

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

## Model Details

This service uses the `t5-small` model, which is better at generating meaningful answers from raw HTML:

1. Preserves the full HTML structure for technical analysis
2. Uses sequence-to-sequence generation to produce more coherent answers
3. Falls back to pattern matching for common technical questions
4. Provides more reliable answers about application architecture 