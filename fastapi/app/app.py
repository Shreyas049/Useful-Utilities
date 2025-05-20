from fastapi import FastAPI, Request, Response, Security, HTTPException, status, Depends
from fastapi.security import APIKeyHeader
from secrets import compare_digest
from contextlib import asynccontextmanager
from pydantic.main import BaseModel
from typing import List
import json
import logging

from utils import config
from model.main import main


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    # initialize global variables here
    global posgresql

    yield
    # release & clean-up
    # posgresql.close()
    del posgresql

app = FastAPI(lifespan=app_lifespan)

class APIInput(BaseModel):
    ID: str = None
    DATA: List = None

def get_dependencies():
    return None

# Define the API key header scheme
api_key_header = APIKeyHeader(name=config.api_auth_name, auto_error=False)

# This function uses Security to declare it's a security verification function
async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Verify API auth key using Security function. Security dependency of FastAPI indicated that this is a security verification.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key header is missing"
        )
    
    if not compare_digest(api_key, config.API_AUTH_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    
    return api_key

@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Skip authentication for docs, OpenAPI schema & other endpoints
    if request.url.path in ["/docs", "/openapi.json", "/redoc", "/health", "/live", "/ready"]:
        return await call_next(request)
    
    try:
        # Get API key using the header scheme
        api_key = await api_key_header(request)
        # Verify the API key using our security function
        await verify_api_key(api_key)
        
        response = await call_next(request)
        return response
        
    except HTTPException as auth_error:
        return Response(
            content=json.dumps({"detail": auth_error.detail}),
            status_code=auth_error.status_code,
            media_type="application/json"
        )
    except Exception as e:
        logging.error(f"Middleware error: {e}")
        return Response(
            content=json.dumps({"detail": "Internal server error"}),
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            media_type="application/json"
        )

@app.get("/live")
async def liveness_probe():
    logging.info(f"Live, status: ok")
    return {"status": "OK"}

@app.get("/ready")
async def readyness_probe():
    logging.info(f"Ready, status: ok")
    return {"status": "OK"}

@app.get("/health")
async def health_probe():
    logging.info(f"Health, status: ok")
    return {"status": "OK"}


# security function directly in endpoint
@app.post("/some_endpoint")
async def some_endpoint(api_key: str = Security(verify_api_key)):
    # This endpoint will require API key verification
    return {"message": "Authenticated!"}

@app.post("/call_azure_openai")
async def call_azure_openai(api_input: APIInput, dependencies=Depends(get_dependencies)):
    event_id = api_input.ID
    event_data = api_input.DATA

    response = main()

    return Response(
        content=json.dumps({"status": response["status"], "message": response["message"]}),
        media_type="application/json",
        status_code=response["status_code"]
    )
