# app/main.py
import logging
from fastapi import FastAPI
from api.router import api_router
from config.settings import KEYCLOAK_CONFIG, SERVICE_MAP
from services.sync import setup_sync_scheduler
from contextlib import asynccontextmanager
from utils import RateLimiter
from dependencies import get_db

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Setup sync scheduler
sync_scheduler = setup_sync_scheduler(None, get_db)


# Startup and shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting application")
    logger.info(f"Keycloak configuration: {KEYCLOAK_CONFIG['server_url']}")
    logger.info(f"Service map: {SERVICE_MAP}")

    # Setup background synchronization
    async with sync_scheduler():
        yield

    # Shutdown
    logger.info("Shutting down application")


# Create FastAPI application
app = FastAPI(
    title="Gateway API",
    description="API Gateway with Keycloak Authentication",
    version="1.0.0",
    lifespan=lifespan,
)

# Add rate limiter to application state
app.state.rate_limiter = RateLimiter()

# Include API router
app.include_router(api_router)


# Add health check endpoint
@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)