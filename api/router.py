# app/api/router.py
from fastapi import APIRouter
from api.endpoints import auth, users, proxy

# Main API router
api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(proxy.router)