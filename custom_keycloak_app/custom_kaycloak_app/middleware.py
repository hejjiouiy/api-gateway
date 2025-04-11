from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from .auth_utils import decode_jwt

class VerifyUserMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.headers.get("Authorization")
        if not token or not token.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing token")

        token = token.split(" ")[1]
        user = decode_jwt(token)

        if not user:
            raise HTTPException(status_code=401, detail="Invalid token")

        request.state.user = user
        return await call_next(request)
a