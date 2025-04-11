from fastapi import Request, HTTPException
from .auth_utils import get_current_user

def require_roles(*roles):
    def wrapper(request: Request):
        user = get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")

        user_roles = user.get("realm_access", {}).get("roles", [])
        if not any(role in user_roles for role in roles):
            raise HTTPException(status_code=403, detail="Forbidden")

        return user
    return wrapper
