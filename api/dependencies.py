# app/api/dependencies.py
from fastapi import Request, HTTPException, status, Depends
from jose import JWTError
from typing import List, Optional
from services.keycloak import get_jwks
from utils import validate_token
from config.settings import KEYCLOAK_CONFIG


async def get_current_user(request: Request):
    """
    Verify the token and extract user info

    Args:
        request: The FastAPI request

    Returns:
        dict: The user info from the token
    """
    # Try to get token from cookies
    token = request.cookies.get("access_token")

    # If not found, try to get token from Authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Get JWKS for validation
        jwks = await get_jwks(request.app.state)

        # Validate JWT
        payload = await validate_token(token, jwks, KEYCLOAK_CONFIG["client_id"])
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )


def require_roles(required_roles: List[str]):
    """
    Create a dependency that checks if the user has the required roles

    Args:
        required_roles: List of roles to check

    Returns:
        function: A dependency function
    """

    async def role_checker(user: dict = Depends(get_current_user)):
        user_roles = user.get("realm_access", {}).get("roles", [])
        for role in required_roles:
            if role not in user_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role {role} required"
                )
        return user

    return role_checker