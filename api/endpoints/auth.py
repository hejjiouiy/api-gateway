# app/api/endpoints/auth.py
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, JSONResponse
import httpx
from services.keycloak import get_oidc_config, refresh_token
from config.settings import KEYCLOAK_CONFIG, RATE_LIMIT_LOGIN
from utils import RateLimiter
from api.dependencies import get_current_user

router = APIRouter(tags=["authentication"])
rate_limiter = RateLimiter()


@router.get("/")
async def root():
    return {"message": "Welcome to FastAPI with Keycloak authentication"}


@router.get("/login")
async def login(request: Request):
    """Redirect to Keycloak login page"""
    client_ip = request.client.host
    oidc_config = await get_oidc_config(request.app.state)

    if not rate_limiter.check(f"login:{client_ip}", RATE_LIMIT_LOGIN, 60):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )

    auth_url = (
        f"{oidc_config['authorization_endpoint']}"
        f"?client_id={KEYCLOAK_CONFIG['client_id']}"
        f"&redirect_uri={KEYCLOAK_CONFIG['callback_uri']}"
        f"&response_type=code"
        f"&scope=openid profile email"
    )
    return RedirectResponse(auth_url)


@router.get("/callback")
async def callback(code: str, request: Request):
    """Handle callback from Keycloak after login"""
    oidc_config = await get_oidc_config(request.app.state)

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": KEYCLOAK_CONFIG["client_id"],
                "client_secret": KEYCLOAK_CONFIG["client_secret"],
                "redirect_uri": KEYCLOAK_CONFIG["callback_uri"]
            }
        )

        if response.status_code != 200:
            return JSONResponse(
                status_code=400,
                content={"message": "Token exchange failed", "details": response.text}
            )

        tokens = response.json()

    # Create response with cookies
    redirect = RedirectResponse(url="/profile")
    redirect.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        max_age=tokens["expires_in"]
    )
    redirect.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        max_age=tokens["refresh_expires_in"]
    )
    return redirect


@router.get("/profile")
async def profile(request: Request, user: dict = Depends(get_current_user)):
    """Show user profile information"""
    # Refresh token if possible
    await refresh_token(request, request.app.state)

    return {
        "message": "You are authenticated",
        "user_info": {
            "id": user.get("sub"),
            "username": user.get("preferred_username"),
            "email": user.get("email"),
            "name": user.get("name"),
            "roles": user.get("realm_access", {}).get("roles", [])
        }
    }


@router.get("/logout")
async def logout(request: Request):
    """Logout by revoking token and clearing cookies"""
    refresh_token_value = request.cookies.get("refresh_token")
    oidc_config = await get_oidc_config(request.app.state)

    # Try to revoke the token at Keycloak
    if refresh_token_value:
        async with httpx.AsyncClient() as client:
            await client.post(
                oidc_config["end_session_endpoint"],
                data={
                    "client_id": KEYCLOAK_CONFIG["client_id"],
                    "client_secret": KEYCLOAK_CONFIG["client_secret"],
                    "refresh_token": refresh_token_value
                }
            )

    # Clear cookies
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


@router.get("/refresh")
async def refresh_token_endpoint(request: Request):
    """Refresh access token using refresh token"""
    tokens = await refresh_token(request, request.app.state)

    if not tokens:
        # If refresh failed, redirect to login
        redirect = RedirectResponse(url="/login")
        redirect.delete_cookie("access_token")
        redirect.delete_cookie("refresh_token")
        return redirect

    # Update cookies with new tokens
    redirect = RedirectResponse(url="/profile")
    redirect.set_cookie(
        key="access_token",
        value=tokens["access_token"],
        httponly=True,
        max_age=tokens["expires_in"]
    )
    redirect.set_cookie(
        key="refresh_token",
        value=tokens["refresh_token"],
        httponly=True,
        max_age=tokens["refresh_expires_in"]
    )
    return redirect