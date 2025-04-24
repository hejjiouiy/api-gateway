from functools import lru_cache

from fastapi import FastAPI, Depends, HTTPException, Request, status, Response
from fastapi.responses import RedirectResponse, JSONResponse
from jose import jwt, JWTError
import httpx
from typing import List, Optional
from utils import RateLimiter
from utils import generate_internal_token

app = FastAPI()
rate_limiter = RateLimiter()
# Keycloak configuration
keycloak_config = {
    "server_url": "http://localhost:8070",
    "realm": "fms",  # Use your realm name
    "client_id": "portal",  # Use your client ID
    "client_secret": "bHqf5pjOUnyBv95kr1NThuWkfWR5lQDl",  # Use your client secret
    "callback_uri": "http://localhost:8000/callback"
}


SERVICE_MAP = {
    "mission": "http://localhost:8050",
    "achat": "http://localhost:8051",
    "stock": "http://localhost:8052"
}


# Function to get OIDC configuration from Keycloak
async def get_oidc_config():
    if not hasattr(app.state, "oidc_config"):
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{keycloak_config['server_url']}/realms/{keycloak_config['realm']}/.well-known/openid-configuration"
            )
            app.state.oidc_config = response.json()
    return app.state.oidc_config


# Add this function to your file:
async def validate_token(token):
    # Get the JWKS if not already cached
    if not hasattr(app.state, "jwks"):
        oidc_config = await get_oidc_config()
        async with httpx.AsyncClient() as client:
            response = await client.get(oidc_config["jwks_uri"])
            app.state.jwks = response.json()

    # Extract the token header to get the key ID
    token_parts = token.split('.')
    if len(token_parts) != 3:
        raise JWTError("Invalid token format")

    # Decode the header (first part of the token)
    from jose.utils import base64url_decode
    import json

    # Convert string to bytes before decoding
    header_bytes = token_parts[0].encode('ascii')
    header = json.loads(base64url_decode(header_bytes).decode('utf-8'))
    kid = header.get("kid")

    # Find the matching key in the JWKS
    key = None
    for jwk in app.state.jwks["keys"]:
        if jwk.get("kid") == kid:
            key = jwk
            break

    if not key:
        raise JWTError(f"Key ID {kid} not found in JWKS")

    # Now properly verify the token
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=keycloak_config["client_id"],
        options={"verify_signature": True}  # Enable verification!
    )


# Function to verify token and extract user info
async def get_current_user(request: Request):
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
        # Validate JWT
        payload = await validate_token(token)
        return payload
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )



# Helper function to check if user has specific roles
def require_roles(required_roles: List[str]):
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


# Root endpoint
@app.get("/")
async def root():
    return {"message": "Welcome to FastAPI with Keycloak authentication"}


# Login endpoint - redirects to Keycloak login page
@app.get("/login")
async def login(request: Request):
    client_ip = request.client.host
    oidc_config = await get_oidc_config()
    if not rate_limiter.check(f"login:{client_ip}", limit=3, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please try again later."
        )
    auth_url = (
        f"{oidc_config['authorization_endpoint']}"
        f"?client_id={keycloak_config['client_id']}"
        f"&redirect_uri={keycloak_config['callback_uri']}"
        f"&response_type=code"
        f"&scope=openid profile email"
    )
    return RedirectResponse(auth_url)


# Callback endpoint - receives the auth code from Keycloak
@app.get("/callback")
async def callback(code: str):
    oidc_config = await get_oidc_config()

    # Exchange authorization code for tokens
    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": keycloak_config["client_id"],
                "client_secret": keycloak_config["client_secret"],
                "redirect_uri": keycloak_config["callback_uri"]
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


# Profile endpoint - shows user information
@app.get("/profile")
async def profile(request:Request,user: dict = Depends(get_current_user)):
    # client_ip = request.client.host
    # if not rate_limiter.check(f"profile:{client_ip}", limit=10, window=60):
    #     raise HTTPException(
    #         status_code=429,
    #         detail="Too many accessing requests , please try again later."
    #     )
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


# Admin-only endpoint
@app.get("/admin")
async def admin_only(user: dict = Depends(require_roles(["admin"]))):
    return {"message": "You have admin access", "user": user.get("preferred_username")}


# User-only endpoint
@app.get("/user")
async def user_only(user: dict = Depends(require_roles(["user"]))):
    return {"message": "You have user access", "user": user.get("preferred_username")}


# Logout endpoint
@app.get("/logout")
async def logout(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    oidc_config = await get_oidc_config()

    # Try to revoke the token at Keycloak
    if refresh_token:
        async with httpx.AsyncClient() as client:
            await client.post(
                oidc_config["end_session_endpoint"],
                data={
                    "client_id": keycloak_config["client_id"],
                    "client_secret": keycloak_config["client_secret"],
                    "refresh_token": refresh_token
                }
            )

    # Clear cookies
    response = RedirectResponse(url="/")
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


# Token refresh endpoint
@app.get("/refresh")
async def refresh_token(request: Request):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    oidc_config = await get_oidc_config()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config["token_endpoint"],
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": keycloak_config["client_id"],
                "client_secret": keycloak_config["client_secret"]
            }
        )

        if response.status_code != 200:
            # If refresh failed, redirect to login
            redirect = RedirectResponse(url="/login")
            redirect.delete_cookie("access_token")
            redirect.delete_cookie("refresh_token")
            return redirect

        tokens = response.json()

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

@lru_cache(maxsize=1)
def get_static_token():
    return generate_internal_token()

@app.get("/header-token")
async def get_header_token(request: Request):
    client_ip = request.client.host
    if not rate_limiter.check(f"login:{client_ip}", limit=10, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many accessing requests , please try again later."
        )
    # First try to get token from cookies
    access_token = request.cookies.get("access_token")

    # If not in cookies, check authorization header
    if not access_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            access_token = auth_header.split(" ")[1]

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token = generate_internal_token()
    return token


# Function to extract the access token from request
@app.get("/get-token")
async def get_token(request: Request) -> str:
    """
    Extract the access token from the request cookies or authorization header.
    Returns the token or raises an HTTPException if no token is found.
    """
    client_ip = request.client.host
    if not rate_limiter.check(f"login:{client_ip}", limit=10, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many accessing requests , please try again later."
        )
    # First try to get token from cookies
    token = request.cookies.get("access_token")

    # If not in cookies, check authorization header
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authentication token provided",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return token


# Function to verify token validity
@app.get("/verify-token")
async def verify_token_endpoint(
    request: Request,
    token: Optional[str] = Depends(get_token)
):
    client_ip = request.client.host
    if not rate_limiter.check(f"login:{client_ip}", limit=10, window=60):
        raise HTTPException(
            status_code=429,
            detail="Too many accessing requests , please try again later."
        )
    try:
        # Retrieve OIDC config and JWKS if not already cached
        if not hasattr(app.state, "jwks"):
            oidc_config = await get_oidc_config()
            async with httpx.AsyncClient() as client:
                response = await client.get(oidc_config["jwks_uri"])
                app.state.jwks = response.json()

        # Get the public key (in production, should match 'kid' from token header)
        public_key = app.state.jwks["keys"][0]

        # Decode and validate the token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=keycloak_config["client_id"],
            options={"verify_signature": False}  # NOTE: Set to True in production!
        )

        return {
            "valid": True,
            "message": "Token is valid",
            "user": {
                "username": payload.get("preferred_username"),
                "email": payload.get("email"),
                "roles": payload.get("realm_access", {}).get("roles", []),
                "exp": payload.get("exp"),
            }
        }

    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}")


@app.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def proxy(service: str, path: str, request: Request, user=Depends(get_current_user)):
    if service not in SERVICE_MAP:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")

    url = f"{SERVICE_MAP[service]}/{path}"


    # Filter and prepare headers
    headers = dict(request.headers)
    # Remove headers that should be set by the client library or might cause conflicts
    headers_to_remove = ["host", "content-length", "connection"]
    for header in headers_to_remove:
        if header in headers:
            del headers[header]

    # Add user context headers for the downstream service
    headers["X-User-ID"] = user.get("sub", "")
    headers["X-User-Email"] = user.get("email", "")
    headers["X-User-Roles"] = ",".join(user.get("realm_access", {}).get("roles", []))
    headers["X-User-Name"] = user.get("name","")
    token = generate_internal_token()
    headers["X-Internal-Gateway-Key"] = token


    method = request.method

    # Handle different content types appropriately
    content = None
    if method in ["POST", "PUT", "PATCH"]:
        content_type = request.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                content = await request.json()
            elif "application/x-www-form-urlencoded" in content_type:
                form = await request.form()
                content = dict(form)
            elif "multipart/form-data" in content_type:
                form = await request.form()
                content = dict(form)
            else:
                # For other content types, pass the raw body
                content = await request.body()
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Error parsing request body: {str(e)}"
            )
    print(url, headers, method, content)
    # Set reasonable timeouts
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method,
                url,
                content=content,
                headers=headers,
                follow_redirects=True
            )

        # Return the response from the microservice
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.headers.get("content-type")
        )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code=504,
            detail=f"Service '{service}' timed out"
        )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=503,
            detail=f"Service '{service}' is unavailable"
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error forwarding request: {str(e)}"
        )