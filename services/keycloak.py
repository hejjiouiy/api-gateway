# app/services/keycloak.py
import logging
import httpx
from fastapi import HTTPException
from config.settings import KEYCLOAK_CONFIG

logger = logging.getLogger(__name__)


async def get_oidc_config(app_state):
    """
    Get and cache the OpenID Connect configuration from Keycloak

    Args:
        app_state: The application state for caching

    Returns:
        dict: The OIDC configuration
    """
    if not hasattr(app_state, "oidc_config"):
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{KEYCLOAK_CONFIG['server_url']}/realms/{KEYCLOAK_CONFIG['realm']}/.well-known/openid-configuration"
            )
            app_state.oidc_config = response.json()
    return app_state.oidc_config


async def get_jwks(app_state):
    """
    Get and cache the JSON Web Key Set from Keycloak

    Args:
        app_state: The application state for caching

    Returns:
        dict: The JWKS
    """
    if not hasattr(app_state, "jwks"):
        oidc_config = await get_oidc_config(app_state)
        async with httpx.AsyncClient() as client:
            response = await client.get(oidc_config["jwks_uri"])
            app_state.jwks = response.json()
    return app_state.jwks


async def get_master_admin_token():
    """
    Get a master admin token that has permissions to access any realm's Admin API.
    This approach uses the master realm's admin credentials.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{KEYCLOAK_CONFIG['server_url']}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "admin",
                    "password": "admin"
                }
            )

            if response.status_code != 200:
                logger.error(f"Failed to get admin token: {response.text}")
                raise HTTPException(
                    status_code=response.status_code,
                    detail=response.text
                )

            token_data = response.json()
            return token_data["access_token"]

    except Exception as e:
        logger.error(f"Error getting admin token: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


async def refresh_token(request, app_state):
    """
    Refresh an access token using the refresh token

    Args:
        request: The FastAPI request
        app_state: The application state for OIDC config

    Returns:
        dict: The new tokens or None if refresh failed
    """
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        return None

    oidc_config = await get_oidc_config(app_state)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            oidc_config["token_endpoint"],
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": KEYCLOAK_CONFIG["client_id"],
                "client_secret": KEYCLOAK_CONFIG["client_secret"]
            }
        )

        if response.status_code != 200:
            return None

        return response.json()