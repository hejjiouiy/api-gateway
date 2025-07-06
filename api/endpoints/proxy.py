# app/api/endpoints/proxy.py
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
import httpx
import logging
from tenacity import retry, stop_after_delay, retry_if_result, retry_if_exception, before_sleep_log
import requests
from app.api.dependencies import get_current_user
from app.services.keycloak import refresh_token
from app.config.settings import SERVICE_MAP
from app.utils.token import generate_internal_token

router = APIRouter(tags=["proxy"])
logger = logging.getLogger(__name__)

# Define custom retry condition for HTTP errors with specific status codes
def is_http_error_with_retryable_status(exception):
    return (
        isinstance(exception, requests.exceptions.HTTPError) and
        exception.response is not None and
        exception.response.status_code in [500, 503, 504]
    )

@router.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@retry(
    stop=stop_after_delay(10),
    retry=(
            retry_if_result(lambda r: getattr(r, 'status_code', None) in [500, 503, 504]) |
            retry_if_exception(lambda e: isinstance(e, requests.exceptions.ConnectionError)) |
            retry_if_exception(lambda e: isinstance(e, requests.exceptions.Timeout)) |
            retry_if_exception(is_http_error_with_retryable_status)
    ),
    before_sleep=before_sleep_log(logger, logging.WARNING)
)
async def proxy(
        service: str,
        path: str,
        request: Request,
        user=Depends(get_current_user)
):
    """
    Proxy requests to microservices
    """
    # Refresh token if possible
    await refresh_token(request, request.app.state)

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
    headers["X-User-Name"] = user.get("name", "")
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

    logger.debug(f"Proxying request to {url} with method {method}")

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