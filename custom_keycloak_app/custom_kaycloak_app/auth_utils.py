from jose import jwt, JWTError
from .config import KEYCLOAK_PUBLIC_KEY, KEYCLOAK_ISSUER

def decode_jwt(token: str):
    try:
        payload = jwt.decode(
            token,
            f"-----BEGIN PUBLIC KEY-----\n{KEYCLOAK_PUBLIC_KEY}\n-----END PUBLIC KEY-----",
            algorithms=["RS256"],
            options={"verify_aud": False},
            issuer=KEYCLOAK_ISSUER,
        )
        return payload
    except JWTError:
        return None

def get_current_user(request):
    return request.state.user
