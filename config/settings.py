# app/config/settings.py
import os

# Keycloak configuration
KEYCLOAK_CONFIG = {
    "server_url": os.getenv("KEYCLOAK_URL", "http://localhost:8070"),
    "realm": os.getenv("KEYCLOAK_REALM", "fms"),
    "client_id": os.getenv("KEYCLOAK_CLIENT_ID", "portal"),
    "client_secret": os.getenv("KEYCLOAK_CLIENT_SECRET", "bHqf5pjOUnyBv95kr1NThuWkfWR5lQDl"),
    "callback_uri": os.getenv("KEYCLOAK_CALLBACK_URI", "http://localhost:8000/callback")
}

# Service map for proxy
SERVICE_MAP = {
    "mission": os.getenv("SERVICE_MISSION_URL", "http://localhost:8050"),
    "achat": os.getenv("SERVICE_ACHAT_URL", "http://localhost:8051"),
    "stock": os.getenv("SERVICE_STOCK_URL", "http://localhost:8052")
}

# Rate limiting configuration
RATE_LIMIT_LOGIN = 3
RATE_LIMIT_WINDOW_LOGIN = 60
RATE_LIMIT_API = 10
RATE_LIMIT_WINDOW_API = 60
RATE_LIMIT_ADMIN = 5
RATE_LIMIT_WINDOW_ADMIN = 60