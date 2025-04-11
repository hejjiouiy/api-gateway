import os
from typing import List

KEYCLOAK_PUBLIC_KEY = os.getenv("KEYCLOAK_PUBLIC_KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxCthyvYyYrSbT1t0Y7c7hrGq3ZIcGxJUX9gKkeHqWgZolgy7NfC5pSFSJOOPu0ql1UrHHxow1naXfw0uY2S/R0EbIUcy7I9YsbRBDZIzcOLBNEU8vuyAl21FEA/2MsUyG8RPhR6IETBxHvtU2WJ3MejAJiFu/XA9OHzyPwY+SqNK2bl/WLJK/90Sry61PpAqivjmUzCBnN0O2PymQ1yVMcF0bQxteZna7QqzEyDAeCgYnaewx7JLnPLpMrUrl/FL7apKhm6gDmkNk98bnpKOByd+R7s9lcdy3TD/qAECf+/VSZRU3cAkGMiimz+vKt+8QEXevQjalOtdr1uML/gp0QIDAQAB")
KEYCLOAK_ISSUER = os.getenv("KEYCLOAK_ISSUER", "http://localhost:8070/realms/myrealm")
ALLOWED_ROLES: List[str] = os.getenv("ALLOWED_ROLES", "admin,user").split(",")
