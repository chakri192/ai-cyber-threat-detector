import os
from datetime import datetime, timedelta, timezone
import jwt
from typing import List, Optional

JWT_SECRET = os.getenv("TSOC_JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MIN = int(os.getenv("TSOC_JWT_EXPIRY_MIN", "30"))

def create_token(scopes: List[str], subject: Optional[str] = None) -> str:
    payload = {
        "sub": subject or "tsoc-service",
        "scopes": scopes,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MIN),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> dict:
    """Decode and verify a JWT. Raises JWTError (bad signature/expired/
    malformed) or RuntimeError (secret not configured) rather than
    returning {} on failure — a caller that only checks truthiness of the
    scopes list must not be able to mistake "invalid token" for "valid
    token with no scopes"."""
    if not JWT_SECRET:
        raise RuntimeError("TSOC_JWT_SECRET not configured")
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
