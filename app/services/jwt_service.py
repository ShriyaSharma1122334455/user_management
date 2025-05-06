# # app/services/jwt_service.py
# from builtins import dict, str
# import jwt
# from datetime import datetime, timedelta
# from settings.config import settings

# def create_access_token(*, data: dict, expires_delta: timedelta = None):
#     to_encode = data.copy()
#     # Convert role to uppercase before encoding the JWT
#     if 'role' in to_encode:
#         to_encode['role'] = to_encode['role'].upper()
#     expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=settings.access_token_expire_minutes))
#     to_encode.update({"exp": expire})
#     encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
#     return encoded_jwt

# def decode_token(token: str):
#     try:
#         decoded = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
#         return decoded
#     except jwt.PyJWTError:
#         return None

# app/services/jwt_service.py
import jwt
from datetime import datetime, timedelta
from settings.config import settings
from typing import Optional, Dict, Any

def create_access_token(*, data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    if 'role' in to_encode:
        to_encode['role'] = to_encode['role'].upper()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

def create_verification_token(email: str) -> str:
    """Create a token specifically for email verification"""
    expire = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiration
    to_encode = {
        "sub": email,
        "exp": expire,
        "type": "email_verification"  # Differentiate from access tokens
    }
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError:
        return None

def verify_email_token(token: str) -> Optional[str]:
    """Verify an email verification token and return the email if valid"""
    decoded = decode_token(token)
    if not decoded:
        return None
    if decoded.get("type") != "email_verification":
        return None
    return decoded.get("sub")