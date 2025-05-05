# app/security.py
from builtins import Exception, ValueError, bool, int, str
import secrets
import bcrypt
import re
from logging import getLogger

# Set up logging
logger = getLogger(__name__)

# def validate_password(password: str) -> str:
#     """
#     Validate that a password meets security requirements before hashing.
    
#     Requirements:
#     - At least 8 characters long
#     - Contains at least one uppercase letter
#     - Contains at least one lowercase letter
#     - Contains at least one digit
#     - Contains at least one special character
    
#     Args:
#         password (str): Password to validate
    
#     Returns:
#         str: The validated password if it meets requirements
    
#     Raises:
#         ValueError: If password doesn't meet requirements
#     """
#     if len(password) < 8:
#         raise ValueError("Password must be at least 8 characters long")
#     if not re.search(r'[A-Z]', password):
#         raise ValueError("Password must contain at least one uppercase letter")
#     if not re.search(r'[a-z]', password):
#         raise ValueError("Password must contain at least one lowercase letter")
#     if not re.search(r'[0-9]', password):
#         raise ValueError("Password must contain at least one digit")
#     if not re.search(r'[^A-Za-z0-9]', password):
#         raise ValueError("Password must contain at least one special character")
    
#     return password

def validate_password(password: str) -> str:
    """
    Validate that a password meets security requirements before hashing.
    
    Requirements:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    
    Args:
        password (str): Password to validate
    
    Returns:
        str: The validated password if it meets requirements
    
    Raises:
        ValueError: If password doesn't meet requirements
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    
    error =[]

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(not c.isalnum() for c in password):
        raise ValueError("Password must contain at least one special character")
    
    if error:
        raise ValueError(", ".join(error))
    
    return password

def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hashes a password using bcrypt with a specified cost factor.
    
    Args:
        password (str): The plain text password to hash.
        rounds (int): The cost factor that determines the computational cost of hashing.

    Returns:
        str: The hashed password.

    Raises:
        ValueError: If hashing the password fails.
    """
    try:
        # Validate password before hashing
        validate_password(password)
        salt = bcrypt.gensalt(rounds=rounds)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    except ValueError as ve:
        raise ve  # Re-raise validation errors
    except Exception as e:
        logger.error("Failed to hash password: %s", e)
        raise ValueError("Failed to hash password") from e

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against a hashed password.
    
    Args:
        plain_password (str): The plain text password to verify.
        hashed_password (str): The bcrypt hashed password.

    Returns:
        bool: True if the password is correct, False otherwise.

    Raises:
        ValueError: If the hashed password format is incorrect or the function fails to verify.
    """
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logger.error("Error verifying password: %s", e)
        raise ValueError("Authentication process encountered an unexpected error") from e

def generate_verification_token() -> str:
    """
    Generates a secure URL-safe verification token.
    
    Returns:
        str: A 16-byte URL-safe token
    """
    return secrets.token_urlsafe(16)