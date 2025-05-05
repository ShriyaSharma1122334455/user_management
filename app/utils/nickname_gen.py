# from builtins import str
# import random


# def generate_nickname() -> str:
#     """Generate a URL-safe nickname using adjectives and animal names."""
#     adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
#     animals = ["panda", "fox", "raccoon", "koala", "lion"]
#     number = random.randint(0, 999)
#     return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"


# Updated nickname_gen.py
import random
import uuid
import re
from typing import Optional
# Import your actual database dependencies here
# from app.db.session import SessionLocal
# from app.repositories.user_repository import UserRepository

def is_valid_nickname_format(nickname: str) -> bool:
    """Check if nickname meets basic format requirements"""
    return (len(nickname) >= 3 and 
            len(nickname) <= 32 and 
            bool(re.match(r'^[\w-]+$', nickname)))

def is_nickname_unique(nickname: str) -> bool:
    """Check if nickname is unique in database"""
    # Implementation example:
    # db = SessionLocal()
    # return UserRepository.get_by_nickname(db, nickname) is None
    return True  # Placeholder - implement actual DB check

def generate_random_nickname() -> str:
    """Generate a random nickname that meets format requirements"""
    adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
    animals = ["panda", "fox", "raccoon", "koala", "lion"]
    number = random.randint(0, 999)
    return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"

def validate_or_generate_nickname(nickname: Optional[str] = None, max_attempts: int = 10) -> str:
    """
    Validate provided nickname or generate a new valid one.
    Process:
    1. If nickname provided, validate format and uniqueness
    2. If invalid or not provided, generate new nickname
    3. Ensure generated nickname passes all checks
    """
    # If nickname provided and valid, return it
    if nickname and is_valid_nickname_format(nickname) and is_nickname_unique(nickname):
        return nickname
    
    # Generate new nicknames until we find a valid one
    for _ in range(max_attempts):
        new_nickname = generate_random_nickname()
        if is_valid_nickname_format(new_nickname) and is_nickname_unique(new_nickname):
            return new_nickname
    
    # Fallback if we can't generate a valid nickname after max attempts
    return f"user_{uuid.uuid4().hex[:8]}"