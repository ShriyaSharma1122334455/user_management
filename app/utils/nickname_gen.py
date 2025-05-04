# app/utils/nickname_gen.py
from builtins import str
import random
import re
from typing import Optional

def validate_nickname(nickname: str) -> bool:
    """
    Validate that a nickname meets requirements.
    
    Requirements:
    - 3 to 20 characters long
    - Only contains letters, numbers, underscores, and hyphens
    - Not empty or None
    
    Args:
        nickname (str): Nickname to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not nickname:
        return False
    if not 3 <= len(nickname) <= 20:
        return False
    if not re.match(r'^[a-zA-Z0-9_-]+$', nickname):
        return False
    return True

def generate_nickname() -> str:
    """
    Generate a random URL-safe nickname.
    Format: adjective_animal_number
    """
    adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
    animals = ["panda", "fox", "raccoon", "koala", "lion"]
    number = random.randint(0, 999)
    return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"

def get_valid_nickname(nickname: Optional[str] = None) -> str:
    """
    Return the provided nickname if valid, otherwise generate a new one.
    
    Args:
        nickname (str, optional): Nickname to validate
        
    Returns:
        str: Valid nickname (either provided or generated)
    """
    if nickname and validate_nickname(nickname):
        return nickname
    return generate_nickname()