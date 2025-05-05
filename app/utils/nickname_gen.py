# # from builtins import str
# # import random


# # def generate_nickname() -> str:
# #     """Generate a URL-safe nickname using adjectives and animal names."""
# #     adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
# #     animals = ["panda", "fox", "raccoon", "koala", "lion"]
# #     number = random.randint(0, 999)
# #     return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"


# # Updated nickname_gen.py
# import random
# import uuid
# import re
# from typing import Optional
# from sqlalchemy.ext.asyncio import AsyncSession  
# from app.models.user_model import User  
# # from app.db.session import SessionLocal
# # from app.repositories.user_repository import UserRepository

# def is_valid_nickname_format(nickname: str) -> bool:
#     """Check if nickname meets basic format requirements"""
#     return (len(nickname) >= 3 and 
#             len(nickname) <= 32 and 
#             bool(re.match(r'^[\w-]+$', nickname)))

# async def is_nickname_unique(session: AsyncSession, nickname: str) -> bool:
#     """
#     Check if nickname exists in database using async SQLAlchemy
#     """
#     from sqlalchemy.future import select
#     result = await session.execute(
#         select(User).where(User.nickname == nickname)
#     )
#     return result.scalar_one_or_none() is None

# def generate_random_nickname() -> str:
#     """Generate a random nickname that meets format requirements"""
#     adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
#     animals = ["panda", "fox", "raccoon", "koala", "lion"]
#     number = random.randint(0, 999)
#     return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"

# def validate_or_generate_nickname(nickname: Optional[str] = None, max_attempts: int = 10) -> str:
#     """
#     Validate provided nickname or generate a new valid one.
#     Process:
#     1. If nickname provided, validate format and uniqueness
#     2. If invalid or not provided, generate new nickname
#     3. Ensure generated nickname passes all checks
#     """
#     # If nickname provided and valid, return it
#     if nickname and is_valid_nickname_format(nickname) and is_nickname_unique(nickname):
#         return nickname
    
#     # Generate new nicknames until we find a valid one
#     for _ in range(max_attempts):
#         new_nickname = generate_random_nickname()
#         if is_valid_nickname_format(new_nickname) and is_nickname_unique(new_nickname):
#             return new_nickname
    
#     # Fallback if we can't generate a valid nickname after max attempts
#     return f"user_{uuid.uuid4().hex[:8]}"


# import random
# import uuid
# import re
# from typing import Optional
# from sqlalchemy.ext.asyncio import AsyncSession
# from app.models.user_model import User
# from sqlalchemy.future import select

# def is_valid_nickname_format(nickname: str) -> bool:
#     """Check if nickname meets format requirements (3-32 chars, alphanumeric)"""
#     return (3 <= len(nickname) <= 32 and bool(re.match(r'^[\w-]+$', nickname)))

# async def is_nickname_unique(session: AsyncSession, nickname: str) -> bool:
#     """SQLAlchemy async check for nickname uniqueness"""
#     result = await session.execute(
#         select(User).where(User.nickname == nickname)
#     )
#     return result.scalar_one_or_none() is None

# def generate_random_nickname() -> str:
#     """Generate adjective_animal_number format nickname"""
#     adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
#     animals = ["panda", "fox", "raccoon", "koala", "lion"]
#     number = random.randint(0, 999)
#     return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"

# async def validate_or_generate_nickname(
#     session: AsyncSession,
#     nickname: Optional[str] = None,
#     max_attempts: int = 10
# ) -> str:
#     """
#     Main function to validate or generate nicknames.
#     Usage example:
#     async with AsyncSession() as session:
#         nickname = await validate_or_generate_nickname(session, "my_nick")
#     """
#     # Validate provided nickname
#     if nickname and is_valid_nickname_format(nickname):
#         if await is_nickname_unique(session, nickname):
#             return nickname
    
#     # Generate new unique nickname
#     for _ in range(max_attempts):
#         new_nickname = generate_random_nickname()
#         if (is_valid_nickname_format(new_nickname) and 
#             await is_nickname_unique(session, new_nickname)):
#             return new_nickname
    
#     # Fallback UUID-based nickname
#     return f"user_{uuid.uuid4().hex[:8]}"


import random
import uuid
import re
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from app.models.user_model import User

def is_valid_nickname_format(nickname: str) -> bool:
    return (3 <= len(nickname) <= 32 and bool(re.match(r'^[\w-]+$', nickname)))

async def is_nickname_unique(session: AsyncSession, nickname: str) -> bool:
    result = await session.execute(
        select(User).where(User.nickname == nickname)
    )
    return result.scalar_one_or_none() is None

def generate_random_nickname() -> str:
    adjectives = ["clever", "jolly", "brave", "sly", "gentle"]
    animals = ["panda", "fox", "raccoon", "koala", "lion"]
    number = random.randint(0, 999)
    return f"{random.choice(adjectives)}_{random.choice(animals)}_{number}"

async def validate_or_generate_nickname(
    session: AsyncSession,
    nickname: Optional[str] = None,
    max_attempts: int = 10
) -> str:
    if nickname and is_valid_nickname_format(nickname):
        if await is_nickname_unique(session, nickname):
            return nickname
    
    for _ in range(max_attempts):
        new_nickname = generate_random_nickname()
        if (is_valid_nickname_format(new_nickname) and 
            await is_nickname_unique(session, new_nickname)):
            return new_nickname
    
    return f"user_{uuid.uuid4().hex[:8]}"