
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