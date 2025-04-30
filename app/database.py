from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool  # Important for async

Base = declarative_base()

class Database:
    """Async database connection handler with connection resilience"""
    _engine = None
    _session_factory = None

    @classmethod
    def initialize(cls, database_url: str, echo: bool = False):
        """Initialize with connection pool settings and pre-ping"""
        if cls._engine is None:
            cls._engine = create_async_engine(
                database_url,
                echo=echo,
                future=True,
                pool_size=20,
                max_overflow=10,
                pool_timeout=30.0,  # seconds
                pool_pre_ping=True,  # Critical for reconnects
                pool_recycle=3600,   # Recycle connections hourly
                poolclass=NullPool if "sqlite" in database_url else None
            )
            cls._session_factory = async_sessionmaker(
                bind=cls._engine,
                class_=AsyncSession,
                expire_on_commit=False,
                autoflush=False
            )

    @classmethod
    async def health_check(cls):
        """Validate database connectivity"""
        async with cls._engine.connect() as conn:
            await conn.execute("SELECT 1")

    @classmethod
    def get_session_factory(cls):
        if cls._session_factory is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        return cls._session_factory