from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from .config import settings
from .models import Base
import os

import socket
from urllib.parse import urlparse

# Connect database engine
# Support sqlite fallback out-of-the-box for ease of setup
db_url = settings.DATABASE_URL

# Robust automatic fallback to local SQLite if PostgreSQL is unreachable
if "postgresql" in db_url:
    try:
        # Extract hostname and port
        parsed = urlparse(db_url.replace("+asyncpg", ""))
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        
        # Test connection with a small timeout
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError):
        # Fallback to local SQLite using aiosqlite driver
        db_url = "sqlite+aiosqlite:///./asip.db"

engine = create_async_engine(
    db_url,
    echo=False,
    future=True,
    # SQLite doesn't support pool_size or max_overflow
    **( {} if db_url.startswith("sqlite") else {"pool_size": 20, "max_overflow": 10} )
)

# Async session factory
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def init_db():
    """Create all tables in the database."""
    async with engine.begin() as conn:
        # If using SQLite, we can set PRAGMA foreign_keys = ON
        if db_url.startswith("sqlite"):
            await conn.exec_driver_sql("PRAGMA foreign_keys = ON")
        await conn.run_sync(Base.metadata.create_all)

async def get_db():
    """FastAPI DB dependency yielding an async session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
