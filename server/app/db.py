from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy.pool import StaticPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from .config import settings


def _make_engine():
    url = settings.database_url
    if url.startswith("sqlite"):
        # For sqlite tests/dev: avoid QueuePool args and allow multi-thread access.
        connect_args = {"check_same_thread": False}
        if ":memory:" in url:
            return create_engine(
                url,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        return create_engine(url, connect_args=connect_args)

    # Default postgres-style engine
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        pool_timeout=30,
    )


# The UI makes frequent concurrent API calls and some endpoints poll using short-lived sessions.
engine = _make_engine()

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Async support for background tasks (e.g. CVE sync)
def _make_async_engine():
    url = settings.database_url
    # Replace sync driver with async driver for SQLAlchemy 2.0
    if "postgresql+psycopg://" in url:
        url = url.replace("postgresql+psycopg://", "postgresql+psycopg_async://")
    elif url.startswith("sqlite"):
        # Handle both sqlite:// and sqlite+pysqlite:// URLs.
        if "://" in url:
            _, rest = url.split("://", 1)
            url = f"sqlite+aiosqlite://{rest}"
        else:
            url = "sqlite+aiosqlite:///:memory:"
        return create_async_engine(
            url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )

    return create_async_engine(
        url,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        pool_timeout=30,
    )

async_engine = _make_async_engine()
AsyncSessionLocal = async_sessionmaker(bind=async_engine, expire_on_commit=False)
