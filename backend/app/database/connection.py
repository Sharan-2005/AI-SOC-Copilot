import time
import logging
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.config import settings

logger = logging.getLogger("soc_copilot.database")

# Initialize PostgreSQL engine
engine = create_engine(
    settings.sqlalchemy_database_url,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    connect_args={"connect_timeout": 5}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def check_database_connection() -> Dict[str, Any]:
    """
    Performs a live connectivity test against PostgreSQL.
    Returns status, latency in milliseconds, and any error message.
    """
    start_time = time.perf_counter()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "connected": True,
            "dialect": "postgresql",
            "latency_ms": latency_ms,
            "error": None
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning(f"Database connection check failed: {exc}")
        return {
            "connected": False,
            "dialect": "postgresql",
            "latency_ms": latency_ms,
            "error": str(exc)
        }
