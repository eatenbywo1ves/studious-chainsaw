"""
Centralized Database Connection Management

This module provides a single, shared database engine and session factory
to prevent the critical per-request engine creation bug.

IMPORTANT: The engine is created ONCE at module import time, not per-request.
This prevents connection pool exhaustion under concurrent load.

Usage:
    from database.connection import get_db

    @router.get("/endpoint")
    async def endpoint(db: Session = Depends(get_db)):
        # Use db session here
        pass
"""

import os
import logging
from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import Pool
from dotenv import load_dotenv

# Setup logging
logger = logging.getLogger(__name__)

# ============================================================================
# ENVIRONMENT CONFIGURATION - Load once at module level
# ============================================================================

env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
load_dotenv(env_path)

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Default to SQLite for development
    sqlite_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "catalytic.db"
    )
    DATABASE_URL = f"sqlite:///{sqlite_path}"

# ============================================================================
# DATABASE ENGINE - Created ONCE at module level (NOT per-request)
# ============================================================================

if DATABASE_URL.startswith("sqlite"):
    # SQLite configuration for development
    logger.info("Initializing SQLite database engine", extra={"database": "SQLite"})
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False,
    )
    logger.info("SQLite engine created successfully")
else:
    # PostgreSQL configuration for production
    # pool_size=20: Number of connections to keep open
    # max_overflow=40: Additional connections allowed under high load
    # pool_pre_ping=True: Verify connections are alive before using
    logger.info(
        "Initializing PostgreSQL database engine",
        extra={"database": "PostgreSQL", "pool_size": 20, "max_overflow": 40}
    )
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        echo=False,
    )
    logger.info("PostgreSQL engine created successfully with connection pooling")

# Create session factory bound to the shared engine
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ============================================================================
# CONNECTION POOL MONITORING
# ============================================================================

# Add pool event listeners for monitoring
@event.listens_for(Pool, "connect")
def receive_connect(dbapi_conn, connection_record):
    """Log when new database connection is created"""
    logger.debug("New database connection created", extra={"connection_id": id(dbapi_conn)})

@event.listens_for(Pool, "checkout")
def receive_checkout(dbapi_conn, connection_record, connection_proxy):
    """Log when connection is checked out from pool"""
    logger.debug("Connection checked out from pool", extra={"connection_id": id(dbapi_conn)})

@event.listens_for(Pool, "checkin")
def receive_checkin(dbapi_conn, connection_record):
    """Log when connection is returned to pool"""
    logger.debug("Connection returned to pool", extra={"connection_id": id(dbapi_conn)})

def get_pool_status() -> dict:
    """
    Get current connection pool status for monitoring.

    Returns:
        dict: Pool statistics including size, connections in use, overflow
    """
    pool = engine.pool
    status = {
        "size": pool.size(),
        "checked_in": pool.checkedin(),
        "checked_out": pool.checkedout(),
        "overflow": pool.overflow(),
        "total_connections": pool.size() + pool.overflow(),
    }
    logger.debug("Pool status retrieved", extra=status)
    return status

# ============================================================================
# DEPENDENCY INJECTION FUNCTION
# ============================================================================

_session_counter = 0

def get_db() -> Generator[Session, None, None]:
    """
    Get database session - use as FastAPI dependency.

    This function yields a database session from the shared connection pool
    and ensures it's properly closed after use.

    Example:
        @router.get("/users")
        async def get_users(db: Session = Depends(get_db)):
            return db.query(User).all()

    Yields:
        Session: SQLAlchemy database session
    """
    global _session_counter
    _session_counter += 1
    session_id = _session_counter

    logger.debug(f"Creating database session", extra={"session_id": session_id})
    db = SessionLocal()
    try:
        yield db
        logger.debug(f"Database session completed successfully", extra={"session_id": session_id})
    except Exception as e:
        logger.error(
            f"Database session error",
            extra={"session_id": session_id, "error": str(e)}
        )
        db.rollback()
        raise
    finally:
        db.close()
        logger.debug(f"Database session closed", extra={"session_id": session_id})
