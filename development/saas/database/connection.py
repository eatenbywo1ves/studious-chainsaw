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
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

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
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        echo=False,
    )
else:
    # PostgreSQL configuration for production
    # pool_size=20: Number of connections to keep open
    # max_overflow=40: Additional connections allowed under high load
    # pool_pre_ping=True: Verify connections are alive before using
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        echo=False,
    )

# Create session factory bound to the shared engine
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ============================================================================
# DEPENDENCY INJECTION FUNCTION
# ============================================================================

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
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
