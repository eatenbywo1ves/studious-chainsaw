"""
Database Connection and Session Management
===========================================

Handles SQLAlchemy engine creation, session management, and database initialization.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from contextlib import contextmanager
from typing import Generator
import os

from .models import Base
from config import get_settings


# Global engine and session factory
_engine = None
_SessionLocal = None


def get_database_url() -> str:
    """
    Get database URL from settings.

    Returns:
        str: Database connection URL
    """
    settings = get_settings()
    return settings.database_url_computed


def create_database_engine():
    """
    Create SQLAlchemy engine based on configuration.

    Returns:
        Engine: SQLAlchemy engine instance
    """
    database_url = get_database_url()
    settings = get_settings()

    # SQLite-specific configuration
    if database_url.startswith("sqlite"):
        # Create data directory if it doesn't exist
        db_path = settings.SQLITE_DB_PATH
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=settings.DEBUG  # Log SQL queries in debug mode
        )
    else:
        # PostgreSQL or other databases
        engine = create_engine(
            database_url,
            pool_size=5,
            max_overflow=10,
            echo=settings.DEBUG
        )

    return engine


def init_db():
    """
    Initialize database by creating all tables.

    Should be called once at application startup.
    """
    global _engine, _SessionLocal

    _engine = create_database_engine()
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

    # Create all tables
    Base.metadata.create_all(bind=_engine)

    print(f"[Database] Initialized: {get_database_url()}")
    print(f"[Database] Tables created: {', '.join(Base.metadata.tables.keys())}")


def get_engine():
    """
    Get the global database engine.

    Returns:
        Engine: SQLAlchemy engine instance
    """
    global _engine
    if _engine is None:
        init_db()
    return _engine


def get_session() -> Session:
    """
    Get a new database session.

    Returns:
        Session: SQLAlchemy session instance

    Usage:
        session = get_session()
        try:
            # Use session
            pass
        finally:
            session.close()
    """
    global _SessionLocal
    if _SessionLocal is None:
        init_db()
    return _SessionLocal()


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager for database sessions.

    Automatically handles commit, rollback, and close.

    Usage:
        with get_db_session() as session:
            scan = session.query(Scan).first()
            # ... use session ...
    """
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency injection for FastAPI endpoints.

    Usage:
        @app.get("/endpoint")
        def endpoint(db: Session = Depends(get_db)):
            scans = db.query(Scan).all()
            return scans
    """
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def reset_database():
    """
    Drop all tables and recreate them.

    WARNING: This will delete all data!
    Only use for testing or development.
    """
    engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    print("[Database] Reset complete - all tables dropped and recreated")


def close_database():
    """
    Close database connections.

    Should be called on application shutdown.
    """
    global _engine
    if _engine is not None:
        _engine.dispose()
        print("[Database] Connections closed")
