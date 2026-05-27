from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from agent.store.schema import Base

_IN_MEMORY = {"sqlite:///:memory:", "sqlite://"}


def make_engine(database_url: str) -> Engine:
    """Create an Engine. In-memory SQLite uses StaticPool so every session
    in a test shares one database."""
    if database_url in _IN_MEMORY:
        return create_engine(
            "sqlite://",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url, future=True)


def init_db(engine: Engine) -> None:
    """Create all tables. Phase 0 uses create_all; Alembic migrations are
    introduced in a later phase when the schema first changes."""
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a sessionmaker bound to `engine`."""
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
