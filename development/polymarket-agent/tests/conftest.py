import pytest

from agent.config import Settings
from agent.store.db import init_db, make_engine, make_session_factory


@pytest.fixture
def settings() -> Settings:
    return Settings(database_url="sqlite:///:memory:")


@pytest.fixture
def engine():
    eng = make_engine("sqlite:///:memory:")
    init_db(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return make_session_factory(engine)


@pytest.fixture
def session(session_factory):
    with session_factory() as sess:
        yield sess
