"""Test skeletons for agent/store/db.py (currently NO test coverage at all).

Public API under test (agent/store/db.py):
    make_engine(database_url: str) -> Engine        (lines 10-20)
    init_db(engine: Engine) -> None                  (lines 23-26)
    make_session_factory(engine: Engine) -> sessionmaker[Session]  (lines 29-31)

Key behavior to pin down:
  - `_IN_MEMORY = {"sqlite:///:memory:", "sqlite://"}` (line 7) is special-cased
    to use StaticPool + check_same_thread=False, so a single in-memory
    "database" is shared across every session created from that ONE engine.
  - Any other URL (file-based sqlite, postgres, ...) goes through a plain
    `create_engine(database_url, future=True)` with NO special connect_args
    and NO StaticPool -- default SQLAlchemy pooling applies.
  - init_db is currently just `Base.metadata.create_all(engine)` -- there is
    no Alembic migration path yet (per the docstring, that lands "in a later
    phase when the schema first changes"), so "migration re-run" here really
    means "create_all called twice is a no-op", not a real migration replay.

Reuses the shared fixtures from tests/conftest.py (`settings`, `engine`,
`session_factory`, `session`) where they fit; several tests below build their
own engine directly via make_engine(...) because they need a *file-based* URL
or a second independent engine, which the shared fixtures don't provide.
"""

import os
import stat
import threading

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ArgumentError, DatabaseError, OperationalError

from agent.store.db import init_db, make_engine, make_session_factory
from agent.store.schema import Market


# ---------------------------------------------------------------------------
# Normal cases
# ---------------------------------------------------------------------------


def test_make_engine_in_memory_variants_both_use_static_pool():
    """Both strings in _IN_MEMORY ("sqlite:///:memory:" and "sqlite://")
    should produce a usable engine backed by StaticPool (i.e. writes made
    through one session are visible from a second session on the SAME
    engine, which would NOT be true without StaticPool for ':memory:')."""
    for url in ("sqlite:///:memory:", "sqlite://"):
        engine = make_engine(url)
        init_db(engine)
        factory = make_session_factory(engine)
        with factory() as s1:
            s1.add(Market(id="m1", question="Q"))
            s1.commit()
        with factory() as s2:
            assert s2.get(Market, "m1") is not None


def test_make_engine_two_in_memory_engines_are_independent():
    """Two separate calls to make_engine("sqlite:///:memory:") must NOT share
    data -- each gets its own StaticPool/connection, i.e. its own private
    in-memory database. This is the semantic the `engine` fixture in
    conftest.py relies on for test isolation."""
    engine_a = make_engine("sqlite:///:memory:")
    init_db(engine_a)
    engine_b = make_engine("sqlite:///:memory:")
    init_db(engine_b)
    with make_session_factory(engine_a)() as s:
        s.add(Market(id="m1", question="Q"))
        s.commit()
    with make_session_factory(engine_b)() as s:
        assert s.get(Market, "m1") is None


def test_make_engine_file_based_sqlite_creates_file(tmp_path):
    """A file-based sqlite URL should create the .db file on disk once a
    connection is actually used (init_db issues CREATE TABLE)."""
    db_path = tmp_path / "test.db"
    engine = make_engine(f"sqlite:///{db_path}")
    init_db(engine)
    assert db_path.exists()


def test_init_db_creates_all_mapped_tables(engine):
    """After init_db, every table declared on Base.metadata (markets,
    price_snapshots, crypto_bars, mode_performance, trade_records,
    mode_floor_state) exists and is queryable."""
    with engine.connect() as conn:
        names = {
            row[0]
            for row in conn.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
        }
    for expected in (
        "markets",
        "price_snapshots",
        "crypto_bars",
        "mode_performance",
        "trade_records",
        "mode_floor_state",
    ):
        assert expected in names


def test_make_session_factory_returns_working_sessionmaker(session_factory):
    """make_session_factory(engine) returns a callable sessionmaker whose
    sessions are usable for add/commit/query, with expire_on_commit=False
    (attributes remain readable post-commit without a refresh query)."""
    with session_factory() as session:
        m = Market(id="m1", question="Q")
        session.add(m)
        session.commit()
        assert m.question == "Q"  # not expired, no refresh needed


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_make_engine_missing_parent_directory_defers_error_to_connect(tmp_path):
    """make_engine() itself never touches the filesystem (SQLAlchemy Engine
    construction is lazy) -- the error only surfaces once a connection is
    actually opened against a nonexistent parent directory."""
    bad_path = tmp_path / "does_not_exist" / "sub" / "test.db"
    engine = make_engine(f"sqlite:///{bad_path}")
    with pytest.raises(OperationalError):
        init_db(engine)  # CREATE TABLE forces a real connection/open


def test_init_db_is_idempotent_on_rerun(engine):
    """Calling init_db twice on the same engine (simulating a 'migration
    re-run' in the current create_all-only world) must not raise and must
    not drop/lose existing data."""
    init_db(engine)  # already done by the `engine` fixture; call again
    factory = make_session_factory(engine)
    with factory() as s:
        s.add(Market(id="m1", question="Q"))
        s.commit()
    init_db(engine)  # second create_all -- should be a silent no-op
    with factory() as s:
        assert s.get(Market, "m1") is not None


def test_concurrent_sessions_from_same_file_engine_see_committed_writes(tmp_path):
    """Two sessions opened from the SAME file-based engine (simulating
    concurrent access, e.g. from separate threads) must each see the other's
    committed writes -- exercises default (non-StaticPool) pooling behavior
    that in-memory URLs deliberately bypass."""
    engine = make_engine(f"sqlite:///{tmp_path / 'concurrent.db'}")
    init_db(engine)
    factory = make_session_factory(engine)
    results = {}

    def writer():
        with factory() as s:
            s.add(Market(id="from-thread", question="Q"))
            s.commit()

    t = threading.Thread(target=writer)
    t.start()
    t.join()
    with factory() as s:
        results["seen"] = s.get(Market, "from-thread") is not None
    assert results["seen"] is True


def test_make_engine_unknown_scheme_still_delegates_to_create_engine(monkeypatch):
    """A non-sqlite URL (e.g. postgresql://...) is NOT in _IN_MEMORY, so
    make_engine must fall through to plain create_engine(url, future=True)
    without StaticPool/connect_args.  We monkeypatch create_engine itself
    rather than actually connecting, since no Postgres driver is installed
    in this environment."""
    import agent.store.db as db_module

    captured = {}

    def fake_create_engine(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return "sentinel-engine"

    monkeypatch.setattr(db_module, "create_engine", fake_create_engine)

    result = make_engine("postgresql://user:pass@localhost/dbname")

    assert result == "sentinel-engine"
    assert captured["url"] == "postgresql://user:pass@localhost/dbname"
    assert captured["kwargs"] == {"future": True}


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_corrupted_db_file_raises_on_query(tmp_path):
    """Pointing make_engine at a file that exists but is NOT a valid SQLite
    file must raise (sqlite3 "file is not a database") once a real query is
    attempted -- init_db's CREATE TABLE is enough to trigger it."""
    bad_file = tmp_path / "corrupt.db"
    bad_file.write_bytes(b"this is not a sqlite database")
    engine = make_engine(f"sqlite:///{bad_file}")
    with pytest.raises(DatabaseError):
        init_db(engine)


@pytest.mark.skipif(
    os.name == "nt",
    reason="chmod-based read-only simulation is unreliable on Windows; "
    "revisit with a Windows-specific ACL/read-only-attribute approach "
    "(e.g. os.chmod + win32 file attributes) before un-skipping.",
)
def test_readonly_db_file_raises_on_write(tmp_path):
    """A DB file with no write permission must raise on any write attempt
    (sqlite3 "attempt to write a readonly database"), not silently no-op."""
    db_path = tmp_path / "readonly.db"
    engine = make_engine(f"sqlite:///{db_path}")
    init_db(engine)  # create schema while writable
    os.chmod(db_path, stat.S_IREAD)
    try:
        factory = make_session_factory(engine)
        with pytest.raises(OperationalError):
            with factory() as s:
                s.add(Market(id="m1", question="Q"))
                s.commit()
    finally:
        os.chmod(db_path, stat.S_IWRITE | stat.S_IREAD)  # allow tmp_path cleanup


def test_make_engine_empty_url_raises():
    """An empty-string database_url is neither in _IN_MEMORY nor a valid
    SQLAlchemy URL -- make_engine (or the eventual connect) should surface a
    clear error rather than silently defaulting to something unexpected."""
    with pytest.raises(ArgumentError):
        make_engine("")
