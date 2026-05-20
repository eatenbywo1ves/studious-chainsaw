from agent.config import Settings, get_settings


def test_settings_defaults():
    settings = Settings()

    assert settings.clob_base_url == "https://clob.polymarket.com"
    assert settings.gamma_base_url == "https://gamma-api.polymarket.com"
    assert settings.database_url.startswith("sqlite")
    assert settings.http_timeout_seconds == 30.0


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("PMA_DATABASE_URL", "postgresql://localhost/test")

    assert get_settings().database_url == "postgresql://localhost/test"
