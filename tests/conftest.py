import pytest


@pytest.fixture(autouse=True)
def no_paid_api_calls(monkeypatch):
    """Tests never inherit the operator's real provider credential."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
