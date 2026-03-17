import os

from sentinel_weave.azure_config import AzureConfig


def test_azure_config_from_env_defaults(monkeypatch):
    monkeypatch.delenv("AZURE_STORAGE_CONNECTION_STRING", raising=False)
    monkeypatch.delenv("AZURE_COSMOS_CONNECTION_STRING", raising=False)
    cfg = AzureConfig.from_env()
    assert cfg.storage_container == "sentinelweave-reports"
    assert cfg.cosmos_container == "threat-reports"


def test_azure_config_validate_reports_missing(monkeypatch):
    monkeypatch.delenv("AZURE_STORAGE_CONNECTION_STRING", raising=False)
    monkeypatch.delenv("AZURE_STORAGE_ACCOUNT_URL", raising=False)
    monkeypatch.delenv("AZURE_COSMOS_CONNECTION_STRING", raising=False)
    monkeypatch.delenv("AZURE_COSMOS_ENDPOINT", raising=False)
    cfg = AzureConfig.from_env()
    warnings = cfg.validate()
    assert "Blob Storage is not configured." in warnings
    assert "Cosmos DB is not configured." in warnings
