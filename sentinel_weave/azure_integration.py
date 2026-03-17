"""
Azure Integration — SentinelWeave

Credential-first Azure wrappers with offline-safe fallbacks. All clients
attempt DefaultAzureCredential first, then fall back to explicit secrets
(connection strings / keys) when provided.

Supported services:
- Azure Blob Storage
- Azure Cosmos DB
- Azure Cognitive Services (Text Analytics)
- Azure Monitor / Application Insights
- Azure Key Vault (Secrets)
- Azure Service Bus (Queue)
- Azure Event Hubs (Producer)

Local fallback writes to ~/.sentinelweave/ when Azure is unavailable.
"""

from __future__ import annotations

import datetime
import json
import os
from pathlib import Path
from typing import Optional

from .azure_config import AzureConfig

# ---------------------------------------------------------------------------
# Local fallback root
# ---------------------------------------------------------------------------

_LOCAL_ROOT = Path.home() / ".sentinelweave"


def _ensure_local_root() -> None:
    _LOCAL_ROOT.mkdir(parents=True, exist_ok=True)


def _get_credential():
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore[import]
    except Exception:
        return None
    return DefaultAzureCredential()


# ---------------------------------------------------------------------------
# Azure Blob Storage wrapper
# ---------------------------------------------------------------------------

class BlobStorageClient:
    """
    Upload and download encrypted threat reports to/from Azure Blob Storage.

    Falls back to local files under ~/.sentinelweave/blobs/.
    """

    def __init__(
        self,
        container_name: str = "sentinelweave-reports",
        connection_string: Optional[str] = None,
        account_url: Optional[str] = None,
        config: Optional[AzureConfig] = None,
    ) -> None:
        cfg = config or AzureConfig.from_env()
        self.container_name = container_name or cfg.storage_container
        self._conn_str = connection_string or cfg.storage_connection_string
        self._account_url = account_url or cfg.storage_account_url
        self._azure_client = self._init_azure()

    def _init_azure(self):
        try:
            from azure.storage.blob import BlobServiceClient  # type: ignore[import]
        except Exception:
            return None

        if self._conn_str:
            try:
                svc = BlobServiceClient.from_connection_string(self._conn_str)
            except Exception:
                return None
        elif self._account_url:
            credential = _get_credential()
            if credential is None:
                return None
            try:
                svc = BlobServiceClient(account_url=self._account_url, credential=credential)
            except Exception:
                return None
        else:
            return None

        try:
            container = svc.get_container_client(self.container_name)
            try:
                container.create_container()
            except Exception:
                pass
            return container
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._azure_client is not None

    def upload(self, data: bytes, blob_name: str) -> str:
        if self._azure_client:
            self._azure_client.upload_blob(blob_name, data, overwrite=True)
            return f"azure://{self.container_name}/{blob_name}"

        _ensure_local_root()
        path = _LOCAL_ROOT / "blobs" / blob_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return f"local://{path}"

    def download(self, blob_name: str) -> bytes:
        if self._azure_client:
            stream = self._azure_client.download_blob(blob_name)
            return stream.readall()

        path = _LOCAL_ROOT / "blobs" / blob_name
        if not path.exists():
            raise FileNotFoundError(f"Blob not found: {blob_name}")
        return path.read_bytes()

    def list_blobs(self) -> list[str]:
        if self._azure_client:
            return [b.name for b in self._azure_client.list_blobs()]

        blob_dir = _LOCAL_ROOT / "blobs"
        if not blob_dir.exists():
            return []
        return [p.name for p in blob_dir.iterdir() if p.is_file()]


# ---------------------------------------------------------------------------
# Azure Cosmos DB wrapper
# ---------------------------------------------------------------------------

class CosmosDbClient:
    """
    Store and query threat data in Azure Cosmos DB with local fallback.

    Local fallback stores items in ~/.sentinelweave/cosmos/<db>/<container>.json
    """

    def __init__(
        self,
        database_name: str = "sentinelweave",
        container_name: str = "threat-reports",
        connection_string: Optional[str] = None,
        endpoint: Optional[str] = None,
        partition_key: str = "/id",
        config: Optional[AzureConfig] = None,
    ) -> None:
        cfg = config or AzureConfig.from_env()
        self.database_name = database_name or cfg.cosmos_database
        self.container_name = container_name or cfg.cosmos_container
        self.partition_key = partition_key or cfg.cosmos_partition_key
        self._conn_str = connection_string or cfg.cosmos_connection_string
        self._endpoint = endpoint or cfg.cosmos_endpoint
        self._container = self._init_azure()

    def _init_azure(self):
        try:
            from azure.cosmos import CosmosClient, PartitionKey  # type: ignore[import]
        except Exception:
            return None

        try:
            if self._conn_str:
                client = CosmosClient.from_connection_string(self._conn_str)
            elif self._endpoint:
                credential = _get_credential()
                if credential is None:
                    return None
                client = CosmosClient(self._endpoint, credential=credential)
            else:
                return None

            database = client.create_database_if_not_exists(id=self.database_name)
            container = database.create_container_if_not_exists(
                id=self.container_name,
                partition_key=PartitionKey(path=self.partition_key),
            )
            return container
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._container is not None

    def _resolve_partition_key(self, item_id: str, partition_key: Optional[str]) -> str:
        if partition_key is not None:
            return partition_key
        if self.partition_key == "/id":
            return item_id
        raise ValueError("partition_key is required when partition key is not '/id'")

    def _local_path(self) -> Path:
        _ensure_local_root()
        local_dir = _LOCAL_ROOT / "cosmos" / self.database_name
        local_dir.mkdir(parents=True, exist_ok=True)
        return local_dir / f"{self.container_name}.json"

    def _load_local_items(self) -> list[dict]:
        path = self._local_path()
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def _write_local_items(self, items: list[dict]) -> None:
        path = self._local_path()
        path.write_text(json.dumps(items, indent=2), encoding="utf-8")

    def upsert_item(self, item: dict) -> dict:
        if "id" not in item:
            raise ValueError("item must include an 'id' field")

        if self._container:
            return self._container.upsert_item(item)

        items = self._load_local_items()
        item_id = str(item.get("id"))
        for idx, existing in enumerate(items):
            if str(existing.get("id")) == item_id:
                items[idx] = item
                break
        else:
            items.append(item)
        self._write_local_items(items)
        return item

    def read_item(self, item_id: str, partition_key: Optional[str] = None) -> Optional[dict]:
        if self._container:
            pk = self._resolve_partition_key(item_id, partition_key)
            return self._container.read_item(item=item_id, partition_key=pk)

        items = self._load_local_items()
        for item in items:
            if str(item.get("id")) == str(item_id):
                return item
        return None

    def delete_item(self, item_id: str, partition_key: Optional[str] = None) -> bool:
        if self._container:
            pk = self._resolve_partition_key(item_id, partition_key)
            self._container.delete_item(item=item_id, partition_key=pk)
            return True

        items = self._load_local_items()
        remaining = [item for item in items if str(item.get("id")) != str(item_id)]
        if len(remaining) == len(items):
            return False
        self._write_local_items(remaining)
        return True

    def query_items(
        self,
        query: str,
        parameters: Optional[list[dict]] = None,
        enable_cross_partition_query: bool = True,
    ) -> list[dict]:
        if self._container:
            return list(
                self._container.query_items(
                    query=query,
                    parameters=parameters,
                    enable_cross_partition_query=enable_cross_partition_query,
                )
            )
        return self._load_local_items()

    def list_items(self) -> list[dict]:
        if self._container:
            return self.query_items("SELECT * FROM c")
        return self._load_local_items()


# ---------------------------------------------------------------------------
# Azure Cognitive Services — Text Analytics wrapper
# ---------------------------------------------------------------------------

class TextAnalyticsClient:
    """
    Analyse free-text security messages using Azure Cognitive Services
    Text Analytics, with local fallback when not configured.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        config: Optional[AzureConfig] = None,
    ) -> None:
        cfg = config or AzureConfig.from_env()
        self._endpoint = endpoint or cfg.text_analytics_endpoint
        self._api_key = api_key or cfg.text_analytics_key
        self._azure_client = self._init_azure()

    def _init_azure(self):
        if not self._endpoint:
            return None
        try:
            from azure.ai.textanalytics import TextAnalyticsClient as AzTAC  # type: ignore[import]
            from azure.core.credentials import AzureKeyCredential  # type: ignore[import]
        except Exception:
            return None

        try:
            if self._api_key:
                return AzTAC(self._endpoint, AzureKeyCredential(self._api_key))
            credential = _get_credential()
            if credential is None:
                return None
            return AzTAC(self._endpoint, credential)
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._azure_client is not None

    def analyze(self, text: str) -> dict:
        if self._azure_client:
            return self._analyze_azure(text)
        return self._analyze_local(text)

    def _analyze_azure(self, text: str) -> dict:
        if self._azure_client is None:
            return self._analyze_local(text)
        try:
            client = self._azure_client
            docs = [text]
            sentiment_result = client.analyze_sentiment(docs)[0]
            kp_result = client.extract_key_phrases(docs)[0]
            ner_result = client.recognize_entities(docs)[0]
            pii_result = client.recognize_pii_entities(docs)[0]

            return {
                "sentiment": sentiment_result.sentiment,
                "key_phrases": list(kp_result.key_phrases),
                "entities": [{"text": e.text, "category": e.category} for e in ner_result.entities],
                "pii_redacted": pii_result.redacted_text,
                "source": "azure",
            }
        except Exception as exc:
            result = self._analyze_local(text)
            result["azure_error"] = str(exc)
            return result

    _NEGATIVE_WORDS = {
        "failed", "error", "denied", "refused", "attack", "malicious",
        "suspicious", "blocked", "unauthorized", "breach", "critical",
        "exploit", "vulnerability", "compromise", "infected", "malware",
    }
    _POSITIVE_WORDS = {
        "success", "allowed", "granted", "connected", "authenticated",
        "resolved", "completed", "healthy", "normal",
    }

    def _analyze_local(self, text: str) -> dict:
        import re

        words = set(re.findall(r"\b\w+\b", text.lower()))

        neg = words & self._NEGATIVE_WORDS
        pos = words & self._POSITIVE_WORDS
        if len(neg) > len(pos):
            sentiment = "negative"
        elif len(pos) > len(neg):
            sentiment = "positive"
        else:
            sentiment = "neutral"

        key_phrases = list({
            w for w in text.split()
            if len(w) > 4 and (w[0].isupper() or w.lower() in self._NEGATIVE_WORDS | self._POSITIVE_WORDS)
        })[:10]

        ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        entities = [{"text": ip, "category": "IPAddress"} for ip in ip_re.findall(text)]

        pii_redacted = ip_re.sub("[REDACTED]", text)

        return {
            "sentiment": sentiment,
            "key_phrases": key_phrases,
            "entities": entities,
            "pii_redacted": pii_redacted,
            "source": "local",
        }


# ---------------------------------------------------------------------------
# Azure Monitor / Application Insights telemetry
# ---------------------------------------------------------------------------

class SecurityTelemetry:
    """
    Emit structured security events to Azure Monitor / Application Insights
    or to a local JSON log file when the SDK is not configured.
    """

    def __init__(self, connection_string: Optional[str] = None, config: Optional[AzureConfig] = None) -> None:
        cfg = config or AzureConfig.from_env()
        self._conn_str = connection_string or cfg.appinsights_connection_string
        self._azure_client = self._init_azure()
        self._local_log = _LOCAL_ROOT / "telemetry.jsonl"

    def _init_azure(self):
        if not self._conn_str:
            return None
        try:
            from azure.monitor.opentelemetry import configure_azure_monitor  # type: ignore[import]
            configure_azure_monitor(connection_string=self._conn_str)
            import logging
            return logging.getLogger("sentinelweave")
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._azure_client is not None

    def track_threat(
        self,
        threat_level: str,
        source_ip: Optional[str] = None,
        signatures: Optional[list[str]] = None,
        anomaly_score: float = 0.0,
        extra: Optional[dict] = None,
    ) -> None:
        payload = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type": "ThreatDetected",
            "threat_level": threat_level,
            "source_ip": source_ip,
            "signatures": signatures or [],
            "anomaly_score": anomaly_score,
            **(extra or {}),
        }

        if self._azure_client:
            try:
                self._azure_client.warning(json.dumps(payload))
                return
            except Exception:
                pass

        _ensure_local_root()
        with self._local_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")

    def get_local_events(self) -> list[dict]:
        if not self._local_log.exists():
            return []
        events = []
        with self._local_log.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return events


# ---------------------------------------------------------------------------
# Azure Key Vault (Secrets) wrapper
# ---------------------------------------------------------------------------

class KeyVaultSecretsClient:
    """Simple Key Vault secrets client with local fallback."""

    def __init__(self, vault_url: Optional[str] = None, config: Optional[AzureConfig] = None) -> None:
        cfg = config or AzureConfig.from_env()
        self._vault_url = vault_url or cfg.key_vault_url
        self._client = self._init_azure()
        self._local_path = _LOCAL_ROOT / "keyvault.json"

    def _init_azure(self):
        if not self._vault_url:
            return None
        credential = _get_credential()
        if credential is None:
            return None
        try:
            from azure.keyvault.secrets import SecretClient  # type: ignore[import]
            return SecretClient(vault_url=self._vault_url, credential=credential)
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._client is not None

    def set_secret(self, name: str, value: str) -> None:
        if self._client:
            self._client.set_secret(name, value)
            return
        _ensure_local_root()
        data = self._load_local()
        data[name] = value
        self._save_local(data)

    def get_secret(self, name: str) -> Optional[str]:
        if self._client:
            return self._client.get_secret(name).value
        data = self._load_local()
        return data.get(name)

    def _load_local(self) -> dict:
        if not self._local_path.exists():
            return {}
        try:
            return json.loads(self._local_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save_local(self, data: dict) -> None:
        self._local_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Azure Service Bus (Queue) wrapper
# ---------------------------------------------------------------------------

class ServiceBusQueueClient:
    """Send messages to an Azure Service Bus queue with local fallback."""

    def __init__(
        self,
        queue_name: str = "sentinelweave-events",
        connection_string: Optional[str] = None,
        namespace: Optional[str] = None,
        config: Optional[AzureConfig] = None,
    ) -> None:
        cfg = config or AzureConfig.from_env()
        self.queue_name = queue_name or cfg.service_bus_queue
        self._conn_str = connection_string or cfg.service_bus_connection_string
        self._namespace = namespace or cfg.service_bus_namespace
        self._client = self._init_azure()
        self._local_path = _LOCAL_ROOT / "servicebus" / f"{self.queue_name}.jsonl"

    def _init_azure(self):
        try:
            from azure.servicebus import ServiceBusClient  # type: ignore[import]
        except Exception:
            return None

        try:
            if self._conn_str:
                return ServiceBusClient.from_connection_string(self._conn_str)
            if self._namespace:
                credential = _get_credential()
                if credential is None:
                    return None
                return ServiceBusClient(self._namespace, credential)
            return None
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._client is not None

    def send(self, message: str) -> None:
        if self._client:
            from azure.servicebus import ServiceBusMessage  # type: ignore[import]
            with self._client:
                sender = self._client.get_queue_sender(queue_name=self.queue_name)
                with sender:
                    sender.send_messages(ServiceBusMessage(message))
            return

        _ensure_local_root()
        self._local_path.parent.mkdir(parents=True, exist_ok=True)
        with self._local_path.open("a", encoding="utf-8") as fh:
            fh.write(message + "\n")


# ---------------------------------------------------------------------------
# Azure Event Hubs (Producer) wrapper
# ---------------------------------------------------------------------------

class EventHubPublisher:
    """Publish events to Azure Event Hubs with local fallback."""

    def __init__(
        self,
        hub_name: str = "sentinelweave-events",
        connection_string: Optional[str] = None,
        namespace: Optional[str] = None,
        config: Optional[AzureConfig] = None,
    ) -> None:
        cfg = config or AzureConfig.from_env()
        self.hub_name = hub_name or cfg.event_hub_name
        self._conn_str = connection_string or cfg.event_hubs_connection_string
        self._namespace = namespace or cfg.event_hubs_namespace
        self._client = self._init_azure()
        self._local_path = _LOCAL_ROOT / "eventhubs" / f"{self.hub_name}.jsonl"

    def _init_azure(self):
        try:
            from azure.eventhub import EventHubProducerClient  # type: ignore[import]
        except Exception:
            return None

        try:
            if self._conn_str:
                return EventHubProducerClient.from_connection_string(
                    conn_str=self._conn_str, eventhub_name=self.hub_name
                )
            if self._namespace:
                credential = _get_credential()
                if credential is None:
                    return None
                return EventHubProducerClient(
                    fully_qualified_namespace=self._namespace,
                    eventhub_name=self.hub_name,
                    credential=credential,
                )
            return None
        except Exception:
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._client is not None

    def publish(self, event: dict) -> None:
        payload = json.dumps(event)
        if self._client:
            from azure.eventhub import EventData  # type: ignore[import]
            with self._client:
                batch = self._client.create_batch()
                batch.add(EventData(payload))
                self._client.send_batch(batch)
            return

        _ensure_local_root()
        self._local_path.parent.mkdir(parents=True, exist_ok=True)
        with self._local_path.open("a", encoding="utf-8") as fh:
            fh.write(payload + "\n")
