"""
Azure Integration — SentinelWeave

Provides thin, offline-safe wrappers around the Azure services that are most
relevant to a cybersecurity / AI-automation project:

* **Azure Blob Storage** — store encrypted threat reports durably in the cloud.
* **Azure Cognitive Services – Text Analytics** — classify and extract
  entities from free-text security descriptions.
* **Azure Monitor / Application Insights** — emit structured security telemetry.

All wrappers degrade gracefully when credentials are absent or the SDK is not
installed: they operate in a *local fallback mode* so the rest of the pipeline
never breaks in development / CI environments.

Environment variables
---------------------
``AZURE_STORAGE_CONNECTION_STRING``
    Full connection string for the target Azure Storage account.
``AZURE_TEXT_ANALYTICS_ENDPOINT``
    Endpoint URL for a Text Analytics resource
    (e.g. ``https://<name>.cognitiveservices.azure.com/``).
``AZURE_TEXT_ANALYTICS_KEY``
    API key for the Text Analytics resource.
``AZURE_APPINSIGHTS_CONNECTION_STRING``
    Connection string for an Application Insights resource.
``AZURE_COSMOS_CONNECTION_STRING``
    Connection string for a Cosmos DB account.

When these variables are unset the wrappers write to / read from local files
under ``~/.sentinelweave/`` instead.
"""

from __future__ import annotations

import json
import os
import hashlib
import datetime
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Local fallback root
# ---------------------------------------------------------------------------

_LOCAL_ROOT = Path.home() / ".sentinelweave"


def _ensure_local_root() -> None:
    _LOCAL_ROOT.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Azure Blob Storage wrapper
# ---------------------------------------------------------------------------

class BlobStorageClient:
    """
    Upload and download encrypted threat reports to/from Azure Blob Storage.

    When ``AZURE_STORAGE_CONNECTION_STRING`` is not set the client stores
    blobs as files in ``~/.sentinelweave/blobs/``.

    Parameters
    ----------
    container_name:
        Azure Blob container to use (default ``"sentinelweave-reports"``).
    connection_string:
        Azure Storage connection string.  Falls back to the
        ``AZURE_STORAGE_CONNECTION_STRING`` environment variable.

    Example
    -------
    ::

        client = BlobStorageClient()
        client.upload(b"encrypted_payload", "report-2024-01-15.bin")
        data = client.download("report-2024-01-15.bin")
    """

    def __init__(
        self,
        container_name: str = "sentinelweave-reports",
        connection_string: Optional[str] = None,
    ) -> None:
        self.container_name = container_name
        self._conn_str = (
            connection_string
            or os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
        )
        self._azure_client = self._init_azure()

    def _init_azure(self):
        """Attempt to initialise the real Azure SDK client."""
        if not self._conn_str:
            return None
        try:
            from azure.storage.blob import BlobServiceClient  # type: ignore
            svc = BlobServiceClient.from_connection_string(self._conn_str)
            container = svc.get_container_client(self.container_name)
            try:
                container.create_container()
            except Exception:  # noqa: BLE001
                pass  # container likely already exists
            return container
        except ImportError:
            return None
        except Exception:  # noqa: BLE001
            return None

    @property
    def is_azure_connected(self) -> bool:
        """True when a live Azure Storage connection is available."""
        return self._azure_client is not None

    def upload(self, data: bytes, blob_name: str) -> str:
        """
        Upload *data* as a blob.

        Args:
            data:      Raw bytes to upload.
            blob_name: Destination blob name / key.

        Returns:
            URI-style string identifying the stored blob
            (``azure://<container>/<name>`` or ``local://<path>``).
        """
        if self._azure_client:
            self._azure_client.upload_blob(blob_name, data, overwrite=True)
            return f"azure://{self.container_name}/{blob_name}"

        # Local fallback
        _ensure_local_root()
        path = _LOCAL_ROOT / "blobs" / blob_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return f"local://{path}"

    def download(self, blob_name: str) -> bytes:
        """
        Download a blob by name.

        Args:
            blob_name: Blob / file name to retrieve.

        Returns:
            Raw bytes.

        Raises:
            FileNotFoundError: If the blob does not exist in local mode.
        """
        if self._azure_client:
            stream = self._azure_client.download_blob(blob_name)
            return stream.readall()

        path = _LOCAL_ROOT / "blobs" / blob_name
        if not path.exists():
            raise FileNotFoundError(f"Blob not found: {blob_name}")
        return path.read_bytes()

    def list_blobs(self) -> list[str]:
        """Return a list of all blob names in the container."""
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
    Store and query threat data in Azure Cosmos DB with a local fallback.

    When ``AZURE_COSMOS_CONNECTION_STRING`` is not set the client stores
    items in ``~/.sentinelweave/cosmos/<db>/<container>.json``.

    Parameters
    ----------
    database_name:
        Cosmos DB database name (default ``"sentinelweave"``).
    container_name:
        Cosmos DB container name (default ``"threat-reports"``).
    connection_string:
        Cosmos DB connection string. Falls back to the
        ``AZURE_COSMOS_CONNECTION_STRING`` environment variable.
    partition_key:
        Container partition key path (default ``"/id"``).
    """

    def __init__(
        self,
        database_name: str = "sentinelweave",
        container_name: str = "threat-reports",
        connection_string: Optional[str] = None,
        partition_key: str = "/id",
    ) -> None:
        self.database_name = database_name
        self.container_name = container_name
        self.partition_key = partition_key
        self._conn_str = (
            connection_string
            or os.environ.get("AZURE_COSMOS_CONNECTION_STRING")
        )
        self._container = self._init_azure()

    def _init_azure(self):
        if not self._conn_str:
            return None
        try:
            from azure.cosmos import CosmosClient, PartitionKey  # type: ignore

            client = CosmosClient.from_connection_string(self._conn_str)
            database = client.create_database_if_not_exists(id=self.database_name)
            container = database.create_container_if_not_exists(
                id=self.container_name,
                partition_key=PartitionKey(path=self.partition_key),
            )
            return container
        except ImportError:
            return None
        except Exception:  # noqa: BLE001
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._container is not None

    def _resolve_partition_key(
        self,
        item_id: str,
        partition_key: Optional[str],
    ) -> str:
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

    def read_item(
        self,
        item_id: str,
        partition_key: Optional[str] = None,
    ) -> Optional[dict]:
        if self._container:
            pk = self._resolve_partition_key(item_id, partition_key)
            return self._container.read_item(item=item_id, partition_key=pk)

        items = self._load_local_items()
        for item in items:
            if str(item.get("id")) == str(item_id):
                return item
        return None

    def delete_item(
        self,
        item_id: str,
        partition_key: Optional[str] = None,
    ) -> bool:
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
    Text Analytics (sentiment, key phrases, entity recognition, PII detection).

    Falls back to a simple keyword-based local implementation when credentials
    are absent.

    Parameters
    ----------
    endpoint:
        Cognitive Services resource endpoint URL.
    api_key:
        Resource API key.

    Example
    -------
    ::

        client = TextAnalyticsClient()
        result = client.analyze("Suspicious login attempt from unknown IP")
        print(result["sentiment"], result["key_phrases"])
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> None:
        self._endpoint = endpoint or os.environ.get("AZURE_TEXT_ANALYTICS_ENDPOINT")
        self._api_key  = api_key  or os.environ.get("AZURE_TEXT_ANALYTICS_KEY")
        self._azure_client = self._init_azure()

    def _init_azure(self):
        if not (self._endpoint and self._api_key):
            return None
        try:
            from azure.ai.textanalytics import TextAnalyticsClient as AzTAC  # type: ignore
            from azure.core.credentials import AzureKeyCredential            # type: ignore
            return AzTAC(self._endpoint, AzureKeyCredential(self._api_key))
        except ImportError:
            return None
        except Exception:  # noqa: BLE001
            return None

    @property
    def is_azure_connected(self) -> bool:
        return self._azure_client is not None

    def analyze(self, text: str) -> dict:
        """
        Analyse *text* and return a structured result dict.

        Keys always present in the return value:

        * ``sentiment``   – ``"positive"``, ``"negative"``, or ``"neutral"``
        * ``key_phrases`` – list of extracted key phrases
        * ``entities``    – list of ``{text, category}`` dicts
        * ``pii_redacted``– version of *text* with PII replaced by ``[REDACTED]``
        * ``source``      – ``"azure"`` or ``"local"``

        Args:
            text: The security event or log message to analyse.

        Returns:
            Analysis result dictionary.
        """
        if self._azure_client:
            return self._analyze_azure(text)
        return self._analyze_local(text)

    # ------------------------------------------------------------------
    # Azure implementation
    # ------------------------------------------------------------------

    def _analyze_azure(self, text: str) -> dict:
        try:
            docs = [text]
            sentiment_result = self._azure_client.analyze_sentiment(docs)[0]
            kp_result        = self._azure_client.extract_key_phrases(docs)[0]
            ner_result       = self._azure_client.recognize_entities(docs)[0]
            pii_result       = self._azure_client.recognize_pii_entities(docs)[0]

            return {
                "sentiment":    sentiment_result.sentiment,
                "key_phrases":  list(kp_result.key_phrases),
                "entities":     [{"text": e.text, "category": e.category} for e in ner_result.entities],
                "pii_redacted": pii_result.redacted_text,
                "source":       "azure",
            }
        except Exception as exc:  # noqa: BLE001
            # Fall back gracefully on any Azure error
            result = self._analyze_local(text)
            result["azure_error"] = str(exc)
            return result

    # ------------------------------------------------------------------
    # Local (offline) implementation
    # ------------------------------------------------------------------

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

        # Simple key-phrase extraction: capitalised words + nouns after verbs
        key_phrases = list({
            w for w in text.split()
            if len(w) > 4 and (w[0].isupper() or w.lower() in self._NEGATIVE_WORDS | self._POSITIVE_WORDS)
        })[:10]

        # Naive IP / hostname entity recognition
        ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        entities = [{"text": ip, "category": "IPAddress"} for ip in ip_re.findall(text)]

        # Redact IPs for PII
        pii_redacted = ip_re.sub("[REDACTED]", text)

        return {
            "sentiment":    sentiment,
            "key_phrases":  key_phrases,
            "entities":     entities,
            "pii_redacted": pii_redacted,
            "source":       "local",
        }


# ---------------------------------------------------------------------------
# Azure Monitor / Application Insights telemetry
# ---------------------------------------------------------------------------

class SecurityTelemetry:
    """
    Emit structured security events to Azure Monitor / Application Insights
    or to a local JSON log file when the SDK is not configured.

    Parameters
    ----------
    connection_string:
        Application Insights connection string.  Falls back to the
        ``AZURE_APPINSIGHTS_CONNECTION_STRING`` environment variable.

    Example
    -------
    ::

        telemetry = SecurityTelemetry()
        telemetry.track_threat(threat_level="HIGH", source_ip="10.0.0.1",
                               signatures=["SSH_BRUTE_FORCE"])
    """

    def __init__(self, connection_string: Optional[str] = None) -> None:
        self._conn_str = (
            connection_string
            or os.environ.get("AZURE_APPINSIGHTS_CONNECTION_STRING")
        )
        self._azure_client = self._init_azure()
        self._local_log = _LOCAL_ROOT / "telemetry.jsonl"

    def _init_azure(self):
        if not self._conn_str:
            return None
        try:
            from azure.monitor.opentelemetry import configure_azure_monitor  # type: ignore
            configure_azure_monitor(connection_string=self._conn_str)
            import logging
            return logging.getLogger("sentinelweave")
        except ImportError:
            return None
        except Exception:  # noqa: BLE001
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
        """
        Record a detected threat event.

        Args:
            threat_level:   Categorical severity string (e.g. ``"HIGH"``).
            source_ip:      Source IP address (may be None).
            signatures:     List of matched attack signature names.
            anomaly_score:  0.0–1.0 composite anomaly score.
            extra:          Any additional key/value pairs to include.
        """
        payload = {
            "timestamp":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "event_type":    "ThreatDetected",
            "threat_level":  threat_level,
            "source_ip":     source_ip,
            "signatures":    signatures or [],
            "anomaly_score": anomaly_score,
            **(extra or {}),
        }

        if self._azure_client:
            try:
                import logging
                self._azure_client.warning(json.dumps(payload))
                return
            except Exception:  # noqa: BLE001
                pass

        # Local JSON-lines fallback
        _ensure_local_root()
        with self._local_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")

    def get_local_events(self) -> list[dict]:
        """
        Read all events written to the local telemetry log.

        Returns:
            List of event dicts (empty list if the log does not exist).
        """
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
