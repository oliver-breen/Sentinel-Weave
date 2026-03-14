"""
Secure Reporter — SentinelWeave

Generates structured threat-intelligence reports and stores them using a
**hybrid post-quantum encryption** scheme:

1. A fresh 32-byte AES-256 session key is generated for each report.
2. The session key is encrypted with QuantaWeave (LWE-based post-quantum
   encryption), which natively supports exactly 32-byte payloads.
3. The actual report JSON is encrypted with AES-256-GCM using that session key.
4. Both the PQ-encrypted session key and the AES-GCM ciphertext are bundled
   and stored (in Azure Blob Storage or locally).

Why post-quantum encryption for threat reports?
-----------------------------------------------
Threat intelligence often contains sensitive IOC data (IP addresses,
malware hashes, internal system names) that needs to stay confidential both
in transit and at rest.  Classical RSA/ECC encryption could be broken by a
sufficiently powerful quantum computer; using a PQ hybrid scheme future-proofs
the confidentiality of stored reports ("harvest now, decrypt later" defence).

Hybrid design rationale
-----------------------
The QuantaWeave LWE KEM is limited to 32-byte plaintexts (n=256, n//8=32),
which is ideal for wrapping a symmetric key.  AES-256-GCM then handles
arbitrary-length report payloads at full speed.  This mirrors the real-world
pattern used in TLS 1.3 and NIST PQ standards (ML-KEM + AES-GCM).

Example
-------
::

    reporter = SecureReporter()
    pub, priv = reporter.generate_keys()

    report_id = reporter.create_and_store(
        title="Brute-Force Attack Detected",
        events=threat_reports,
        public_key=pub,
    )

    plain = reporter.retrieve_and_decrypt(report_id, priv)
    print(plain["title"])
"""

from __future__ import annotations

import hashlib
import json
import os
import datetime
from typing import Optional

from .azure_integration import BlobStorageClient
from .threat_detector import ThreatReport, ThreatLevel


# ---------------------------------------------------------------------------
# Helpers — lazy imports
# ---------------------------------------------------------------------------

def _get_quantaweave():
    """
    Import QuantaWeave lazily so the module can be loaded even if the package
    path is not on sys.path (e.g. during isolated unit tests).
    """
    try:
        from quantaweave import QuantaWeave  # type: ignore
        return QuantaWeave
    except ImportError as exc:
        raise ImportError(
            "The 'quantaweave' package must be importable to use SecureReporter. "
            "Make sure you are running from the repository root."
        ) from exc


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256-GCM using *key*.

    Returns:
        Tuple of (nonce, ciphertext_with_tag).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-256-GCM *ciphertext* (with tag appended) using *key*/*nonce*.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails (wrong key).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

def _build_report_dict(
    title: str,
    threat_reports: list[ThreatReport],
    metadata: Optional[dict] = None,
) -> dict:
    """Serialise a list of threat reports into a plain-text report dict."""
    events = []
    for r in threat_reports:
        events.append({
            "raw":          r.event.raw,
            "event_type":   r.event.event_type,
            "source_ip":    r.event.source_ip,
            "severity":     r.event.severity,
            "signatures":   r.event.matched_sigs,
            "threat_level": r.threat_level.value,
            "anomaly_score": r.anomaly_score,
            "explanation":  r.explanation,
        })

    by_level = {lvl.value: 0 for lvl in ThreatLevel}
    for r in threat_reports:
        by_level[r.threat_level.value] += 1

    return {
        "schema_version": "1.0",
        "title":          title,
        "generated_at":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "total_events": len(threat_reports),
            "by_threat_level": by_level,
            "max_anomaly_score": max((r.anomaly_score for r in threat_reports), default=0.0),
        },
        "events":    events,
        "metadata":  metadata or {},
    }


# ---------------------------------------------------------------------------
# SecureReporter
# ---------------------------------------------------------------------------

class SecureReporter:
    """
    Creates post-quantum–encrypted threat intelligence reports and stores
    them (in Azure Blob Storage or locally).

    Parameters
    ----------
    security_level:
        QuantaWeave security level — ``'LEVEL1'`` (128-bit), ``'LEVEL3'``
        (192-bit), or ``'LEVEL5'`` (256-bit).  Default: ``'LEVEL1'``.
    blob_client:
        Optional pre-configured :class:`~sentinel_weave.azure_integration.BlobStorageClient`.
        If *None*, a new client with default settings is created.
    """

    def __init__(
        self,
        security_level: str = "LEVEL1",
        blob_client: Optional[BlobStorageClient] = None,
    ) -> None:
        self.security_level = security_level
        self._blob = blob_client or BlobStorageClient()
        self._qw = _get_quantaweave()(security_level)

    # ------------------------------------------------------------------
    # Key management
    # ------------------------------------------------------------------

    def generate_keys(self) -> tuple[dict, dict]:
        """
        Generate a new QuantaWeave public/private key pair.

        Returns:
            Tuple of (public_key, private_key).  Store the private key
            securely; it is required for decryption.
        """
        return self._qw.generate_keypair()

    # ------------------------------------------------------------------
    # Create & encrypt  (hybrid PQ + AES-GCM)
    # ------------------------------------------------------------------

    def create_and_store(
        self,
        title: str,
        events: list[ThreatReport],
        public_key: dict,
        metadata: Optional[dict] = None,
    ) -> str:
        """
        Build a threat report, encrypt it with a hybrid PQ + AES-GCM scheme,
        and store it.

        Hybrid scheme
        ~~~~~~~~~~~~~
        1. Generate a random 32-byte AES-256 session key.
        2. Encrypt the session key with QuantaWeave (LWE, max 32 bytes).
        3. Encrypt the report JSON with AES-256-GCM using the session key.
        4. Bundle and store the PQ-wrapped key + AES ciphertext.

        Args:
            title:      Human-readable report title.
            events:     List of :class:`~sentinel_weave.threat_detector.ThreatReport`
                        objects to include.
            public_key: QuantaWeave public key (from :meth:`generate_keys`).
            metadata:   Optional extra key/value pairs to embed in the report.

        Returns:
            A *report_id* string (use with :meth:`retrieve_and_decrypt`).
        """
        report_dict = _build_report_dict(title, events, metadata)
        plaintext   = json.dumps(report_dict, ensure_ascii=False).encode()

        # 1. Generate 32-byte session key and encrypt with QuantaWeave
        session_key     = os.urandom(32)
        pq_ciphertext   = self._qw.encrypt(session_key, public_key)

        # 2. Encrypt the report with AES-256-GCM
        nonce, aes_ct   = _aes_gcm_encrypt(session_key, plaintext)

        # 3. Bundle everything for storage
        payload = json.dumps({
            "scheme":            "hybrid-pq-aes256gcm",
            "security_level":    self.security_level,
            "pq_ciphertext":     _ciphertext_to_json(pq_ciphertext),
            "aes_nonce":         list(nonce),
            "aes_ciphertext":    list(aes_ct),
        }).encode()

        report_id = _make_report_id(title, report_dict["generated_at"])
        self._blob.upload(payload, report_id)
        return report_id

    # ------------------------------------------------------------------
    # Retrieve & decrypt
    # ------------------------------------------------------------------

    def retrieve_and_decrypt(self, report_id: str, private_key: dict) -> dict:
        """
        Download a stored report and decrypt it.

        Args:
            report_id:   The string returned by :meth:`create_and_store`.
            private_key: QuantaWeave private key (from :meth:`generate_keys`).

        Returns:
            The original report dictionary.

        Raises:
            FileNotFoundError: If the report does not exist in storage.
            ValueError:        If decryption fails (wrong key or corrupt data).
        """
        raw   = self._blob.download(report_id)
        outer = json.loads(raw)

        # 1. Recover the session key via QuantaWeave
        pq_ct       = _json_to_ciphertext(outer["pq_ciphertext"])
        session_key = self._qw.decrypt(pq_ct, private_key)

        # 2. Decrypt the AES-256-GCM payload
        nonce    = bytes(outer["aes_nonce"])
        aes_ct   = bytes(outer["aes_ciphertext"])
        try:
            plaintext = _aes_gcm_decrypt(session_key, nonce, aes_ct)
        except Exception as exc:
            raise ValueError(
                "Report decryption failed — wrong private key or corrupt data."
            ) from exc

        return json.loads(plaintext.decode())

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def list_reports(self) -> list[str]:
        """Return all stored report IDs."""
        return [b for b in self._blob.list_blobs() if b.startswith("report-")]


# ---------------------------------------------------------------------------
# Serialisation helpers for QuantaWeave ciphertexts
# ---------------------------------------------------------------------------

def _ciphertext_to_json(ct: dict) -> dict:
    """
    Convert a QuantaWeave ciphertext dict (which may contain lists of ints)
    into a JSON-serialisable dict.
    """
    def _convert(v):
        if isinstance(v, (list, tuple)):
            return [int(x) for x in v]
        if isinstance(v, dict):
            return {k: _convert(val) for k, val in v.items()}
        return v

    return {k: _convert(v) for k, v in ct.items()}


def _json_to_ciphertext(d: dict) -> dict:
    """Inverse of :func:`_ciphertext_to_json` — no conversion needed."""
    return d


# ---------------------------------------------------------------------------
# Report ID helpers
# ---------------------------------------------------------------------------

def _make_report_id(title: str, generated_at: str) -> str:
    """
    Derive a deterministic, filesystem-safe blob name from a report title
    and timestamp.
    """
    slug = "".join(c if c.isalnum() else "-" for c in title.lower()).strip("-")[:40]
    ts_tag = generated_at.replace(":", "").replace("T", "-").replace("Z", "")[:15]
    digest = hashlib.sha256((title + generated_at).encode()).hexdigest()[:8]
    return f"report-{ts_tag}-{slug}-{digest}.bin"
