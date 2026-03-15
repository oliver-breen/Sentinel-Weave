"""
Federated Threat Intel — SentinelWeave

Enables peer-to-peer sharing of *encrypted* threat-intelligence summaries
between SentinelWeave nodes.

Architecture
------------
Each node is identified by a *node_id* (UUID) and an *AES-256-GCM key* used
to encrypt/decrypt summaries.  Nodes can be added as *peers* using a shared
key (pre-shared key model) or a session key exchanged out-of-band.

Sharing flow
~~~~~~~~~~~~
1. The local node calls :meth:`FederatedIntelHub.create_summary` to build and
   encrypt a :class:`ThreatIntelSummary` from its recent
   :class:`~sentinel_weave.threat_detector.ThreatReport` objects.
2. The encrypted bundle is serialised to JSON and can be:
   - sent directly via :meth:`FederatedIntelHub.share_to_peer` (HTTP POST); or
   - returned as bytes for transport over any channel.
3. The receiving node calls :meth:`FederatedIntelHub.receive_bundle` to
   authenticate, decrypt, and store the summary.
4. Summaries are available via :meth:`FederatedIntelHub.list_summaries` and
   :meth:`FederatedIntelHub.get_summary`.

Encryption
~~~~~~~~~~
Every summary is encrypted with **AES-256-GCM** using the shared key
registered for the sender's *node_id*.  An HMAC-SHA256 of the ciphertext is
included as a message-authentication tag so tampering is detected before
decryption.

HTTP transport
~~~~~~~~~~~~~~
:meth:`share_to_peer` sends a JSON ``POST`` to
``http://<peer_host>:<peer_port>/api/federated/receive``.  No third-party
HTTP library is required; the standard-library ``urllib.request`` is used.

No external dependencies beyond the Python standard library and
``cryptography`` (already required by *SentinelWeave* for AES-GCM).

Example
-------
::

    from sentinel_weave.federated_intel import FederatedIntelHub

    # Node A
    hub_a = FederatedIntelHub(node_id="node-a")
    shared_key = hub_a.generate_shared_key()

    # Node B registers A as a peer
    hub_b = FederatedIntelHub(node_id="node-b")
    hub_b.register_peer("node-a", shared_key)
    hub_a.register_peer("node-b", shared_key)

    # A creates and shares a summary
    bundle = hub_a.create_summary(reports, peer_id="node-b")
    hub_b.receive_bundle(bundle)

    # B inspects received intel
    summaries = hub_b.list_summaries()
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from .threat_detector import ThreatReport, ThreatLevel


# ---------------------------------------------------------------------------
# AES-GCM helpers (same pattern as secure_reporter)
# ---------------------------------------------------------------------------

def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ct


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(nonce, ct, None)


def _hmac_sha256(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ThreatIntelSummary:
    """
    Compact summary of threat intelligence from a remote peer node.

    Attributes:
        sender_id:      Node ID of the originating node.
        received_at:    UTC ISO-8601 timestamp of receipt.
        total_events:   Total number of threat reports summarised.
        threat_counts:  Map of :class:`~sentinel_weave.threat_detector.ThreatLevel`
                        name → count.
        top_sources:    Top source IPs by event count (up to 10).
        top_signatures: Most common matched signatures (up to 10).
        max_anomaly:    Highest anomaly score in the batch.
        campaigns:      List of campaign summary dicts (if available).
        metadata:       Arbitrary extra key/value pairs from the sender.
    """
    sender_id: str
    received_at: str
    total_events: int
    threat_counts: dict[str, int]
    top_sources: list[tuple[str, int]]
    top_signatures: list[tuple[str, int]]
    max_anomaly: float
    campaigns: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "sender_id":      self.sender_id,
            "received_at":    self.received_at,
            "total_events":   self.total_events,
            "threat_counts":  self.threat_counts,
            "top_sources":    self.top_sources,
            "top_signatures": self.top_signatures,
            "max_anomaly":    self.max_anomaly,
            "campaigns":      self.campaigns,
            "metadata":       self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ThreatIntelSummary":
        return cls(
            sender_id      = d["sender_id"],
            received_at    = d["received_at"],
            total_events   = d["total_events"],
            threat_counts  = d["threat_counts"],
            top_sources    = [tuple(x) for x in d.get("top_sources", [])],
            top_signatures = [tuple(x) for x in d.get("top_signatures", [])],
            max_anomaly    = d["max_anomaly"],
            campaigns      = d.get("campaigns", []),
            metadata       = d.get("metadata", {}),
        )


@dataclass
class PeerNode:
    """Represents a known federation peer."""
    node_id: str
    shared_key: bytes          # 32-byte AES-256 key
    host: Optional[str] = None # HTTP host for push delivery
    port: int = 5000           # HTTP port for push delivery

    @property
    def base_url(self) -> str:
        if self.host:
            return f"http://{self.host}:{self.port}"
        return ""


# ---------------------------------------------------------------------------
# Encrypted bundle (wire format)
# ---------------------------------------------------------------------------

_BUNDLE_VERSION = "1"


def _build_bundle(
    sender_id: str,
    peer_key: bytes,
    payload: dict,
) -> dict:
    """Encrypt *payload* and return a JSON-serialisable bundle dict."""
    plaintext = json.dumps(payload, ensure_ascii=False).encode()
    nonce, ct = _aes_gcm_encrypt(peer_key, plaintext)
    ct_hex    = ct.hex()
    tag       = _hmac_sha256(peer_key, ct)
    return {
        "version":   _BUNDLE_VERSION,
        "sender_id": sender_id,
        "nonce":     nonce.hex(),
        "ciphertext": ct_hex,
        "hmac":      tag,
    }


def _open_bundle(bundle: dict, peer_key: bytes) -> dict:
    """Authenticate and decrypt an encrypted bundle, return the inner payload."""
    ct_hex = bundle["ciphertext"]
    tag    = bundle["hmac"]
    # HMAC-SHA256 authentication
    expected = _hmac_sha256(peer_key, bytes.fromhex(ct_hex))
    if not hmac.compare_digest(expected, tag):
        raise ValueError("Bundle authentication failed: HMAC mismatch")
    nonce = bytes.fromhex(bundle["nonce"])
    ct    = bytes.fromhex(ct_hex)
    try:
        plaintext = _aes_gcm_decrypt(peer_key, nonce, ct)
    except Exception as exc:
        raise ValueError("Bundle decryption failed") from exc
    return json.loads(plaintext.decode())


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------

def _build_summary_payload(
    sender_id: str,
    reports: list[ThreatReport],
    metadata: Optional[dict] = None,
) -> dict:
    """Derive a summary dict from a list of ThreatReports."""
    threat_counts: dict[str, int] = {lvl.value: 0 for lvl in ThreatLevel}
    source_counts: dict[str, int] = {}
    sig_counts:    dict[str, int] = {}
    max_anomaly = 0.0

    for r in reports:
        threat_counts[r.threat_level.value] = threat_counts.get(r.threat_level.value, 0) + 1
        ip = r.event.source_ip or "unknown"
        source_counts[ip] = source_counts.get(ip, 0) + 1
        for sig in (r.event.matched_sigs or []):
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
        if r.anomaly_score > max_anomaly:
            max_anomaly = r.anomaly_score

    top_sources = sorted(source_counts.items(), key=lambda x: -x[1])[:10]
    top_sigs    = sorted(sig_counts.items(),    key=lambda x: -x[1])[:10]

    return {
        "sender_id":      sender_id,
        "created_at":     datetime.now(timezone.utc).isoformat(),
        "total_events":   len(reports),
        "threat_counts":  threat_counts,
        "top_sources":    top_sources,
        "top_signatures": top_sigs,
        "max_anomaly":    max_anomaly,
        "metadata":       metadata or {},
    }


# ---------------------------------------------------------------------------
# FederatedIntelHub
# ---------------------------------------------------------------------------

class FederatedIntelHub:
    """
    Manage federation peers and exchange encrypted threat-intelligence
    summaries.

    Parameters
    ----------
    node_id:
        Unique identifier for this node.  Defaults to a random UUID.
    """

    def __init__(self, node_id: Optional[str] = None) -> None:
        self._node_id: str = node_id or str(uuid.uuid4())
        self._peers:   dict[str, PeerNode] = {}
        self._received: list[ThreatIntelSummary] = []

    # ------------------------------------------------------------------
    # Identity & peers
    # ------------------------------------------------------------------

    @property
    def node_id(self) -> str:
        """The unique identifier for this node."""
        return self._node_id

    @staticmethod
    def generate_shared_key() -> bytes:
        """Generate a random 32-byte AES-256 shared key."""
        return os.urandom(32)

    def register_peer(
        self,
        peer_id: str,
        shared_key: bytes,
        host: Optional[str] = None,
        port: int = 5000,
    ) -> None:
        """
        Register a peer node with its shared encryption key.

        Parameters
        ----------
        peer_id:
            Unique identifier of the peer.
        shared_key:
            32-byte pre-shared key used for AES-256-GCM encryption with
            this peer.
        host:
            Optional hostname or IP for HTTP push delivery.
        port:
            HTTP port (default 5000).
        """
        if len(shared_key) != 32:
            raise ValueError("shared_key must be exactly 32 bytes")
        self._peers[peer_id] = PeerNode(
            node_id=peer_id, shared_key=shared_key, host=host, port=port
        )

    def remove_peer(self, peer_id: str) -> None:
        """Remove a registered peer."""
        self._peers.pop(peer_id, None)

    def list_peers(self) -> list[str]:
        """Return the list of registered peer IDs."""
        return list(self._peers)

    def get_peer(self, peer_id: str) -> Optional[PeerNode]:
        """Return the :class:`PeerNode` for *peer_id*, or *None*."""
        return self._peers.get(peer_id)

    # ------------------------------------------------------------------
    # Create & share
    # ------------------------------------------------------------------

    def create_summary(
        self,
        reports: list[ThreatReport],
        peer_id: str,
        metadata: Optional[dict] = None,
    ) -> bytes:
        """
        Build an encrypted threat-intelligence summary for *peer_id*.

        Parameters
        ----------
        reports:
            Recent :class:`~sentinel_weave.threat_detector.ThreatReport`
            objects to summarise.
        peer_id:
            The registered peer to encrypt the summary for.
        metadata:
            Optional extra key/value pairs to embed (e.g. node version,
            region).

        Returns
        -------
        bytes
            JSON-encoded encrypted bundle (UTF-8).
        """
        peer = self._peers.get(peer_id)
        if peer is None:
            raise KeyError(f"Peer {peer_id!r} is not registered")

        payload = _build_summary_payload(self._node_id, reports, metadata)
        bundle  = _build_bundle(self._node_id, peer.shared_key, payload)
        return json.dumps(bundle, ensure_ascii=False).encode()

    def share_to_peer(
        self,
        reports: list[ThreatReport],
        peer_id: str,
        metadata: Optional[dict] = None,
        timeout: int = 10,
    ) -> int:
        """
        Create a summary and HTTP-POST it to ``peer.base_url/api/federated/receive``.

        Parameters
        ----------
        reports:
            Reports to summarise.
        peer_id:
            Target peer.
        metadata:
            Optional extra metadata.
        timeout:
            HTTP request timeout in seconds.

        Returns
        -------
        int
            HTTP status code returned by the peer (200/201 = success).

        Raises
        ------
        KeyError:
            If *peer_id* is not registered.
        ValueError:
            If the peer has no ``host`` configured.
        urllib.error.URLError:
            On network errors.
        """
        peer = self._peers.get(peer_id)
        if peer is None:
            raise KeyError(f"Peer {peer_id!r} is not registered")
        if not peer.host:
            raise ValueError(f"Peer {peer_id!r} has no host configured — cannot push")

        bundle_bytes = self.create_summary(reports, peer_id, metadata)
        url          = f"{peer.base_url}/api/federated/receive"
        req = urllib.request.Request(
            url,
            data=bundle_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status

    # ------------------------------------------------------------------
    # Receive & store
    # ------------------------------------------------------------------

    def receive_bundle(self, bundle_bytes: bytes) -> ThreatIntelSummary:
        """
        Authenticate, decrypt, and store an incoming encrypted bundle.

        Parameters
        ----------
        bundle_bytes:
            Raw bytes as returned by a remote :meth:`create_summary` call.

        Returns
        -------
        ThreatIntelSummary
            The decrypted and parsed summary.

        Raises
        ------
        KeyError:
            If the sender node is not a registered peer.
        ValueError:
            If HMAC authentication or decryption fails.
        """
        bundle = json.loads(bundle_bytes.decode())
        sender_id = bundle.get("sender_id", "")
        peer = self._peers.get(sender_id)
        if peer is None:
            raise KeyError(
                f"Received bundle from unknown sender {sender_id!r}. "
                "Register the sender as a peer first."
            )
        payload = _open_bundle(bundle, peer.shared_key)
        summary = ThreatIntelSummary(
            sender_id      = payload["sender_id"],
            received_at    = datetime.now(timezone.utc).isoformat(),
            total_events   = payload["total_events"],
            threat_counts  = payload["threat_counts"],
            top_sources    = [tuple(x) for x in payload.get("top_sources", [])],
            top_signatures = [tuple(x) for x in payload.get("top_signatures", [])],
            max_anomaly    = payload["max_anomaly"],
            campaigns      = payload.get("campaigns", []),
            metadata       = payload.get("metadata", {}),
        )
        self._received.append(summary)
        return summary

    # ------------------------------------------------------------------
    # Query received summaries
    # ------------------------------------------------------------------

    def list_summaries(self) -> list[ThreatIntelSummary]:
        """Return all received summaries (newest last)."""
        return list(self._received)

    def get_summary(self, sender_id: str) -> Optional[ThreatIntelSummary]:
        """Return the most recent summary from *sender_id*, or *None*."""
        for s in reversed(self._received):
            if s.sender_id == sender_id:
                return s
        return None

    def clear_summaries(self) -> None:
        """Remove all stored summaries."""
        self._received.clear()

    def summary_stats(self) -> dict:
        """
        Return aggregate statistics across all received summaries.

        Returns
        -------
        dict
            Keys: ``total_summaries``, ``total_events``,
            ``peers_seen``, ``max_anomaly_seen``.
        """
        peers: set[str] = set()
        total_events = 0
        max_anomaly  = 0.0
        for s in self._received:
            peers.add(s.sender_id)
            total_events += s.total_events
            if s.max_anomaly > max_anomaly:
                max_anomaly = s.max_anomaly
        return {
            "total_summaries": len(self._received),
            "total_events":    total_events,
            "peers_seen":      sorted(peers),
            "max_anomaly_seen": max_anomaly,
        }

    def __repr__(self) -> str:
        return (
            f"FederatedIntelHub(node_id={self._node_id!r}, "
            f"peers={len(self._peers)}, summaries={len(self._received)})"
        )
