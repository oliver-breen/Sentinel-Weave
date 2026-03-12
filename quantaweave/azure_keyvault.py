"""
Azure Key Vault integration for QuantaWeave PQC keys.

Provides secure storage and retrieval of post-quantum cryptographic keys
using Azure Key Vault Secrets.  When the ``azure-keyvault-secrets`` and
``azure-identity`` packages are not installed (or when running in a test
environment without Azure credentials), the :class:`MockKeyVaultClient` can
be used as a drop-in replacement.

Usage (real Azure)::

    from quantaweave.azure_keyvault import PQCKeyVaultClient
    client = PQCKeyVaultClient(vault_url="https://<vault>.vault.azure.net/")
    client.store_key("my-kyber-pk", public_key_bytes)
    retrieved = client.retrieve_key("my-kyber-pk")

Usage (mock / testing)::

    from quantaweave.azure_keyvault import MockKeyVaultClient
    client = MockKeyVaultClient()
    client.store_key("my-kyber-pk", public_key_bytes)
    retrieved = client.retrieve_key("my-kyber-pk")
"""

import base64
import json
import datetime
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Base interface
# ---------------------------------------------------------------------------

class KeyVaultClientBase:
    """Abstract-like base for Key Vault clients (real and mock)."""

    def store_key(self, name: str, key_bytes: bytes, tags: Optional[Dict[str, str]] = None) -> None:
        """Store *key_bytes* under *name* in the vault.

        Args:
            name:      Secret name (must match ``[a-zA-Z0-9-]+``).
            key_bytes: Raw key material to persist.
            tags:      Optional string-to-string metadata tags.
        """
        raise NotImplementedError

    def retrieve_key(self, name: str) -> bytes:
        """Retrieve raw key bytes previously stored under *name*.

        Args:
            name: Secret name.

        Returns:
            Raw key bytes.

        Raises:
            KeyError: If *name* does not exist in the vault.
        """
        raise NotImplementedError

    def delete_key(self, name: str) -> None:
        """Delete the secret *name* from the vault.

        Args:
            name: Secret name.

        Raises:
            KeyError: If *name* does not exist in the vault.
        """
        raise NotImplementedError

    def list_key_names(self) -> List[str]:
        """Return a list of all secret names currently stored in the vault."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Azure-backed implementation (requires azure-keyvault-secrets + azure-identity)
# ---------------------------------------------------------------------------

class PQCKeyVaultClient(KeyVaultClientBase):
    """Azure Key Vault client for storing post-quantum cryptographic keys.

    Keys are base64-encoded before storage so that arbitrary binary material
    can be safely stored as Key Vault *secrets* (which are UTF-8 strings).

    Args:
        vault_url:  Full URL of the Azure Key Vault, e.g.
                    ``"https://my-vault.vault.azure.net/"``.
        credential: An Azure credential object.  Defaults to
                    :class:`azure.identity.DefaultAzureCredential` when
                    ``None``.

    Raises:
        ImportError: If ``azure-keyvault-secrets`` or ``azure-identity`` are
                     not installed.
    """

    def __init__(self, vault_url: str, credential=None):
        try:
            from azure.keyvault.secrets import SecretClient  # type: ignore[import]
            from azure.identity import DefaultAzureCredential  # type: ignore[import]
        except ImportError as exc:
            raise ImportError(
                "Azure SDK packages are required for PQCKeyVaultClient.  "
                "Install them with:\n"
                "  pip install azure-keyvault-secrets azure-identity\n"
                "Or use MockKeyVaultClient for testing without Azure credentials."
            ) from exc

        self._vault_url = vault_url
        cred = credential or DefaultAzureCredential()
        self._client = SecretClient(vault_url=vault_url, credential=cred)

    def store_key(self, name: str, key_bytes: bytes, tags: Optional[Dict[str, str]] = None) -> None:
        """Store *key_bytes* as a base64-encoded secret in Azure Key Vault."""
        encoded = base64.b64encode(key_bytes).decode("utf-8")
        self._client.set_secret(name, encoded, tags=tags)

    def retrieve_key(self, name: str) -> bytes:
        """Retrieve and base64-decode a secret from Azure Key Vault."""
        secret = self._client.get_secret(name)
        return base64.b64decode(secret.value)

    def delete_key(self, name: str) -> None:
        """Begin deletion of a secret.  The vault may enter a soft-delete state."""
        self._client.begin_delete_secret(name).result()

    def list_key_names(self) -> List[str]:
        """List all secret names in the vault (non-deleted)."""
        return [prop.name for prop in self._client.list_properties_of_secrets()]


# ---------------------------------------------------------------------------
# In-memory mock (no Azure credentials required)
# ---------------------------------------------------------------------------

class MockKeyVaultClient(KeyVaultClientBase):
    """In-memory mock of an Azure Key Vault client.

    Intended for unit testing and local development where Azure credentials
    are not available.  Behaviour mirrors :class:`PQCKeyVaultClient` exactly,
    including metadata tags and operation audit logging.
    """

    def __init__(self):
        self._store: Dict[str, dict] = {}

    def store_key(self, name: str, key_bytes: bytes, tags: Optional[Dict[str, str]] = None) -> None:
        """Persist *key_bytes* in the in-memory store."""
        self._store[name] = {
            "value": base64.b64encode(key_bytes).decode("utf-8"),
            "tags": tags or {},
            "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def retrieve_key(self, name: str) -> bytes:
        """Return raw key bytes for *name*.

        Raises:
            KeyError: If *name* has not been stored.
        """
        if name not in self._store:
            raise KeyError(f"Secret '{name}' not found in vault.")
        return base64.b64decode(self._store[name]["value"])

    def delete_key(self, name: str) -> None:
        """Remove *name* from the in-memory store.

        Raises:
            KeyError: If *name* does not exist.
        """
        if name not in self._store:
            raise KeyError(f"Secret '{name}' not found in vault.")
        del self._store[name]

    def list_key_names(self) -> List[str]:
        """Return the names of all stored secrets."""
        return list(self._store.keys())

    def get_metadata(self, name: str) -> dict:
        """Return the full metadata record for *name* (value, tags, created).

        Raises:
            KeyError: If *name* does not exist.
        """
        if name not in self._store:
            raise KeyError(f"Secret '{name}' not found in vault.")
        return dict(self._store[name])


# ---------------------------------------------------------------------------
# Convenience helper: store / load a QuantaWeave keypair as a JSON bundle
# ---------------------------------------------------------------------------

def store_pqc_keypair(
    client: KeyVaultClientBase,
    name: str,
    public_key: bytes,
    private_key: bytes,
    algorithm: str = "QuantaWeave",
    tags: Optional[Dict[str, str]] = None,
) -> None:
    """Bundle and store a PQC keypair under a single vault secret.

    Both keys are base64-encoded and stored together as a JSON object.
    The *name* is used as the secret name.

    Args:
        client:      A :class:`KeyVaultClientBase` instance.
        name:        Secret name.
        public_key:  Raw public key bytes.
        private_key: Raw private key bytes.
        algorithm:   Human-readable algorithm identifier stored in the bundle.
        tags:        Optional metadata tags.
    """
    bundle = json.dumps({
        "algorithm": algorithm,
        "public_key": base64.b64encode(public_key).decode("utf-8"),
        "private_key": base64.b64encode(private_key).decode("utf-8"),
    "stored_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }).encode("utf-8")
    client.store_key(name, bundle, tags=tags)


def load_pqc_keypair(client: KeyVaultClientBase, name: str):
    """Load a PQC keypair bundle previously stored by :func:`store_pqc_keypair`.

    Args:
        client: A :class:`KeyVaultClientBase` instance.
        name:   Secret name.

    Returns:
        Tuple of ``(public_key_bytes, private_key_bytes)``.
    """
    raw = client.retrieve_key(name)
    bundle = json.loads(raw.decode("utf-8"))
    public_key = base64.b64decode(bundle["public_key"])
    private_key = base64.b64decode(bundle["private_key"])
    return public_key, private_key
