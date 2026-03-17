"""
Azure configuration and environment schema.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Optional


@dataclass(frozen=True)
class AzureConfig:
    storage_connection_string: Optional[str] = None
    storage_account_url: Optional[str] = None
    storage_container: str = "sentinelweave-reports"

    cosmos_connection_string: Optional[str] = None
    cosmos_endpoint: Optional[str] = None
    cosmos_database: str = "sentinelweave"
    cosmos_container: str = "threat-reports"
    cosmos_partition_key: str = "/id"

    text_analytics_endpoint: Optional[str] = None
    text_analytics_key: Optional[str] = None

    appinsights_connection_string: Optional[str] = None
    key_vault_url: Optional[str] = None

    service_bus_connection_string: Optional[str] = None
    service_bus_namespace: Optional[str] = None
    service_bus_queue: str = "sentinelweave-events"

    event_hubs_connection_string: Optional[str] = None
    event_hubs_namespace: Optional[str] = None
    event_hub_name: str = "sentinelweave-events"

    @classmethod
    def from_env(cls) -> "AzureConfig":
        return cls(
            storage_connection_string=os.getenv("AZURE_STORAGE_CONNECTION_STRING"),
            storage_account_url=os.getenv("AZURE_STORAGE_ACCOUNT_URL"),
            storage_container=os.getenv("AZURE_STORAGE_CONTAINER", "sentinelweave-reports"),
            cosmos_connection_string=os.getenv("AZURE_COSMOS_CONNECTION_STRING"),
            cosmos_endpoint=os.getenv("AZURE_COSMOS_ENDPOINT"),
            cosmos_database=os.getenv("AZURE_COSMOS_DATABASE", "sentinelweave"),
            cosmos_container=os.getenv("AZURE_COSMOS_CONTAINER", "threat-reports"),
            cosmos_partition_key=os.getenv("AZURE_COSMOS_PARTITION_KEY", "/id"),
            text_analytics_endpoint=os.getenv("AZURE_TEXT_ANALYTICS_ENDPOINT"),
            text_analytics_key=os.getenv("AZURE_TEXT_ANALYTICS_KEY"),
            appinsights_connection_string=os.getenv("AZURE_APPINSIGHTS_CONNECTION_STRING"),
            key_vault_url=os.getenv("AZURE_KEYVAULT_URL"),
            service_bus_connection_string=os.getenv("AZURE_SERVICEBUS_CONNECTION_STRING"),
            service_bus_namespace=os.getenv("AZURE_SERVICEBUS_NAMESPACE"),
            service_bus_queue=os.getenv("AZURE_SERVICEBUS_QUEUE", "sentinelweave-events"),
            event_hubs_connection_string=os.getenv("AZURE_EVENTHUBS_CONNECTION_STRING"),
            event_hubs_namespace=os.getenv("AZURE_EVENTHUBS_NAMESPACE"),
            event_hub_name=os.getenv("AZURE_EVENTHUB_NAME", "sentinelweave-events"),
        )

    def validate(self) -> list[str]:
        warnings: list[str] = []
        if not (self.storage_connection_string or self.storage_account_url):
            warnings.append("Blob Storage is not configured.")
        if not (self.cosmos_connection_string or self.cosmos_endpoint):
            warnings.append("Cosmos DB is not configured.")
        if not self.text_analytics_endpoint:
            warnings.append("Text Analytics endpoint is not configured.")
        if self.text_analytics_endpoint and not self.text_analytics_key:
            warnings.append("Text Analytics key not set (AAD auth will be used).")
        if not self.appinsights_connection_string:
            warnings.append("App Insights connection string is not configured.")
        if not self.key_vault_url:
            warnings.append("Key Vault URL is not configured.")
        if not (self.service_bus_connection_string or self.service_bus_namespace):
            warnings.append("Service Bus is not configured.")
        if not (self.event_hubs_connection_string or self.event_hubs_namespace):
            warnings.append("Event Hubs is not configured.")
        return warnings


ENV_SCHEMA = [
    ("AZURE_STORAGE_CONNECTION_STRING", "Storage connection string"),
    ("AZURE_STORAGE_ACCOUNT_URL", "Storage account URL"),
    ("AZURE_STORAGE_CONTAINER", "Storage container name"),
    ("AZURE_COSMOS_CONNECTION_STRING", "Cosmos DB connection string"),
    ("AZURE_COSMOS_ENDPOINT", "Cosmos DB endpoint URL"),
    ("AZURE_COSMOS_DATABASE", "Cosmos DB database name"),
    ("AZURE_COSMOS_CONTAINER", "Cosmos DB container name"),
    ("AZURE_COSMOS_PARTITION_KEY", "Cosmos DB partition key"),
    ("AZURE_TEXT_ANALYTICS_ENDPOINT", "Text Analytics endpoint URL"),
    ("AZURE_TEXT_ANALYTICS_KEY", "Text Analytics API key"),
    ("AZURE_APPINSIGHTS_CONNECTION_STRING", "App Insights connection string"),
    ("AZURE_KEYVAULT_URL", "Key Vault URL"),
    ("AZURE_SERVICEBUS_CONNECTION_STRING", "Service Bus connection string"),
    ("AZURE_SERVICEBUS_NAMESPACE", "Service Bus namespace"),
    ("AZURE_SERVICEBUS_QUEUE", "Service Bus queue name"),
    ("AZURE_EVENTHUBS_CONNECTION_STRING", "Event Hubs connection string"),
    ("AZURE_EVENTHUBS_NAMESPACE", "Event Hubs namespace"),
    ("AZURE_EVENTHUB_NAME", "Event Hubs hub name"),
]
