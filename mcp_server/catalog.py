from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


class WorkspaceCatalog:
    def __init__(self, catalog_path: str):
        self.catalog_path = Path(catalog_path)
        self._data = self._load()

    def _load(self) -> dict[str, list[str]]:
        if not self.catalog_path.exists():
            return {}
        raw = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Workspace catalog must be a JSON object")

        normalized: dict[str, list[str]] = {}
        for key, tables in raw.items():
            if isinstance(tables, list):
                normalized[key] = [str(t) for t in tables if isinstance(t, str)]
        return normalized

    @property
    def data(self) -> dict[str, list[str]]:
        return self._data

    def keys(self) -> list[str]:
        return sorted(self._data.keys())

    def get(self, key: str) -> list[str]:
        return list(self._data.get(key, []))

    def search_categories(self, text: str) -> dict[str, list[str]]:
        text = text.lower().strip()
        out: dict[str, list[str]] = {}
        for key, tables in self._data.items():
            if text in key.lower() or any(text in t.lower() for t in tables):
                out[key] = tables
        return out

    def cmdb_tables(self) -> list[str]:
        for key in self._data:
            if "cmdb" in key.lower():
                return self._data[key]
        return []

    def telemetry_domains_for_entity(self, entity_type: str) -> list[str]:
        mapping = {
            "ip": [
                "alerts_and_incidents",
                "identity_and_authentication",
                "endpoint_microsoft_defender",
                "network_security_devices",
                "network_and_proxy",
                "cmdb_and_asset_context",
            ],
            "user": [
                "alerts_and_incidents",
                "identity_and_authentication",
                "endpoint_microsoft_defender",
                "email_and_m365",
                "identity_governance_and_pam",
            ],
            "host": [
                "alerts_and_incidents",
                "endpoint_microsoft_defender",
                "windows_servers",
                "linux_servers",
                "cmdb_and_asset_context",
            ],
            "domain": [
                "alerts_and_incidents",
                "network_and_proxy",
                "dns_and_ip_management",
                "email_and_m365",
            ],
            "sha256": [
                "alerts_and_incidents",
                "endpoint_microsoft_defender",
                "security_and_behavior_analytics",
            ],
            "sha1": [
                "alerts_and_incidents",
                "endpoint_microsoft_defender",
                "security_and_behavior_analytics",
            ],
            "md5": [
                "alerts_and_incidents",
                "endpoint_microsoft_defender",
                "security_and_behavior_analytics",
            ],
        }
        default_domains = ["alerts_and_incidents", "identity_and_authentication"]
        return [d for d in mapping.get(entity_type, default_domains) if d in self._data]

    def tables_for_domains(self, domains: Iterable[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for domain in domains:
            for table in self._data.get(domain, []):
                if table not in seen:
                    seen.add(table)
                    out.append(table)
        return out