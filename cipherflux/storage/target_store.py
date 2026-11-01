"""
Target Management and Authorization Store for CipherFlux Labs.
"""
import os
import json
import csv
import uuid
import ipaddress
import socket
import urllib.parse
from enum import Enum
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

from . import get_cipherflux_data_dir

class TargetType(str, Enum):
    URL = "URL"
    IP = "IP"
    CIDR = "CIDR"
    API = "API"
    DOMAIN = "DOMAIN"

# Cloud metadata addresses that must never be targeted
BLOCKED_METADATA_IPS = {
    "169.254.169.254",
    "100.100.100.200",
}

BLOCKED_METADATA_DOMAINS = {
    "metadata.google.internal",
    "metadata.gcp.internal",
    "instance-data",
}

class TargetItem:
    def __init__(
        self,
        id: str,
        name: str,
        target_type: TargetType,
        value: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        authorized: bool = False,
        authorized_by: str = "",
        authorization_date: str = "",
        scope_notes: str = "",
        allowed_ports: Optional[List[int]] = None,
        allowed_paths: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        created_at: str = "",
    ):
        self.id = id or f"tgt-{uuid.uuid4().hex[:8]}"
        self.name = name or value
        self.target_type = TargetType(target_type) if isinstance(target_type, str) else target_type
        self.value = value.strip()
        self.description = description
        self.tags = tags or []
        self.authorized = authorized
        self.authorized_by = authorized_by
        self.authorization_date = authorization_date or (datetime.now(timezone.utc).isoformat() if authorized else "")
        self.scope_notes = scope_notes
        self.allowed_ports = allowed_ports or []
        self.allowed_paths = allowed_paths or []
        self.excluded_paths = excluded_paths or []
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.target_type.value,
            "value": self.value,
            "description": self.description,
            "tags": self.tags,
            "authorized": self.authorized,
            "authorized_by": self.authorized_by,
            "authorization_date": self.authorization_date,
            "scope_notes": self.scope_notes,
            "allowed_ports": self.allowed_ports,
            "allowed_paths": self.allowed_paths,
            "excluded_paths": self.excluded_paths,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetItem":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            target_type=data.get("type", TargetType.URL),
            value=data.get("value", ""),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            authorized=data.get("authorized", False),
            authorized_by=data.get("authorized_by", ""),
            authorization_date=data.get("authorization_date", ""),
            scope_notes=data.get("scope_notes", ""),
            allowed_ports=data.get("allowed_ports", []),
            allowed_paths=data.get("allowed_paths", []),
            excluded_paths=data.get("excluded_paths", []),
            created_at=data.get("created_at", ""),
        )

class TargetStore:
    """Manages registered targets, authorization states, and scope validation."""

    def __init__(self, storage_dir: Optional[str] = None):
        if storage_dir is None:
            self.storage_dir = get_cipherflux_data_dir()
        else:
            self.storage_dir = Path(storage_dir)

        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.filepath = self.storage_dir / "targets.json"
        self._targets: Dict[str, TargetItem] = {}
        self.load()

    def load(self) -> None:
        if self.filepath.exists():
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        target = TargetItem.from_dict(item)
                        self._targets[target.id] = target
            except Exception:
                self._targets = {}
        else:
            # Seed local safe demonstration targets
            self._seed_default_targets()

    def save(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        data = [t.to_dict() for t in self._targets.values()]
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _seed_default_targets(self) -> None:
        default_target = TargetItem(
            id="tgt-local-dev",
            name="Local Security Lab / Workspace",
            target_type=TargetType.URL,
            value="http://127.0.0.1:8000",
            description="Local development and authorized test workspace",
            tags=["local", "dev", "lab"],
            authorized=True,
            authorized_by="Lead Security Architect",
            scope_notes="Authorized for defensive baseline assessment and canary testing.",
        )
        self._targets[default_target.id] = default_target
        self.save()

    def add_target(self, target: TargetItem) -> TargetItem:
        self._targets[target.id] = target
        self.save()
        return target

    def remove_target(self, target_id: str) -> bool:
        if target_id in self._targets:
            del self._targets[target_id]
            self.save()
            return True
        return False

    def get_target(self, target_id: str) -> Optional[TargetItem]:
        return self._targets.get(target_id)

    def get_by_value(self, value: str) -> Optional[TargetItem]:
        v = value.strip().lower()
        for t in self._targets.values():
            if t.value.strip().lower() == v:
                return t
        return None

    def list_targets(self) -> List[TargetItem]:
        return list(self._targets.values())

    @staticmethod
    def validate_target(value: str, target_type: TargetType) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate target syntax and check SSRF / cloud metadata boundaries.
        Returns: (is_valid, message, metadata)
        """
        val = value.strip()
        metadata: Dict[str, Any] = {"input": val, "type": target_type.value}

        if target_type in (TargetType.URL, TargetType.API):
            if not val.startswith(("http://", "https://")):
                return False, "URL/API target must start with http:// or https://", metadata
            parsed = urllib.parse.urlparse(val)
            host = parsed.hostname or parsed.netloc.split(":")[0]
            if not host:
                return False, "Target URL missing hostname or host segment.", metadata
            metadata["hostname"] = host
            metadata["port"] = parsed.port or (443 if parsed.scheme == "https" else 80)
            metadata["scheme"] = parsed.scheme

            # Check metadata hostnames
            if host.lower() in BLOCKED_METADATA_DOMAINS:
                return False, f"Target violates security policy: cloud metadata endpoint '{host}' is prohibited.", metadata

            # Check IP resolution
            try:
                ip_str = socket.gethostbyname(host)
                metadata["resolved_ip"] = ip_str
                if ip_str in BLOCKED_METADATA_IPS:
                    return False, f"Target resolved to blocked metadata service IP '{ip_str}'.", metadata
            except socket.gaierror:
                metadata["resolved_ip"] = "Unresolved"

            return True, f"Target validated: {val} (Host: {host})", metadata

        elif target_type == TargetType.IP:
            try:
                ip_obj = ipaddress.ip_address(val)
                metadata["ip"] = str(ip_obj)
                metadata["is_private"] = ip_obj.is_private
                metadata["is_loopback"] = ip_obj.is_loopback
                if str(ip_obj) in BLOCKED_METADATA_IPS:
                    return False, f"Target IP '{val}' is a prohibited cloud metadata endpoint.", metadata
                return True, f"Target IP validated: {val}", metadata
            except ValueError:
                return False, f"'{val}' is not a valid IPv4 or IPv6 address.", metadata

        elif target_type == TargetType.CIDR:
            try:
                net = ipaddress.ip_network(val, strict=False)
                metadata["network"] = str(net)
                metadata["num_addresses"] = net.num_addresses
                if net.num_addresses > 65536:
                    return False, f"Network range /{net.prefixlen} ({net.num_addresses} hosts) is too large for controlled assessment.", metadata
                return True, f"Authorized CIDR range validated: {net} ({net.num_addresses} addresses)", metadata
            except ValueError:
                return False, f"'{val}' is not a valid CIDR network range (e.g. 192.168.1.0/24).", metadata

        elif target_type == TargetType.DOMAIN:
            domain = val.lower().split("/")[0].split(":")[0]
            if not domain or "." not in domain:
                return False, f"'{val}' is not a valid domain name.", metadata
            metadata["domain"] = domain
            if domain in BLOCKED_METADATA_DOMAINS:
                return False, f"Domain '{domain}' is a prohibited metadata endpoint.", metadata
            try:
                ip_str = socket.gethostbyname(domain)
                metadata["resolved_ip"] = ip_str
                if ip_str in BLOCKED_METADATA_IPS:
                    return False, f"Domain resolved to blocked metadata IP '{ip_str}'.", metadata
            except socket.gaierror:
                metadata["resolved_ip"] = "Unresolved"

            return True, f"Domain validated: {domain}", metadata

        return False, "Unknown target type.", metadata

    def check_scope(self, target_value: str) -> Tuple[bool, str, Optional[TargetItem]]:
        """
        Check if a given target is explicitly registered and authorized in scope.
        """
        cleaned = target_value.strip().lower()
        for t in self._targets.values():
            val = t.value.strip().lower()
            if cleaned == val or cleaned.startswith(val):
                if not t.authorized:
                    return False, f"Target '{t.value}' is registered but NOT authorized for scanning.", t
                return True, f"Target authorized in scope by '{t.authorized_by}'.", t
        return False, f"Target '{target_value}' is outside the authorized scope registry.", None

    def export_json(self, filepath: str) -> int:
        data = [t.to_dict() for t in self._targets.values()]
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return len(data)

    def import_json(self, filepath: str) -> int:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        count = 0
        for item in data:
            target = TargetItem.from_dict(item)
            self._targets[target.id] = target
            count += 1
        self.save()
        return count

    def export_csv(self, filepath: str) -> int:
        fields = ["id", "name", "type", "value", "authorized", "authorized_by", "tags", "description"]
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            for t in self._targets.values():
                writer.writerow({
                    "id": t.id,
                    "name": t.name,
                    "type": t.target_type.value,
                    "value": t.value,
                    "authorized": t.authorized,
                    "authorized_by": t.authorized_by,
                    "tags": ",".join(t.tags),
                    "description": t.description,
                })
        return len(self._targets)

    def import_csv(self, filepath: str) -> int:
        count = 0
        with open(filepath, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                target = TargetItem(
                    id=row.get("id") or f"tgt-{uuid.uuid4().hex[:8]}",
                    name=row.get("name") or row.get("value", ""),
                    target_type=TargetType(row.get("type", "URL")),
                    value=row.get("value", ""),
                    description=row.get("description", ""),
                    tags=[t.strip() for t in row.get("tags", "").split(",") if t.strip()],
                    authorized=str(row.get("authorized", "")).lower() in ("true", "1", "yes"),
                    authorized_by=row.get("authorized_by", ""),
                )
                self._targets[target.id] = target
                count += 1
        self.save()
        return count

target_store = TargetStore()
