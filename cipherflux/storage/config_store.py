"""
Configuration & Settings Management for CipherFlux Labs.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from . import get_cipherflux_data_dir

class ConfigStore:
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            self.config_dir = get_cipherflux_data_dir()
        else:
            self.config_dir = Path(config_dir)

        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / "config.json"
        self._config: Dict[str, Any] = self._default_config()
        self.load()

    def _default_config(self) -> Dict[str, Any]:
        default_out = str(self.config_dir / "reports")
        return {
            "app_name": "CipherFlux Labs",
            "app_version": "1.0.0",
            "default_scan_timeout": 8.0,
            "max_concurrency": 10,
            "request_rate_limit": 50,
            "http_user_agent": "Mozilla/5.0 (X11; Kali Linux x86_64) CipherFlux/1.0 (Defensive Vulnerability Scanner)",
            "proxy_url": "",
            "output_directory": default_out,
            "default_report_format": "pdf",
            "terminal_colors": True,
            "log_level": "INFO",
            "enforce_scope": True,
            "allow_private_ips": True,
            "safe_mode_only": True,
            "cve_database_auto_update": True,
        }

    def load(self) -> None:
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                    self._config.update(saved)
            except Exception:
                pass
        else:
            self.save()

    def save(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump(self._config, f, indent=2)

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._config[key] = value
        self.save()

    def all(self) -> Dict[str, Any]:
        return dict(self._config)

    def reset_defaults(self) -> None:
        self._config = self._default_config()
        self.save()

config_store = ConfigStore()
