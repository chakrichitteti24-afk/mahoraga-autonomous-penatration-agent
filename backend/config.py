import os
from pathlib import Path
from typing import List, Set
from pydantic import BaseModel, Field

class Settings(BaseModel):
    app_name: str = "CipherFlux Labs - Enterprise-Grade Security Assessment Platform"
    app_version: str = "2.0.0"
    api_prefix: str = "/api"
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = True
    
    # Workspace root path
    workspace_root: Path = Path(__file__).resolve().parent.parent
    
    # Concurrency and performance controls
    max_concurrent_requests: int = 10
    default_request_timeout: float = 8.0
    scan_rate_limit_per_second: float = 20.0
    
    # CORS allowed origins
    allowed_origins: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    
    # Scope & Security Settings
    enforce_authorization_checks: bool = True
    allow_private_ip_scans: bool = True  # Allowed for local development/lab environments (127.0.0.1, localhost)
    
    # File extensions to include in SAST code scanning
    sast_allowed_extensions: List[str] = [
        ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".env", ".yaml", ".yml",
        ".sql", ".sh", ".bash", ".go", ".rs", ".java", ".php", ".cs", ".xml",
        ".tf", ".hcl", ".dockerfile"
    ]
    
    # Directories ignored during SAST traversal
    sast_ignored_dirs: Set[str] = {
        "node_modules", ".git", ".venv", "venv", "__pycache__", "dist", "build",
        ".next", ".oxlint", ".pytest_cache", "target", "vendor"
    }

settings = Settings()
