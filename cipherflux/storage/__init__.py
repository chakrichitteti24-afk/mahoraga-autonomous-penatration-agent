"""
Storage package initialization with safe directory fallback.
"""
import os
from pathlib import Path

def get_cipherflux_data_dir() -> Path:
    """
    Get the active CipherFlux data directory.
    Prefers CIPHERFLUX_DATA_DIR, then ~/.cipherflux, falling back to local .cipherflux if permissions restricted.
    """
    env_dir = os.environ.get("CIPHERFLUX_DATA_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    try:
        user_dir = Path.home() / ".cipherflux"
        user_dir.mkdir(parents=True, exist_ok=True)
        test_file = user_dir / ".perm_check"
        test_file.touch()
        test_file.unlink()
        return user_dir
    except (PermissionError, OSError):
        # Fallback to local repository folder
        repo_dir = Path(__file__).resolve().parent.parent.parent / ".cipherflux"
        repo_dir.mkdir(parents=True, exist_ok=True)
        return repo_dir
