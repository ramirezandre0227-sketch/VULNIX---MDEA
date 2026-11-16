"""Configuración por variables de entorno (con lectura opcional de un fichero .env en la raíz del repo)."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_dotenv(path: Path) -> None:
    """Carga KEY=VALUE sin sobrescribir el entorno real. Sin dependencias externas."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


@dataclass(frozen=True)
class Settings:
    db_dsn: str
    admin_dsn: str | None
    data_dir: Path
    sandbox_root: Path
    api_internal_url: str
    internal_token: str
    php_bin: str
    node_bin: str
    worker_id: str
    poll_interval: float = 2.0
    analysis_timeout_s: int = 3600
    heartbeat_s: int = 60
    max_workers: int = 1
    extra: dict = field(default_factory=dict)

    @staticmethod
    def load(env_file: Path | None = None) -> "Settings":
        _load_dotenv(env_file or REPO_ROOT / ".env")
        data_dir = Path(os.environ.get("VULNIX_DATA_DIR") or REPO_ROOT / "var" / "data")
        return Settings(
            db_dsn=os.environ.get("VULNIX_DB_DSN", ""),
            admin_dsn=os.environ.get("VULNIX_ADMIN_DSN") or None,
            data_dir=data_dir,
            sandbox_root=Path(os.environ.get("VULNIX_SANDBOX_ROOT") or REPO_ROOT / "var" / "sandbox"),
            api_internal_url=os.environ.get("VULNIX_API_INTERNAL_URL", "http://127.0.0.1:8000").rstrip("/"),
            internal_token=os.environ.get("VULNIX_INTERNAL_TOKEN", ""),
            php_bin=os.environ.get("VULNIX_PHP_BIN", "php"),
            node_bin=os.environ.get("VULNIX_NODE_BIN", "node"),
            worker_id=os.environ.get("VULNIX_WORKER_ID") or f"{socket.gethostname()}-{os.getpid()}",
            poll_interval=float(os.environ.get("VULNIX_POLL_INTERVAL", "2")),
            analysis_timeout_s=int(os.environ.get("VULNIX_ANALYSIS_TIMEOUT_S", "3600")),
            max_workers=int(os.environ.get("VULNIX_MAX_WORKERS", "1")),
        )
