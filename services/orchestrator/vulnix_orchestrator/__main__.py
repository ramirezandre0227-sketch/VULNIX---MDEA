"""CLI del orquestador.

  python -m vulnix_orchestrator run       # bucle continuo (servicio)
  python -m vulnix_orchestrator drain     # procesa la cola pendiente y termina
  python -m vulnix_orchestrator analyzers # registra y muestra el estado de los analizadores
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from vulnix_core.config import Settings

from .worker import Worker


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vulnix-orchestrator")
    p.add_argument("command", choices=["run", "drain", "analyzers"], nargs="?", default="run")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    settings = Settings.load()
    if not settings.db_dsn or not settings.internal_token:
        print("Falta VULNIX_DB_DSN o VULNIX_INTERNAL_TOKEN (ver .env).", file=sys.stderr)
        return 2
    worker = Worker(settings)
    if args.command == "analyzers":
        print(json.dumps(worker.register_analyzers(), indent=2, ensure_ascii=False))
        return 0
    if args.command == "drain":
        print(f"{worker.drain()} jobs procesados")
        return 0
    worker.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
