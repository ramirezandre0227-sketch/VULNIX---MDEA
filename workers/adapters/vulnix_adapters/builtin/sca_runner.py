"""Runner SCA: inventario de componentes desde lockfiles y SBOM CycloneDX 1.5.

Se ejecuta en el sandbox (parsea ficheros no confiables). La correlación con la inteligencia de
vulnerabilidades se hace después, fuera del sandbox, contra la base local sincronizada offline.
Fail closed: un manifiesto sin lockfile impide conocer versiones exactas -> error MISSING_LOCKFILE.

Uso: python -I -m vulnix_adapters.builtin.sca_runner <src> <components.json> <sbom.json>
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import quote

from . import RUNNER_VERSION

SKIP_DIRS = {".git", "node_modules", "vendor", "bower_components"}
MAX_LOCK_BYTES = 30 * 1024 * 1024
EXIT_MISSING_LOCKFILE = 3


def _load_json(path: Path):
    if path.stat().st_size > MAX_LOCK_BYTES:
        raise ValueError(f"{path.name} excede el tamaño máximo")
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def parse_composer_lock(path: Path, rel: str) -> list[dict]:
    data = _load_json(path)
    comps = []
    for section, scope in (("packages", "required"), ("packages-dev", "dev")):
        for pkg in data.get(section) or []:
            name, version = pkg.get("name"), str(pkg.get("version", ""))
            if name and version:
                comps.append({"ecosystem": "Packagist", "name": name.lower(), "version": version.lstrip("v"), "scope": scope, "source": rel})
    return comps


def parse_package_lock(path: Path, rel: str) -> list[dict]:
    data = _load_json(path)
    comps = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2/3
        for key, meta in packages.items():
            if not key or not isinstance(meta, dict) or meta.get("link") or "node_modules/" not in key:
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if name and version:
                comps.append({"ecosystem": "npm", "name": name, "version": str(version), "scope": "dev" if meta.get("dev") else "required", "source": rel})
        return comps

    def walk(deps: dict, depth: int = 0):  # lockfileVersion 1
        if depth > 64:
            return
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                comps.append({"ecosystem": "npm", "name": name, "version": str(meta["version"]), "scope": "dev" if meta.get("dev") else "required", "source": rel})
                walk(meta.get("dependencies") or {}, depth + 1)

    walk(data.get("dependencies") or {})
    return comps


_YARN_HEADER = re.compile(r'^"?((?:@[^@/\s"]+/)?[^@\s",]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?')


def parse_yarn_lock(path: Path, rel: str) -> list[dict]:
    if path.stat().st_size > MAX_LOCK_BYTES:
        raise ValueError("yarn.lock excede el tamaño máximo")
    comps, current = [], None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" "):
            m = _YARN_HEADER.match(line.strip())
            current = m.group(1) if m and not line.startswith("__metadata") else None
            continue
        if current:
            v = _YARN_VERSION.match(line)
            if v:
                comps.append({"ecosystem": "npm", "name": current, "version": v.group(1), "scope": "unknown", "source": rel})
                current = None
    return comps


_PNPM_PKG = re.compile(r"^\s{2}['\"]?/?((?:@[^@/\s'\"]+/)?[^@\s'\"/]+)[@/]([0-9][^(:'\"\s]*)")


def parse_pnpm_lock(path: Path, rel: str) -> list[dict]:
    if path.stat().st_size > MAX_LOCK_BYTES:
        raise ValueError("pnpm-lock.yaml excede el tamaño máximo")
    comps, in_packages = [], False
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = line.startswith("packages")
            continue
        if line and not line.startswith(" "):
            in_packages = False
        if in_packages:
            m = _PNPM_PKG.match(line)
            if m:
                comps.append({"ecosystem": "npm", "name": m.group(1), "version": m.group(2), "scope": "unknown", "source": rel})
    return comps


LOCK_PARSERS = {
    "composer.lock": parse_composer_lock,
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
}
NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


def purl(c: dict) -> str:
    if c["ecosystem"] == "npm":
        return f"pkg:npm/{quote(c['name'], safe='/')}@{quote(c['version'])}".replace("pkg:npm/@", "pkg:npm/%40")
    return f"pkg:composer/{c['name']}@{quote(c['version'])}"


def inventory(src: Path) -> dict:
    components: list[dict] = []
    lockfiles, missing, errors = [], [], []
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        files = set(filenames)
        rel_dir = Path(dirpath).relative_to(src).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        if "composer.json" in files and "composer.lock" not in files:
            try:
                cdata = _load_json(Path(dirpath) / "composer.json")
                reqs = {**(cdata.get("require") or {}), **(cdata.get("require-dev") or {})}
                # php, ext-* y lib-* son requisitos de plataforma, no paquetes.
                has_pkgs = any(not (k == "php" or k.startswith(("ext-", "lib-"))) for k in reqs)
            except (ValueError, json.JSONDecodeError, AttributeError):
                has_pkgs = True
            if has_pkgs:
                missing.append(prefix + "composer.json")
        if "package.json" in files and not files.intersection(NPM_LOCKS):
            pkg = Path(dirpath) / "package.json"
            try:
                data = _load_json(pkg)
                has_deps = bool(data.get("dependencies") or data.get("devDependencies") or data.get("optionalDependencies"))
            except (ValueError, json.JSONDecodeError):
                has_deps = True
            if has_deps:
                missing.append(prefix + "package.json")
        for name in sorted(files.intersection(LOCK_PARSERS)):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            rel = prefix + name
            try:
                components.extend(LOCK_PARSERS[name](path, rel))
                lockfiles.append(rel)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                errors.append({"lockfile": rel, "error": str(exc)[:300]})
    unique = {(c["ecosystem"], c["name"], c["version"], c["source"]): c for c in components}
    return {"components": sorted(unique.values(), key=lambda c: (c["ecosystem"], c["name"], c["version"])),
            "lockfiles": lockfiles, "manifests_without_lockfile": missing, "errors": errors}


def cyclonedx(inv: dict) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "tools": [{"vendor": "VULNIX", "name": "vulnix-sca", "version": RUNNER_VERSION}]},
        "components": [{
            "type": "library", "name": c["name"], "version": c["version"], "purl": purl(c),
            "scope": "optional" if c["scope"] == "dev" else "required",
            "properties": [{"name": "vulnix:ecosystem", "value": c["ecosystem"]}, {"name": "vulnix:source", "value": c["source"]}],
        } for c in inv["components"]],
    }


def main() -> int:
    if len(sys.argv) < 4:
        print("uso: sca_runner <src> <components.json> <sbom.json>", file=sys.stderr)
        return 64
    src, out, sbom_out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve()
    inv = inventory(src)
    inv.update({"tool": "vulnix-sca", "runner_version": RUNNER_VERSION})
    out.write_text(json.dumps(inv, indent=1), encoding="utf-8")
    sbom_out.write_text(json.dumps(cyclonedx(inv), indent=1), encoding="utf-8")
    if inv["manifests_without_lockfile"] or inv["errors"]:
        print("Manifiestos sin lockfile o lockfiles ilegibles: " + json.dumps(inv["manifests_without_lockfile"] + inv["errors"]), file=sys.stderr)
        return EXIT_MISSING_LOCKFILE
    return 0


if __name__ == "__main__":
    sys.exit(main())
