"""Sandbox efímero por job (manual §8).

- Directorio temporal propio (src de solo lectura, out, tmp, home) destruido al terminar el job.
- Entorno mínimo: NUNCA hereda credenciales (DSN de BD, tokens de servicio, claves).
- Límites: tiempo de pared, tamaño de salida, memoria y número de procesos
  (Windows: Job Object; POSIX: rlimits + grupo de procesos propio).
- La red no se puede bloquear por proceso sin privilegios en Windows: las herramientas integradas no
  usan red, y la ejecución de builds/DAST requiere una VM desechable (isolation_level lo deja registrado).
"""

from __future__ import annotations

import os
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .extract import ExtractLimits, safe_extract

IS_WINDOWS = os.name == "nt"


@dataclass(frozen=True)
class SandboxLimits:
    process_memory_mb: int = 1024
    job_memory_mb: int = 2048
    max_processes: int = 32
    max_output_bytes: int = 64 * 1024 * 1024
    cpu_seconds: int = 900


@dataclass
class RunResult:
    exit_code: int | None
    timed_out: bool
    duration_s: float
    stdout_path: Path
    stderr_path: Path
    killed_reason: str | None = None

    def stderr_tail(self, limit: int = 2000) -> str:
        try:
            data = self.stderr_path.read_bytes()[-limit:]
        except OSError:
            return ""
        return data.decode("utf-8", errors="replace")


def _on_rm_error(func, path, _exc):
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        pass


class Sandbox:
    def __init__(self, root: Path, job_id: str, limits: SandboxLimits | None = None, extract_limits: ExtractLimits | None = None):
        self.root = Path(root)
        self.job_id = job_id
        self.limits = limits or SandboxLimits()
        self.extract_limits = extract_limits or ExtractLimits()
        self.base: Path | None = None

    # ------------------------------------------------------------------ ciclo de vida
    def __enter__(self) -> "Sandbox":
        self.root.mkdir(parents=True, exist_ok=True)
        self.base = self.root / f"job-{self.job_id[:8]}-{secrets.token_hex(6)}"
        for sub in ("src", "out", "tmp", "home"):
            (self.base / sub).mkdir(parents=True)
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()

    def destroy(self) -> None:
        if self.base and self.base.exists():
            shutil.rmtree(self.base, onerror=_on_rm_error)
        self.base = None

    @property
    def src(self) -> Path:
        assert self.base is not None
        return self.base / "src"

    @property
    def out(self) -> Path:
        assert self.base is not None
        return self.base / "out"

    @property
    def isolation_level(self) -> str:
        return "windows-job-object" if IS_WINDOWS else "posix-rlimits-pgroup"

    # ------------------------------------------------------------------ materialización del artefacto
    def materialize(self, artifact: Path, kind: str, filename: str) -> list[str]:
        if kind == "ZIP":
            return safe_extract(artifact, self.src, self.extract_limits)
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in Path(filename).name) or "artifact.txt"
        target = self.src / safe_name
        shutil.copyfile(artifact, target)
        os.chmod(target, stat.S_IREAD)
        return [safe_name]

    # ------------------------------------------------------------------ ejecución
    def _env(self, extra: dict[str, str] | None) -> dict[str, str]:
        assert self.base is not None
        env: dict[str, str] = {
            "PATH": os.environ.get("PATH", ""),
            "TEMP": str(self.base / "tmp"), "TMP": str(self.base / "tmp"), "TMPDIR": str(self.base / "tmp"),
            "HOME": str(self.base / "home"), "USERPROFILE": str(self.base / "home"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
            "NO_COLOR": "1", "CI": "1", "VULNIX_SANDBOX": "1",
        }
        if IS_WINDOWS:
            for key in ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"):
                if key in os.environ:
                    env[key] = os.environ[key]
            env["APPDATA"] = env["LOCALAPPDATA"] = str(self.base / "home")
        env.update(extra or {})
        return env

    def run(self, argv: list[str], timeout_s: int, env: dict[str, str] | None = None, cwd: Path | None = None) -> RunResult:
        assert self.base is not None, "sandbox no inicializado"
        stdout_path = self.out / f"stdout-{secrets.token_hex(4)}.log"
        stderr_path = self.out / f"stderr-{secrets.token_hex(4)}.log"
        started = time.monotonic()
        killed: str | None = None
        timed_out = False
        with stdout_path.open("wb") as so, stderr_path.open("wb") as se:
            kwargs = dict(stdin=subprocess.DEVNULL, stdout=so, stderr=se, cwd=str(cwd or self.base), env=self._env(env), close_fds=True)
            job = None
            if IS_WINDOWS:
                from .winjob import JobObject

                job = JobObject(self.limits.process_memory_mb, self.limits.job_memory_mb, self.limits.max_processes)
                proc = job.spawn(argv, **kwargs)
            else:
                proc = subprocess.Popen(argv, preexec_fn=self._posix_limits, start_new_session=True, **kwargs)  # noqa: PLW1509
            try:
                while True:
                    try:
                        proc.wait(timeout=0.25)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if time.monotonic() - started > timeout_s:
                        timed_out, killed = True, "TIMEOUT"
                    elif stdout_path.stat().st_size + stderr_path.stat().st_size > self.limits.max_output_bytes:
                        killed = "OUTPUT_LIMIT"
                    if killed:
                        self._kill(proc, job)
                        proc.wait(timeout=10)
                        break
            finally:
                if job is not None:
                    job.close()
                elif proc.poll() is None:
                    self._kill(proc, None)
        return RunResult(
            exit_code=None if killed else proc.returncode,
            timed_out=timed_out,
            duration_s=round(time.monotonic() - started, 3),
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            killed_reason=killed,
        )

    def _kill(self, proc: subprocess.Popen, job) -> None:
        if job is not None:
            job.terminate()
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]
            except (ProcessLookupError, PermissionError):
                proc.kill()

    def _posix_limits(self) -> None:  # pragma: no cover - solo POSIX
        import resource

        mem = self.limits.process_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CPU, (self.limits.cpu_seconds, self.limits.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_NPROC, (self.limits.max_processes, self.limits.max_processes))
        resource.setrlimit(resource.RLIMIT_FSIZE, (self.limits.max_output_bytes, self.limits.max_output_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def python_cmd(module: str, *args: str) -> list[str]:
    """Invoca un runner integrado en modo aislado (-I: ignora cwd, PYTHONPATH y site de usuario)."""
    return [sys.executable, "-I", "-m", module, *args]
