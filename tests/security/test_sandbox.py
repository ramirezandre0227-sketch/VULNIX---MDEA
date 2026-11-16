"""Aislamiento del sandbox (manual §8 y §9: escape de sandbox, límites, destrucción tras el job)."""

import os
import sys

import pytest

from vulnix_sandbox.runner import Sandbox, SandboxLimits


def test_environment_does_not_leak_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNIX_DB_DSN", "postgresql://user:SECRET@db/vulnix")
    monkeypatch.setenv("VULNIX_INTERNAL_TOKEN", "super-secret-token")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "abc")
    with Sandbox(tmp_path, "envtest") as sb:
        r = sb.run([sys.executable, "-I", "-c", "import os,json;print(json.dumps(dict(os.environ)))"], timeout_s=30)
        env = r.stdout_path.read_text()
    assert r.exit_code == 0
    assert "SECRET" not in env and "super-secret-token" not in env and "AWS_SECRET" not in env
    assert "VULNIX_SANDBOX" in env


def test_timeout_kills_process_tree(tmp_path):
    code = ("import subprocess,sys,time\n"
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
            "time.sleep(60)\n")
    with Sandbox(tmp_path, "timeout") as sb:
        r = sb.run([sys.executable, "-I", "-c", code], timeout_s=2)
    assert r.timed_out and r.killed_reason == "TIMEOUT" and r.exit_code is None
    assert r.duration_s < 20


def test_output_limit_kills_process(tmp_path):
    with Sandbox(tmp_path, "output", SandboxLimits(max_output_bytes=200_000)) as sb:
        r = sb.run([sys.executable, "-I", "-c", "import sys\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush()"], timeout_s=30)
    assert r.killed_reason == "OUTPUT_LIMIT"


@pytest.mark.skipif(os.name != "nt", reason="límite de procesos del Job Object de Windows")
def test_process_limit_enforced_on_windows(tmp_path):
    code = ("import subprocess,sys\nok=0\n"
            "procs=[]\n"
            "for i in range(10):\n"
            "    try:\n"
            "        procs.append(subprocess.Popen([sys.executable,'-c','import time;time.sleep(5)'])); ok+=1\n"
            "    except OSError:\n"
            "        pass\n"
            "print(ok)\n"
            "[p.kill() for p in procs]\n")
    with Sandbox(tmp_path, "nproc", SandboxLimits(max_processes=4)) as sb:
        r = sb.run([sys.executable, "-I", "-c", code], timeout_s=60)
        spawned = int(r.stdout_path.read_text().strip() or 0)
    assert spawned < 10


def test_sandbox_is_destroyed(tmp_path):
    with Sandbox(tmp_path, "destroy") as sb:
        base = sb.base
        (sb.src / "f.txt").write_text("x")
        os.chmod(sb.src / "f.txt", 0o444)
    assert base is not None and not base.exists()


def test_isolated_python_ignores_planted_modules(tmp_path):
    """Un json.py plantado en el código analizado no debe importarse (python -I)."""
    with Sandbox(tmp_path, "planted") as sb:
        (sb.src / "json.py").write_text("raise SystemExit('PLANTED')")
        r = sb.run([sys.executable, "-I", "-c", "import json; print('ok')"], timeout_s=30, cwd=sb.src)
        assert r.exit_code == 0 and "ok" in r.stdout_path.read_text()
