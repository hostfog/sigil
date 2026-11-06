from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .conftest import INTEROP

SCRIPT = Path(__file__).resolve().parents[1] / "interop.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)


def test_gen_then_check(tmp_path: Path) -> None:
    out = tmp_path / "python.json"
    assert run("gen", str(out)).returncode == 0

    entries = json.loads(out.read_text(encoding="utf-8"))
    assert len(entries) == len(INTEROP["cases"]) == 41
    assert set(entries[0]) == {"kind", "alg", "key", "token"}
    assert set(entries[-1]) == {"kind", "alg", "enc", "key", "token"}

    result = run("check", str(out))
    assert result.returncode == 0, result.stderr
    assert "41/41 passed" in result.stdout


def test_check_fails_on_bad_token(tmp_path: Path) -> None:
    out = tmp_path / "python.json"
    run("gen", str(out))
    entries = json.loads(out.read_text(encoding="utf-8"))
    entries[0]["token"] = entries[1]["token"]
    out.write_text(json.dumps(entries), encoding="utf-8")

    result = run("check", str(out))
    assert result.returncode == 1
    assert "40/41 passed" in result.stdout
