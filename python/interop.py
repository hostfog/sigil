"""Cross-language interop: `interop.py gen <out.json>` and `interop.py check <in.json>`."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "src"))

import sigil  # noqa: E402

TESTDATA = HERE.parent / "testdata"
NOW = 1800000000


def load(name: str) -> Any:
    return json.loads((TESTDATA / name).read_text(encoding="utf-8"))


def gen(out: Path) -> int:
    keys = sigil.KeySet.from_json(load("keys.json"))
    spec = load("interop.json")
    results: List[Dict[str, Any]] = []
    for case in spec["cases"]:
        key = keys.get(case["key"])
        assert key is not None, case["key"]
        if case["kind"] == "jws":
            token = sigil.sign(spec["claims"], key, alg=case["alg"])
        else:
            recipient = key if key.type == "oct" else key.public_key()
            token = sigil.encrypt(spec["claims"], recipient, alg=case["alg"], enc=case["enc"])
        results.append({**case, "token": token})
    out.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


def check(path: Path) -> int:
    keys = sigil.KeySet.from_json(load("keys.json"))
    expected = load("interop.json")["claims"]
    entries = json.loads(path.read_text(encoding="utf-8"))
    failures = 0
    for entry in entries:
        label = " ".join(filter(None, (entry["kind"], entry["alg"], entry.get("enc"), entry["key"])))
        try:
            key = keys.get(entry["key"])
            if key is None:
                raise LookupError(f"unknown key {entry['key']}")
            options: Dict[str, Any] = {"algorithms": [entry["alg"]], "issuer": "sigil", "audience": "all", "now": NOW}
            if entry["kind"] == "jws":
                token = sigil.verify(entry["token"], key.public_key() if key.type != "oct" else key, **options)
            else:
                token = sigil.decrypt(entry["token"], key, **options)
                if token.header.get("enc") != entry["enc"]:
                    raise ValueError(f"enc is {token.header.get('enc')}")
            if token.claims != expected:
                raise ValueError("claims differ")
        except Exception as exc:
            failures += 1
            print(f"FAIL  {label}: {type(exc).__name__}: {exc}", file=sys.stderr)
        else:
            print(f"ok    {label}")
    print(f"{len(entries) - failures}/{len(entries)} passed")
    return 1 if failures or not entries else 0


def main(argv: List[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("gen", "check"):
        print("usage: interop.py gen <out.json> | check <in.json>", file=sys.stderr)
        return 2
    command = gen if argv[1] == "gen" else check
    return command(Path(argv[2]))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
