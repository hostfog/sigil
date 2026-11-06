#!/usr/bin/env bash
# Every implementation verifies tokens produced by every other one.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

run() {
  case "$1" in
    go)     (cd "$root/go" && go run ./cmd/sigil-interop "$2" "$3") ;;
    node)   node "$root/node/interop.mjs" "$2" "$3" ;;
    php)    php "$root/php/bin/interop.php" "$2" "$3" ;;
    python) python3 "$root/python/interop.py" "$2" "$3" ;;
  esac
}

langs=(go node php python)

for lang in "${langs[@]}"; do
  run "$lang" gen "$out/$lang.json"
done

failed=0
for from in "${langs[@]}"; do
  for to in "${langs[@]}"; do
    if run "$to" check "$out/$from.json" >/dev/null; then
      echo "ok    $from -> $to"
    else
      echo "FAIL  $from -> $to"
      failed=1
    fi
  done
done

exit $failed
