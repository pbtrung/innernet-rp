#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
case "${1:-unit}" in
  unit)
    python3 tests/fixtures/reference.py --check tests/fixtures/protocol-v1.json
    cargo test --workspace --locked
    ;;
  integration)
    cargo test -p innernet-pq --locked --test native_interop
    ;;
  docker-smoke|docker-faults|compatibility|load)
    echo "Suite '$1' is not implemented at M0; this is not a passing/skipped result." >&2
    exit 2
    ;;
  *) echo "Usage: bash tests/run.sh {unit|integration|docker-smoke|docker-faults|compatibility|load}" >&2; exit 2 ;;
esac
