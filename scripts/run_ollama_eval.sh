#!/usr/bin/env bash
# Run OpenSec eval against Ollama using OLLAMA_BASE_URL + OLLAMA_MODEL from .env
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "Missing .env — copy .env.example and set OLLAMA_BASE_URL" >&2
  echo "  cp .env.example .env" >&2
  exit 1
fi

exec python scripts/eval.py --ollama "$@"
