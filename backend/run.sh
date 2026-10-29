#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  source .venv/bin/activate
  pip install fastapi uvicorn websockets boto3 python-dotenv
else
  source .venv/bin/activate
fi
export SOURCE="${SOURCE:-replay}"
exec uvicorn main:app --reload --host 0.0.0.0 --port 8000
