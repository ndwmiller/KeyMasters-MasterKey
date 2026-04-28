#!/usr/bin/env bash
# Run this once BEFORE the talk while uvicorn is up on :8000.
# Registers the demo user and seeds one credential so the attack
# slides have something real to attack.
set -eu
B=${BASE_URL:-http://localhost:8000}

echo "→ register alice (idempotent — 409 means already there)"
curl -s "$B/auth/register" -H 'Content-Type: application/json' -d '{
  "username": "alice",
  "master_password": "Correct!horse1",
  "recovery_q1": "What was the name of your first pet?",
  "recovery_a1": "Fluffy",
  "recovery_q2": "In what city were you born?",
  "recovery_a2": "Boston"
}' -o /dev/null -w "  status: %{http_code}\n"

echo "→ log in via the JSON API to mint a Bearer token"
TOK=$(curl -s "$B/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","master_password":"Correct!horse1"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

echo "→ create a credential so slide 8's strings|grep has a real target"
curl -s "$B/credentials" \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"service":"github","username":"alice@example.com","password":"hunter2","notes":"work"}' \
  -o /dev/null -w "  status: %{http_code}\n"

echo "✓ seed complete"
