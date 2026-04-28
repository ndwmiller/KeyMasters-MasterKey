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
RESP=$(curl -s -w "\n%{http_code}" "$B/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","master_password":"Correct!horse1"}')
CODE=$(printf '%s\n' "$RESP" | tail -n 1)
BODY=$(printf '%s\n' "$RESP" | sed '$d')

if [ "$CODE" = "429" ]; then
  cat <<'MSG'
  ✗ alice is rate-limited (429). The brute-force demo locked her for 15 min.
    The limiter lives in process memory — restart uvicorn (Ctrl-C in the
    server terminal, then rerun the same command) and re-run ./demo/seed.sh.
MSG
  exit 1
fi
if [ "$CODE" != "200" ]; then
  echo "  ✗ login failed: HTTP $CODE"
  echo "    body: $BODY"
  exit 1
fi
TOK=$(printf '%s\n' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

echo "→ create a credential so slide 8's strings|grep has a real target"
curl -s "$B/credentials" \
  -H "Authorization: Bearer $TOK" \
  -H 'Content-Type: application/json' \
  -d '{"service":"github","username":"alice@example.com","password":"hunter2","notes":"work"}' \
  -o /dev/null -w "  status: %{http_code}\n"

echo "✓ seed complete"
