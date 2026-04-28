#!/usr/bin/env bash
# SLIDE 9 — CSRF rejection. Run demo/login.sh first to populate /tmp/mk.jar.
# Expected: no csrf → 403, with csrf → 303.
JAR=${JAR:-/tmp/mk.jar}
B=${BASE_URL:-http://localhost:8000}

echo "── attack: stolen session, no csrf token ──"
curl -sb "$JAR" -X POST "$B/vault/new" \
  -d 'service=evil&username=x&password=x' \
  -o /dev/null -w "no csrf → %{http_code}\n"

echo
echo "── legit: same request with the matching csrf token ──"
TOK=$(curl -sc "$JAR" -b "$JAR" "$B/vault/new" \
  | grep -oE 'value="[^"]+"' | head -1 | cut -d'"' -f2)
curl -sb "$JAR" -X POST "$B/vault/new" \
  -d "service=github&username=alice&password=hunter2&_csrf=$TOK" \
  -o /dev/null -w "with csrf → %{http_code}\n"
