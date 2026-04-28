#!/usr/bin/env bash
# Establishes a logged-in curl jar at /tmp/mk.jar so the CSRF slide can
# show JUST the attack line — the messy session+token capture lives here.
# Run this once before slide 9.
set -eu
JAR=${JAR:-/tmp/mk.jar}
B=${BASE_URL:-http://localhost:8000}

# 1) GET /login to plant the mk_csrf cookie in the jar
curl -sc "$JAR" -b "$JAR" "$B/login" >/dev/null

# 2) Re-fetch the login page and pull the matching csrf token from the form
TOK=$(curl -sc "$JAR" -b "$JAR" "$B/login" \
  | grep -oE 'value="[^"]+"' | head -1 | cut -d'"' -f2)

# 3) Submit the login with the token; the server will set mk_session in the jar
curl -sc "$JAR" -b "$JAR" -X POST "$B/login" \
  -d "username=alice&master_password=Correct!horse1&_csrf=$TOK" \
  -o /dev/null -w "logged in → %{http_code}\n"

echo "✓ jar ready: $JAR"
