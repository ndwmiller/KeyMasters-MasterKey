#!/usr/bin/env bash
# SLIDE 7 — brute force the JSON login endpoint until the rate limiter trips.
# Expected: attempts 1-5 → 401, attempt 6+ → 429.
B=${BASE_URL:-http://localhost:8000}
USER=${USER_NAME:-alice}

for i in 1 2 3 4 5 6 7; do
  curl -s -o /dev/null -w "attempt $i → %{http_code}\n" \
    -X POST "$B/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USER\",\"master_password\":\"guess$i\"}"
done
