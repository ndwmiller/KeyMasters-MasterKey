#!/usr/bin/env bash
# SLIDE 8 — open the live sqlite as if it had been exfiltrated.
# Expected: ciphertext blobs in credentials, bcrypt hash in users,
# and zero plaintext leakage of the seeded "github" / "hunter2".
DB=${DB_PATH:-./master_key.sqlite}

echo "── credentials.row ──"
sqlite3 "$DB" "SELECT id, hex(service_enc), hex(password_enc) FROM credentials LIMIT 1;"

echo
echo "── users.row ──"
sqlite3 "$DB" "SELECT username, hex(bcrypt_hash) FROM users LIMIT 1;"

echo
echo "── plaintext scan ──"
strings "$DB" | grep -iE 'github|hunter2' || echo '[no plaintext credentials found]'
