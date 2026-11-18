#!/usr/bin/env bash
# Seed the local WordPress target with users + posts so there is something to
# enumerate. Safe to re-run. Requires the stack to be up: docker compose up -d
set -euo pipefail

URL="http://localhost:8080"
wp() { docker compose run --rm -T wpcli "$@"; }

echo "[*] Waiting for WordPress core files + database..."
for i in $(seq 1 30); do
  if wp core version >/dev/null 2>&1; then break; fi
  sleep 2
done

if ! wp core is-installed >/dev/null 2>&1; then
  echo "[*] Installing WordPress (admin / admin123)..."
  wp core install \
    --url="$URL" \
    --title="Vulnerable Test Site" \
    --admin_user=admin \
    --admin_password=admin123 \
    --admin_email=admin@example.test \
    --skip-email
else
  echo "[*] WordPress already installed."
fi

# Give admin a published post so it shows up in the REST /users endpoint.
wp post create --post_status=publish --post_author=1 \
  --post_title="Welcome" --post_content="First post." >/dev/null

# Create a couple of extra users, each with a published post.
create_user() {
  local login="$1" email="$2" role="$3" pass="$4"
  if ! wp user get "$login" >/dev/null 2>&1; then
    wp user create "$login" "$email" --role="$role" --user_pass="$pass" >/dev/null
  fi
  local uid; uid="$(wp user get "$login" --field=ID)"
  wp post create --post_status=publish --post_author="$uid" \
    --post_title="Post by $login" --post_content="Hello from $login." >/dev/null
}

create_user editor1  editor1@example.test  editor  Sup3rSecret!
create_user author1  author1@example.test  author  tr0ub4dor

echo "[+] Done. Users seeded:"
wp user list --fields=ID,user_login,display_name,roles
echo "[+] Target ready at $URL"
