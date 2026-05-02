#!/usr/bin/env bash
set -euo pipefail

# One-time server bootstrap for Nginx + Let's Encrypt on Ubuntu.
# Usage:
#   sudo DOMAIN=itu-minitwit.me EMAIL=you@example.com APP_UPSTREAM_PORT=8080 ./bootstrap_droplet_tls.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root (sudo)."
  exit 1
fi

DOMAIN="${DOMAIN:-}"
EMAIL="${EMAIL:-}"
APP_UPSTREAM_PORT="${APP_UPSTREAM_PORT:-8080}"
SERVER_NAME="${SERVER_NAME:-$DOMAIN www.$DOMAIN}"

if [[ -z "${DOMAIN}" ]]; then
  echo "DOMAIN is required. Example: DOMAIN=itu-minitwit.me"
  exit 1
fi

if [[ -z "${EMAIL}" ]]; then
  echo "EMAIL is required. Example: EMAIL=you@example.com"
  exit 1
fi

echo "Installing Nginx and Certbot..."
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx
systemctl enable --now nginx

echo "Configuring firewall (ufw) if available..."
if command -v ufw >/dev/null 2>&1; then
  ufw allow OpenSSH || true
  ufw allow 'Nginx Full' || true
fi

NGINX_CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"

echo "Creating Nginx reverse-proxy config at ${NGINX_CONF_PATH}..."
cat > "${NGINX_CONF_PATH}" <<EOF
server {
    listen 80;
    listen [::]:80;

    server_name ${SERVER_NAME};

    location = /grafana {
        return 301 /grafana/;
    }

    location /grafana/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Prefix /grafana;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        proxy_pass http://127.0.0.1:${APP_UPSTREAM_PORT};
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

ln -sf "${NGINX_CONF_PATH}" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
rm -f /etc/nginx/sites-enabled/default

echo "Validating and reloading Nginx..."
nginx -t
systemctl reload nginx

echo "Requesting TLS certificate from Let's Encrypt..."
certbot --nginx -d "${DOMAIN}" -d "www.${DOMAIN}" --non-interactive --agree-tos -m "${EMAIL}" --redirect --keep-until-expiring

echo "Testing cert renewal (dry run)..."
certbot renew --dry-run

echo "Bootstrap completed for ${DOMAIN}."
