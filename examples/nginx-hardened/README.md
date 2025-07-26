# NGINX Hardened Template

## Start

./start.sh

## Stop

docker-compose down

## Logs

logs/access.log, logs/error.log

## Security Features

- Strict file permissions (mount configs as read-only)
- Rate limiting, request size limits
- Strong TLS (certs in ./certs)
- Security headers (CSP, HSTS, Referrer-Policy)
- ModSecurity/Fail2ban integration possible
