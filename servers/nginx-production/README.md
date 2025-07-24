# NGINX Production Template

## Start

./start.sh

## Stop

docker-compose down

## Logs

logs/access.log, logs/error.log

## Security Features

- Secure headers
- Minimal modules
- Strong TLS (add certs for SSL)
- Proper log rotation (configure in production)
