# NGINX Vulnerable Template

## Start

./start.sh

## Stop

docker-compose down

## Logs

logs/access.log, logs/error.log

## Vulnerabilities

- Directory listing enabled
- No security headers
- Permissive CORS
- No SSL
- For testing only! Do not use in production.
