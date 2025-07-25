# SSL Certificates for Hardened NGINX

Place your SSL certificate and key here as:
- server.crt
- server.key

For testing, you can generate a self-signed certificate with:

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost"

These files will be mounted into the container at /etc/nginx/certs/.
