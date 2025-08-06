# Dockerfile for Nginx Security Monitor in a production environment
# This Dockerfile sets up an Nginx server with the Nginx Security Monitor application
# It installs necessary dependencies, configures the environment, and prepares the application for deployment

# Base image with specific version for stability
FROM nginx:1.25-alpine

# Update the package list and install necessary packages in a single layer to reduce image size
RUN apk add --no-cache \
    coreutils \
    git \
    python3 \
    py3-pip \
    build-base \
    python3-dev \
    linux-headers \
    musl-dev \
    curl && \
    python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install --no-cache-dir poetry && \
    ([ ! -e /usr/bin/python ] && ln -s /usr/bin/python3 /usr/bin/python || echo "Python symlink already exists")

# Add the virtual environment to PATH
ENV PATH="/opt/venv/bin:$PATH"

# Copy only what's needed for dependency installation first
WORKDIR /opt/nginx-security-monitor
COPY pyproject.toml poetry.lock ./
COPY schema.yml ./
# --- Or use git clone (for CI/remote builds):
# RUN git clone --branch example-testing https://github.com/AccessiTech/nginx-security-monitor.git /opt/nginx-security-monitor

# Use our virtual environment with Poetry
RUN . /opt/venv/bin/activate && \
    poetry config virtualenvs.in-project true && \
    poetry install --with dev --no-interaction --no-root

# Copy the rest of the application after dependency installation
COPY . .

# DEV: start the monitor service in development mode with enhanced debugging
# This command runs Nginx in the background and then the Nginx Security Monitor service 
# with the fallback configuration that we know works
# It uses our virtual environment to ensure all dependencies are available
CMD nginx && . /opt/venv/bin/activate && poetry run python -m nginx_security_monitor.monitor_service /opt/nginx-security-monitor/config/settings.yaml
