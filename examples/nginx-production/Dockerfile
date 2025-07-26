FROM nginx:latest

RUN apt-get update && \
    apt-get install -y git python3 python3-dev build-essential curl systemctl && \
    git clone https://github.com/AccessiTech/nginx-security-monitor.git /opt/nginx-security-monitor && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:$PATH"

RUN cd /opt/nginx-security-monitor && poetry install --no-root

