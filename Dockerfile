FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/kcb064/network-watchdog" \
      org.opencontainers.image.description="Self-hosted homelab health monitor: UniFi, Home Assistant, AdGuard, Docker, TrueNAS, WAN" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.example.yaml .
COPY netwatch ./netwatch

EXPOSE 8787
VOLUME ["/config", "/data"]

HEALTHCHECK --interval=60s --timeout=10s --retries=3 --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/healthz', timeout=5)"

CMD ["python", "-m", "netwatch", "--config", "/config/config.yaml", "--data", "/data"]
