FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
        iw iproute2 nftables hostapd dnsmasq-base rfkill wireless-tools procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md ./
COPY airtrap ./airtrap
RUN pip install --no-cache-dir .
VOLUME ["/var/log/airtrap", "/var/lib/airtrap", "/etc/airtrap"]
ENTRYPOINT ["airtrap"]
CMD ["run", "-c", "/etc/airtrap/airtrap.yml"]
