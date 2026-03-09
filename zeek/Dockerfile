FROM zeek/zeek:lts

LABEL maintainer="NSM Stack" \
    description="Zeek Network Security Monitor — JSON log output"

# Install GeoIP database support and curl
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmaxminddb0 \
    libmaxminddb-dev \
    mmdb-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create log output directory
RUN mkdir -p /zeek-logs && chmod 777 /zeek-logs

# Copy local site configuration
COPY local.zeek /usr/local/zeek/share/zeek/site/local.zeek

# Set Zeek log directory to shared volume
ENV ZEEK_LOG_DIR=/zeek-logs

# Zeek runs as root for raw socket access (NET_RAW cap granted in compose)
USER root

ENTRYPOINT ["/bin/bash", "-c"]
CMD ["zeek -i eth0 -C /usr/local/zeek/share/zeek/site/local.zeek 2>&1"]
