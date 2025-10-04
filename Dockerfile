FROM python:3.11-alpine

# Set working directory
WORKDIR /app

# Install required packages including Docker CLI
RUN apk add --no-cache \
    tzdata \
    docker-cli \
    && rm -rf /var/cache/apk/*

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/config

# Copy application files
COPY dns_monitor.py /app/
COPY manage.py /app/

# Copy config file if it exists (optional)
COPY config/dns_config.example.json /app/config/dns_config.example.json

# Set timezone (optional)
ENV TZ=Europe/Rome

# Create docker group and non-root user for security
RUN addgroup -g 999 docker && \
    addgroup -g 1000 dnsmonitor && \
    adduser -D -s /bin/sh -u 1000 -G dnsmonitor dnsmonitor && \
    adduser dnsmonitor docker

# Change ownership of app directory and ensure logs directory is writable
RUN chown -R dnsmonitor:dnsmonitor /app && \
    chmod 755 /app/logs

# Switch to non-root user
USER dnsmonitor

# Health check
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import socket; socket.gethostbyname('google.com')" || exit 1

# Run the DNS monitor service
CMD ["python", "/app/dns_monitor.py"]
