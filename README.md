# 🔄 DNS Monitor for Nginx Proxy Manager

Automatic DNS monitoring service that updates IP addresses in Nginx Proxy Manager configurations when they change.

## 🚀 Quick Start

### Using Docker Compose (Recommended)

1. **Step 0** - The first time add your public ip inside the Access List in NPM GUI  `allow` field:
 
2. **Simple Setup** - Add to your existing `docker-compose.yml`:

```yaml
version: '3.8'

services:
  nginx-proxy:
    image: 'jc21/nginx-proxy-manager:latest'
    container_name: nginx-proxy
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt

  dns-monitor:
    # Build directly from GitHub
    build:
      context: https://github.com/savergiggio/NPM_DNS_Watcher.git
      dockerfile: Dockerfile
    container_name: dns-monitor
    restart: unless-stopped
    # Map container user to host user for proper permissions
    user: "0:0"
    environment:
      - TZ=Europe/Rome
      # MODIFY THESE VALUES:
      - DNS_DOMAINS=yourdomain.com
      - DNS_CHECK_INTERVAL=60
      - DNS_NGINX_CONTAINER=nginx-proxy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      # Share nginx data directory
      - ./data:/data:rw
      # Mount logs directory
      - ./dns_logs:/app/logs:rw
      # Mount Docker socket (Linux/Mac)
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - nginx-proxy
```

3. **Start the service**:
```bash
docker-compose up -d
```

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_DOMAINS` | ✅ | - | Domains to monitor (comma-separated) |
| `DNS_CHECK_INTERVAL` | ❌ | `300` | Check interval in seconds |
| `DNS_NGINX_CONTAINER` | ❌ | `nginx-proxy` | Nginx container name to restart |


### Examples

**Single domain:**
```yaml
- DNS_DOMAINS=mydomain.duckdns.org
```

**Custom check interval (every 1 minute):**
```yaml
- DNS_CHECK_INTERVAL=60
```

## 🔧 Features

- ✅ **Automatic DNS monitoring** - Periodically checks domain IP addresses
- ✅ **Smart IP detection** - Only updates when public IP addresses change
- ✅ **Nginx integration** - Automatically restarts Nginx Proxy Manager
- ✅ **Comprehensive logging** - Detailed logs for monitoring and debugging
- ✅ **Environment configuration** - No external config files needed
- ✅ **Docker integration** - Seamless integration with existing setups

## 📁 How It Works

1. **DNS Resolution**: Periodically resolves configured domains to IP addresses
2. **Change Detection**: Compares current IPs with previously known IPs
3. **Config Update**: Updates Nginx Proxy Manager configuration files when IPs change
5. **Nginx Restart**: Automatically restarts the Nginx container to apply changes
6. **Logging**: Records all activities for monitoring and troubleshooting

## 📊 Monitoring

### Logs
- **Container logs**: `docker-compose logs -f dns-monitor`
- **Log files**: `./dns_logs/dns_monitor.log`

### Health Check
The container includes a health check that verifies the service is running properly.

## 🔒 Security

- **Read-only access** to Docker socket (only for container restart)
- **No external dependencies** beyond standard Python libraries
- **Minimal container** based on Alpine Linux

## 🛠️ Development

### Manual Configuration
If you prefer JSON configuration over environment variables, mount a config file:
```yaml
volumes:
  - ./dns_config.json:/app/config/dns_config.json:ro
```

## 📝 License

MIT License - see LICENSE file for details.

