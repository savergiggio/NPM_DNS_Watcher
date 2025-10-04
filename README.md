# 🔄 DNS Monitor for Nginx Proxy Manager

Automatic DNS monitoring service that updates IP addresses in Nginx Proxy Manager configurations when they change.

## 🚀 Quick Start

### Using Docker Compose (Recommended)

1. **Simple Setup** - Add to your existing `docker-compose.yml`:

```yaml
services:
  dns-monitor:
    build:
      context: https://github.com/your-username/npm-dns-monitor.git
      dockerfile: Dockerfile
    container_name: dns-monitor
    restart: unless-stopped
    environment:
      - TZ=Europe/Rome
      - DNS_DOMAINS=yourdomain.duckdns.org
      - DNS_CHECK_INTERVAL=300
      - DNS_NGINX_CONTAINER=nginx-proxy
    volumes:
      - /path/to/nginx/data:/data:rw
      - ./dns_logs:/app/logs:rw
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - nginx-proxy
```

2. **Start the service**:
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

**Multiple domains:**
```yaml
- DNS_DOMAINS=home.duckdns.org,office.duckdns.org,server.example.com
```

**Custom check interval (every 1 minute):**
```yaml
- DNS_CHECK_INTERVAL=60
```

## 🔧 Features

- ✅ **Automatic DNS monitoring** - Periodically checks domain IP addresses
- ✅ **Smart IP detection** - Only updates when public IP addresses change
- ✅ **Nginx integration** - Automatically restarts Nginx Proxy Manager
- ✅ **Configuration backup** - Creates backups before making changes
- ✅ **Comprehensive logging** - Detailed logs for monitoring and debugging
- ✅ **Environment configuration** - No external config files needed
- ✅ **Docker integration** - Seamless integration with existing setups

## 📁 How It Works

1. **DNS Resolution**: Periodically resolves configured domains to IP addresses
2. **Change Detection**: Compares current IPs with previously known IPs
3. **Config Update**: Updates Nginx Proxy Manager configuration files when IPs change
4. **Backup Creation**: Creates timestamped backups before modifications
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
- **Backup system** prevents configuration loss
- **No external dependencies** beyond standard Python libraries
- **Minimal container** based on Alpine Linux

## 🛠️ Development

### Local Build
```bash
git clone https://github.com/your-username/npm-dns-monitor.git
cd npm-dns-monitor
docker build -t dns-monitor .
```

### Manual Configuration
If you prefer JSON configuration over environment variables, mount a config file:
```yaml
volumes:
  - ./dns_config.json:/app/config/dns_config.json:ro
```

## 📝 License

MIT License - see LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/npm-dns-monitor/issues)
- **Documentation**: See the `/docs` folder for detailed guides
- **Examples**: Check the `/examples` folder for configuration samples
