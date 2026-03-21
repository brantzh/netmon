# NetMon Software Deployment Guide

## 1. Deployment Modes

NetMon provides three deployment modes:

| Mode | Users | Complexity | Use Case |
|------|-------|------------|----------|
| CLI | 1 | Low | Terminal direct run |
| Web Single | 1 | Medium | Single-user Web UI |
| Web Multi | Multiple | Medium-High | Multi-user concurrent |

---

## 2. Pre-Deployment Check

```bash
# 1. Check Python version
python3 --version  # Should be 3.8+

# 2. Check pip availability
pip3 --version

# 3. Check directory exists
ls -la /Users/ben/.openclaw/workspace/netmon/
```

---

## 3. Mode One: CLI Terminal Mode

### 3.1 Quick Start

```bash
cd /Users/ben/.openclaw/workspace/netmon/core

# Default scan (192.168.1-254.1-254)
python3 realtime_subnet_monitor.py

# Scan with specified parameters
python3 realtime_subnet_monitor.py \
  --ip-prefix 192.168 \
  --start-subnet 1 \
  --end-subnet 254 \
  --scan-ip-start 1 \
  --scan-ip-end 64 \
  --mode ping
```

### 3.2 Parameter Reference

| Parameter | Short | Default | Description |
|-----------|-------|---------|-------------|
| --ip-prefix | - | 192.168 | Network prefix |
| --start-subnet | - | 1 | Start subnet |
| --end-subnet | - | 254 | End subnet |
| --scan-ip-start | - | 1 | IP start |
| --scan-ip-end | - | 254 | IP end |
| --mode | - | ping | Scan mode |
| --tcp-port | - | 22 | TCP port |
| --refresh-interval | - | 120 | Refresh interval |
| --subnets-per-group | - | 4 | Subnets per group |

### 3.3 Interactive Operations

| Key | Function |
|-----|----------|
| r | Manual scan trigger |
| m | Switch scan mode |
| q | Exit program |
| a-h | Settings |

---

## 4. Mode Two: Single-User Web

### 4.1 Install Dependencies

```bash
cd /Users/ben/.openclaw/workspace/netmon/web
pip3 install flask
```

### 4.2 Start Service

```bash
# Default port 80
sudo python3 netmon_web.py

# Specify port
sudo NETMON_WEB_PORT=8080 python3 netmon_web.py

# Run in background
nohup sudo python3 netmon_web.py > /var/log/netmon.log 2>&1 &
```

### 4.3 Access

```
http://<serverIP>/
```

### 4.4 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/status | GET | Get status |
| /api/scan | POST | Start scan |
| /api/scan | DELETE | Stop scan |
| /api/results | GET | Get results |
| /api/groups | GET | Get groups |
| /api/config | GET/POST | Config management |

### 4.5 API Authentication

```bash
# Set API key
export NETMON_API_KEY=your-secret-key

# Request with key
curl -H "X-API-Key: your-secret-key" http://localhost/api/status
```

---

## 5. Mode Three: Multi-User Web

### 5.1 Install Dependencies

```bash
cd /Users/ben/.openclaw/workspace/netmon/multi/api
pip3 install flask
```

### 5.2 Start Service

```bash
# Default port 80, max 5 concurrent scans
sudo python3 netmon_web_multi.py

# Custom configuration
export NETMON_WEB_PORT=8080
export NETMON_API_KEY=your-secret-key
export NETMON_IP_PREFIX=10.0
sudo python3 netmon_web_multi.py
```

### 5.3 Multi-User Support

- Automatic user session creation
- Each user has independent scan instance
- Distinguish by `X-User-ID` or `user_id` parameter

```bash
# Create new user scan
curl -X POST "http://localhost/api/scan?user_id=user-123" \
  -H "X-API-Key: your-secret-key"

# Get specific user results
curl "http://localhost/api/results?user_id=user-123" \
  -H "X-API-Key: your-secret-key"
```

---

## 6. Production Deployment

### 6.1 Using Nginx Reverse Proxy

```nginx
# /etc/nginx/sites-available/netmon
server {
    listen 80;
    server_name netmon.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Enable configuration:
```bash
sudo ln -s /etc/nginx/sites-available/netmon /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 6.2 Systemd Service (Linux)

```ini
# /etc/systemd/system/netmon.service
[Unit]
Description=NetMon Network Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/Users/ben/.openclaw/workspace/netmon/web
ExecStart=/usr/bin/python3 /Users/ben/.openclaw/workspace/netmon/web/netmon_web.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable netmon
sudo systemctl start netmon
```

### 6.3 Docker Deployment (Optional)

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY . /app

RUN pip install flask

EXPOSE 80
CMD ["python3", "netmon_web.py"]
```

Build and run:
```bash
docker build -t netmon .
docker run -d -p 80:80 --name netmon netmon
```

---

## 7. Configuration Examples

### 7.1 Scan /26 Subnet (64 IPs)

```bash
python3 realtime_subnet_monitor.py \
  --ip-prefix 192.168 \
  --start-subnet 1 \
  --end-subnet 254 \
  --scan-ip-start 1 \
  --scan-ip-end 64 \
  --mode ping
```

### 7.2 TCP Port Scanning

```bash
python3 realtime_subnet_monitor.py \
  --mode tcp \
  --tcp-port 22 \
  --ip-prefix 192.168 \
  --start-subnet 1 \
  --end-subnet 10
```

### 7.3 nmap Mode

```bash
# Requires nmap installation
sudo apt install nmap

python3 realtime_subnet_monitor.py \
  --mode nmap \
  --ip-prefix 192.168 \
  --start-subnet 1 \
  --end-subnet 254
```

---

## 8. Security Recommendations

### 8.1 Firewall

```bash
# Allow only internal network access
sudo ufw allow from 192.168.0.0/16 to any port 80
sudo ufw allow from 10.0.0.0/8 to any port 80
sudo ufw enable
```

### 8.2 API Key

- MUST set `NETMON_API_KEY` in production
- Rotate key periodically
- Use HTTPS for transmission

### 8.3 Least Privilege

- Avoid running Web service as root
- Create dedicated user `netmon`
- Limit log file permissions

---

## 9. Performance Tuning

### 9.1 Large-Scale Scan Parameters

| Scenario | Recommended Settings |
|----------|---------------------|
| 20K IPs | `--refresh-interval 180` |
| High concurrency | Modify code `max_threads = 1000` |
| Low latency network | `--retry-count 1` |

### 9.2 Multi-User Limits

```python
# Modify concurrent limit in code
scan_executor = ThreadPoolExecutor(max_workers=10)  # Change to 10
```

---

## 10. Troubleshooting

### 10.1 Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| ModuleNotFoundError | Missing flask | pip3 install flask |
| Permission denied | Port in use | Use different port |
| ping timeout | Firewall block | Check firewall rules |
| No such file | Path error | Check working directory |

### 10.2 Log Locations

| Mode | Log Location |
|------|--------------|
| CLI | Current directory *.log |
| Web | /var/log/netmon.log |
| Docker | docker logs netmon |

### 10.3 Debug Mode

```bash
# Enable debug output
export NETMON_DEBUG=true
python3 netmon_web.py
```

---

## 11. Version History

| Version | Date | Features |
|---------|------|----------|
| v1.x | 2026-03 | Initial release |
| v2.x | 2026-03-21 | Thread safety fixes |

---

*Document Version: 2.0*
*Updated: 2026-03-21*