# NetMon - IP Network Monitoring Tool for HPC/GPU Clusters

Advanced network monitoring solution designed specifically for large-scale HPC/GPU clusters with multiple NICs per machine. Supports both single-user and multi-user concurrent architectures with multiple scan modes.

---

## 🌟 Features

### Multi-User Concurrent Support
- Isolated sessions for each user
- Independent configurations and scan results
- Support for concurrent scanning of different network segments
- Perfect for multi-administrator environments

### Multiple Scan Modes
- **PING Mode**: Fast async ping sweep (optimized for large networks)
- **TCP Mode**: Single port scan (selectable ports)
- **NMAP Mode**: Advanced scanning (if available)

### Web Interface
- Real-time dashboard with visual network activity
- Group and detailed views
- REST API for integration

### Three Deployment Modes
- **CLI Mode**: Interactive terminal interface
- **Single-User Web**: Web-based monitoring
- **Multi-User Web**: Team operations with user isolation

---

## 🚀 Quick Start

### CLI Mode

```bash
cd core
python3 realtime_subnet_monitor_v2.py --mode ping
```

### Web Mode

```bash
# Single-user
cd web
sudo python3 netmon_web_v2.py

# Multi-user
cd multi/api
sudo python3 netmon_web_multi_v2.py
```

### Docker

```bash
cd deploy
docker-compose up -d
```

---

## 📊 Performance

| Scan Scale | Ping Mode | TCP Mode | Nmap Mode |
|------------|-----------|----------|-----------|
| 1,000 IPs  | ~4 sec    | ~2 sec   | ~5 sec    |
| 5,000 IPs  | ~20 sec   | ~8 sec   | ~25 sec   |
| 10,000 IPs | ~40 sec   | ~16 sec  | ~50 sec   |
| 20,000 IPs | ~80 sec   | ~32 sec  | ~100 sec  |

### Resource Consumption

| Resource | 20K IP Scan | Idle |
|----------|-------------|------|
| CPU       | 10-30%     | <1%  |
| Memory    | ~10 MB     | ~5 MB|

---

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NETMON_IP_PREFIX` | 192.168 | Network prefix |
| `NETMON_START_SUBNET` | 1 | Start subnet |
| `NETMON_END_SUBNET` | 254 | End subnet |
| `NETMON_SCAN_IP_START` | 1 | IP start |
| `NETMON_SCAN_IP_END` | 254 | IP end |
| `NETMON_SCAN_MODE` | ping | Scan mode |
| `NETMON_TCP_PORT` | 22 | TCP port |
| `NETMON_WEB_PORT` | 80 | Web port |
| `NETMON_API_KEY` | - | API key |

---

## 🖥️ API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | POST | Trigger scan |
| `/api/scan` | DELETE | Stop scan |
| `/api/results` | GET | Get results |
| `/api/groups` | GET | Get groups |
| `/api/config` | GET/POST | Config management |
| `/api/status` | GET | Status query |

---

## 📁 Project Structure

```
netmon/
├── core/                      # Core scanning engine
│   ├── realtime_subnet_monitor.py
│   └── realtime_subnet_monitor_v2.py
├── web/                       # Single-user Web
│   ├── netmon_web.py
│   └── netmon_web_v2.py
├── multi/
│   └── api/                   # Multi-user Web
│       ├── netmon_web_multi.py
│       └── netmon_web_multi_v2.py
├── deploy/                    # Deployment scripts
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── install-*.sh
│   └── netmon.service
└── docs/                      # Documentation
    ├── 01-Environment_Prep.md
    ├── 02-Deployment.md
    └── 03-Software_Introduction.md
```

---

## 🛠️ Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Python    | 3.8+    | 3.10+       |
| CPU       | 2 cores | 4+ cores    |
| Memory    | 2 GB    | 4 GB        |

### Supported OS
- ✅ macOS 12+
- ✅ Linux (Ubuntu 20.04+, Debian 11+)
- ✅ Windows (WSL2)

---

## 📄 License

MIT License - See LICENSE file for details.

---

## 👥 Authors

NetMon Team

---

*For detailed documentation, see the `docs/` folder.*