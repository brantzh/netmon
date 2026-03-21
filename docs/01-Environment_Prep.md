# NetMon Environment Preparation Guide

## 1. Overview

This document describes the runtime environment requirements for NetMon network monitoring software.

### 1.1 Software Architecture

| Component | Description | Location |
|-----------|-------------|-----------|
| realtime_subnet_monitor.py | Core scanning engine | core/ |
| netmon_web.py | Single-user Web API | web/ |
| netmon_web_multi.py | Multi-user Web API | multi/api/ |

---

## 2. Hardware Requirements

### 2.1 Minimum Configuration

| Resource | Requirement | Notes |
|----------|-------------|-------|
| CPU | 2 cores | More = faster scanning |
| Memory | 2 GB | ~10 MB for 20K IPs |
| Disk | 1 GB | Log files |
| Network | 100 Mbps | Scanning speed bottleneck |

### 2.2 Recommended Configuration

| Resource | Recommended | Scenario |
|----------|--------------|----------|
| CPU | 4+ cores | Concurrent scanning |
| Memory | 4 GB | Multi-user/large networks |
| Disk | 5 GB | Long-term operation |
| Network | 1 Gbps | Large-scale scanning |

---

## 3. Operating System

### 3.1 Supported Operating Systems

| OS | Version | Status |
|----|---------|--------|
| macOS | 12+ | ✅ Supported |
| Linux | Ubuntu 20.04+ / Debian 11+ | ✅ Supported |
| Windows | 10/11 (WSL2 recommended) | ✅ Supported |

### 3.2 Windows Notes

- WSL2 (Windows Subsystem for Linux) recommended
- Or use Git Bash / PowerShell
- ping command must be available in system PATH

---

## 4. Required Software

### 4.1 Required Dependencies

| Software | Purpose | Version |
|----------|---------|---------|
| Python | Runtime | 3.8+ |
| pip | Package manager | Included with Python |

### 4.2 Optional Dependencies

| Software | Purpose | Installation |
|----------|---------|--------------|
| nmap | Advanced scanning | `sudo apt install nmap` |
| Flask | Web server | Auto-installed |
| Nginx | Reverse proxy | Production recommended |

### 4.3 Install Required Dependencies

```bash
# macOS
brew install python3

# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip

# Verify
python3 --version
pip3 --version
```

---

## 5. Network Requirements

### 5.1 Scanning Range

| Parameter | Default | Description |
|-----------|---------|-------------|
| IP prefix | 192.168 | Network.Subnet |
| Subnet range | 1-254 | Third octet range |
| IP range | 1-254 | Fourth octet range |

### 5.2 Firewall Requirements

| Port | Purpose | Description |
|------|---------|-------------|
| 22/TCP | SSH | Remote management |
| 80/TCP | HTTP | Web access |
| 443/TCP | HTTPS | Secure access |
| ICMP | Ping | Scanning protocol |

### 5.3 Permission Requirements

- **Ping scanning**: No root required
- **TCP scanning**: No root required (ports 1024+)
- **nmap scanning**: Root recommended (ARP detection)

---

## 6. Environment Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| NETMON_IP_PREFIX | 192.168 | Network prefix |
| NETMON_START_SUBNET | 1 | Start subnet |
| NETMON_END_SUBNET | 254 | End subnet |
| NETMON_SCAN_IP_START | 1 | IP start |
| NETMON_SCAN_IP_END | 254 | IP end |
| NETMON_SCAN_MODE | ping | Scanning mode |
| NETMON_TCP_PORT | 22 | TCP port |
| NETMON_REFRESH_INTERVAL | 120 | Refresh interval (sec) |
| NETMON_RETRY_COUNT | 2 | Retry count |
| NETMON_API_KEY | - | API key |
| NETMON_WEB_PORT | 80 | Web port |

---

## 7. Directory Structure

```
netmon/
├── core/                      # Core scanning engine
│   ├── realtime_subnet_monitor.py
│   ├── realtime_subnet_monitor_v2.py
│   └── realtime_subnet_monitor_v1.9.py.bak
├── web/                       # Single-user Web
│   ├── netmon_web.py
│   ├── netmon_web_v2.py
│   └── netmon_web_v1.py.bak
├── multi/
│   └── api/
│       ├── netmon_web_multi.py
│       ├── netmon_web_multi_v2.py
│       └── netmon_web_multi_v1.py.bak
└── docs/                      # Documentation
    ├── 01-环境准备手册.md
    ├── 01-Environment_Prep.md
    ├── 02-部署手册.md
    └── 02-Deployment.md
```

---

## 8. Verification Checklist

Please confirm the following before installation:

- [ ] Python 3.8+ installed
- [ ] pip available
- [ ] Network reachability test (ping)
- [ ] Firewall allows required ports
- [ ] Sufficient disk space (≥1GB)
- [ ] Sufficient memory (≥2GB)

---

## 9. FAQ

### Q1: "Permission denied" on macOS

**Solution**: No special permission needed, Python can run directly

### Q2: Ping timeout on Windows

**Solution**: Check Windows Firewall settings, allow ICMP

### Q3: nmap not available

**Solution**:
```bash
# Ubuntu
sudo apt install nmap

# macOS
brew install nmap
```

---

*Document Version: 2.0*
*Updated: 2026-03-21*