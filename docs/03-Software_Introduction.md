# NetMon Software Introduction

## 1. Overview

**NetMon** is a network monitoring tool designed specifically for High-Performance Computing (HPC) and GPU cluster environments. It enables real-time monitoring of IP address activity across large-scale subnets, helping operations teams quickly discover and manage online devices in clusters.

### 1.1 Core Features

- ⚡ **High-Performance Scanning**: Supports scanning 20,000+ IP addresses in a single run
- 🔄 **Multi-Mode Scanning**: Supports Ping / TCP / Nmap scanning modes
- 👥 **Multi-User Support**: Multiple concurrent users with isolated scan instances
- 🌐 **Web Interface**: Intuitive Web UI and REST API
- 🛡️ **Thread-Safe**: v2.0 fixes support concurrent safe operations

---

## 2. Application Scenarios

### 2.1 Large-Scale HPC/GPU Cluster Monitoring

In HPC/GPU cluster environments, monitoring the online status of large numbers of compute nodes is essential:

| Scenario | Description |
|----------|-------------|
| **GPU Cluster Node Monitoring** | Monitor online status of hundreds of GPU servers |
| **HPC Compute Node Management** | Real-time monitoring of 1000+ compute nodes |
| **Storage Server Monitoring** | Monitor NFS/GPUFS storage server availability |
| **Network Equipment Monitoring** | Monitor IB switches, login nodes, monitoring nodes |

### 2.2 Typical Applications

```
┌─────────────────────────────────────────────────────────────┐
│                  HPC Cluster Network Topology               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   Login Node                                                │
│        │                                                    │
│   ┌────┴──────┐                                            │
│   │ Monitoring │ (NetMon)                                    │
│   └────┬──────┘                                            │
│        │                                                     │
│   ┌────┴──────────────────────────────────────┐            │
│   │         Management Network (192.168.1.0/16) │           │
│   │ 192.168.1.1 - 192.168.1.254               │            │
│   │ 192.168.2.1 - 192.168.2.254               │            │
│   │ ...                                        │            │
│   │ 192.168.254.1 - 192.168.254.254          │            │
│   └─────────────────────────────────────────────┘            │
│                                                             │
│   256 subnets × 254 IPs = 64,512 IP addresses              │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 Monitoring Scale

| Cluster Size | Subnets | IP Range | NetMon Suitability |
|--------------|---------|-----------|---------------------|
| Small Cluster | 1-10 | 2,540 IPs | ✅ Fully Supported |
| Medium Cluster | 10-50 | 12,700 IPs | ✅ Fully Supported |
| Large Cluster | 50-254 | 64,516 IPs | ✅ Fully Supported |
| Ultra-Scale | >254 | >64,516 IPs | ⚠️ Requires batch scanning |

---

## 3. Software Capabilities

### 3.1 Scanning Modes

| Mode | Principle | Use Case |
|------|-----------|----------|
| **Ping** | ICMP probe | Quick host discovery |
| **TCP** | Port connection probe | Service discovery scenarios |
| **Nmap** | ARP/Nmap probe | Most reliable for LAN |

### 3.2 Deployment Modes

```
┌─────────────────────────────────────────────┐
│          NetMon Deployment Modes           │
├─────────────────────────────────────────────┤
│                                             │
│  Mode 1: CLI Terminal Mode                  │
│  ├── Interactive terminal UI               │
│  ├── Real-time scan progress               │
│  └── Ideal for quick troubleshooting       │
│                                             │
│  Mode 2: Single-User Web                   │
│  ├── Web interface                        │
│  ├── REST API                             │
│  └── Ideal for daily monitoring           │
│                                             │
│  Mode 3: Multi-User Web                    │
│  ├── Multiple concurrent users             │
│  ├── User isolation                       │
│  └── Ideal for team operations             │
│                                             │
└─────────────────────────────────────────────┘
```

### 3.3 API Capabilities

| Endpoint | Method | Function |
|----------|--------|-----------|
| `/api/scan` | POST | Trigger scan |
| `/api/scan` | DELETE | Stop scan |
| `/api/results` | GET | Get results |
| `/api/groups` | GET | Get groups |
| `/api/config` | GET/POST | Config management |
| `/api/status` | GET | Status query |

---

## 4. Performance Metrics

### 4.1 Scanning Performance

| Scan Scale | Ping Mode | TCP Mode | Nmap Mode |
|------------|-----------|-----------|-----------|
| 1,000 IPs | ~4 sec | ~2 sec | ~5 sec |
| 5,000 IPs | ~20 sec | ~8 sec | ~25 sec |
| 10,000 IPs | ~40 sec | ~16 sec | ~50 sec |
| 20,000 IPs | ~80 sec | ~32 sec | ~100 sec |

### 4.2 Concurrency Capability

| Mode | Max Concurrent Users | Scan Threads | Notes |
|------|----------------------|---------------|-------|
| Single-User | 1 | 800 | Suitable for daily use |
| Multi-User | 5 | 800 | v2.0 concurrent limit |

### 4.3 Resource Consumption

| Resource | During 20K IP Scan | Idle |
|----------|-------------------|------|
| CPU | 10-30% | <1% |
| Memory | ~10 MB | ~5 MB |
| Bandwidth | <1 Mbps | 0 |

---

## 5. Software Interface

### 5.1 CLI Terminal Interface

```
┌────────────────────────────────────────────────────────────────────────────────┐
│  CONFIGURATION                                                          │
│  [A] Network: 192.168  [B] Subnet: 1-254  [C] IP Range: 1-254          │
│  [D] Refresh: 120s  [E] Subnets/Group: 4  [F] Mode: PING             │
│  [a-h] Settings | [m] Change Mode | [r] Scan | [c] Cancel | [q] Quit│
├────────────────────────────────────────────────────────────────────────────────┤
│  Last Updated: 2026-03-21 10:30:00  |  Groups: 64  |  Last Scan: 45.2s│
│  Status: WAITING [████████████████░░░] Next in 75s                      │
├────────────────────────────────────────────────────────────────────────────────┤
│  SUBNET MONITOR                                                        │
├────────────────────────────────────────────────────────────────────────────────┤
│   G1         G2         G3         G4         G5         G6     ...     │
│  (1-4)      (5-8)      (9-12)     (13-16)    (17-20)    (21-24)       │
│    12         8         15         3         22         0               │
├────────────────────────────────────────────────────────────────────────────────┤
│  >>> Enter group number (1-64) and press Enter                         │
└────────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Web Interface

```
┌─────────────────────────────────────────────────────────────────────────┐
│  🖥️ NetMon Multi-User                                    [Settings] │
├─────────────────────────────────────────────────────────────────────────┤
│  User: a1b2c3d4...  Network: 192.168.1-254  IP: 1-64  Mode: PING    │
│  Last: 10:30:00  Duration: 45.2s           Status: ✓ Ready         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐        │
│  │   G1   │  │   G2   │  │   G3   │  │   G4   │  │   G5   │  ...  │
│  │  12 ip │  │   8 ip │  │  15 ip │  │   3 ip │  │  22 ip │        │
│  │ subnets│  │ subnets│  │ subnets│  │ subnets│  │ subnets│        │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘        │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.3 Detailed Group View

```
┌─────────────────────────────────────────────────────────────────────────┐
│  GROUP 1 DETAIL VIEW                                    [Rescan]   │
├─────────────────────────────────────────────────────────────────────────┤
│  Subnets: 192.168.1.0/24, 192.168.2.0/24, ...                        │
├────────────────────────────────────────────────────────────────────────────────┤
│  192.168.1.0/24 [12]                                                      │
│  001 002 003 004 005 006 007 008 009 010                              │
│  ..│  │  │  │  │  │  │  │  │  │                                                  │
│   │  │  │  │  │  │  │  │  │  └──○ 010                                          │
│   │  │  │  │  │  │  │  │  └──○ 009                                          │
│   │  │  │  │  │  │  │  └──○ 008                                          │
│   │  │  │  │  │  │  └──● 007 ← Active Host (Green)                         │
│   │  │  │  │  │  └──○ 006                                                  │
│   │  │  │  │  └──○ 005                                                  │
│   │  │  │  └──○ 004                                                    │
│   │  │  └──○ 003                                                      │
│   └──○ 002                                                           │
│   ● 001 ← Active Host (Green)                                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Technical Specifications

### 6.1 Supported Network Ranges

| Config | Range |
|--------|-------|
| IP Prefix | Any (e.g., 192.168, 10.0, 172.16) |
| Subnet Range | 1-254 |
| IP Range | 1-254 |

### 6.2 Environment Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| Python | 3.8+ | 3.10+ |
| CPU | 2 cores | 4+ cores |
| Memory | 2 GB | 4 GB |
| Disk | 1 GB | 5 GB |

### 6.3 Supported Operating Systems

- ✅ macOS 12+
- ✅ Linux (Ubuntu 20.04+, Debian 11+)
- ✅ Windows (WSL2)

---

## 7. Quick Start

### 7.1 CLI Mode

```bash
cd /Users/ben/.openclaw/workspace/netmon/core

# Default scan
python3 realtime_subnet_monitor_v2.py

# Scan /26 subnet (64 IPs)
python3 realtime_subnet_monitor_v2.py \
  --ip-prefix 192.168 \
  --start-subnet 1 \
  --end-subnet 254 \
  --scan-ip-start 1 \
  --scan-ip-end 64
```

### 7.2 Web Mode

```bash
# Single-user version
cd /Users/ben/.openclaw/workspace/netmon/web
sudo python3 netmon_web_v2.py

# Multi-user version
cd /Users/ben/.openclaw/workspace/netmon/multi/api
sudo python3 netmon_web_multi_v2.py
```

### 7.3 API Usage

```bash
# Trigger scan
curl -X POST http://localhost/api/scan

# Get results
curl http://localhost/api/results

# Get groups
curl http://localhost/api/groups
```

---

## 8. Version Information

| Version | Date | Description |
|---------|------|-------------|
| v1.x | 2026-03 | Initial release |
| v2.0 | 2026-03-21 | Thread safety fixes |

---

*Document Version: 2.0*
*Updated: 2026-03-21*
*Author: NetMon Team*