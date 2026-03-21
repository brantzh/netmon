# NetMon - HPC/GPU 集群 IP 网络监控工具

专为大规模 HPC/GPU 集群设计的高级网络监控解决方案，支持每台机器多个网卡。支持单用户和多用户并发架构，提供多种扫描模式。

---

## 🌟 核心特性

### 多用户并发支持
- 每个用户独立会话
- 独立配置和扫描结果
- 支持不同网段并发扫描
- 非常适合多管理员环境

### 多种扫描模式
- **PING 模式**: 快速异步 ping 扫描 (针对大型网络优化)
- **TCP 模式**: 单端口扫描 (可选端口)
- **NMAP 模式**: 高级扫描 (如可用)

### Web 界面
- 实时仪表板显示网络活动
- 分组和详细视图
- REST API 集成

### 三种部署模式
- **CLI 模式**: 交互式终端界面
- **单用户 Web**: Web 监控
- **多用户 Web**: 团队运维，用户隔离

---

## 🚀 快速开始

### CLI 模式

```bash
cd core
python3 realtime_subnet_monitor_v2.py --mode ping
```

### Web 模式

```bash
# 单用户版
cd web
sudo python3 netmon_web_v2.py

# 多用户版
cd multi/api
sudo python3 netmon_web_multi_v2.py
```

### Docker 部署

```bash
cd deploy
docker-compose up -d
```

---

## 📊 性能指标

| 扫描规模 | PING 模式 | TCP 模式 | NMAP 模式 |
|----------|-----------|----------|-----------|
| 1,000 IP  | ~4 秒    | ~2 秒   | ~5 秒    |
| 5,000 IP  | ~20 秒   | ~8 秒   | ~25 秒   |
| 10,000 IP | ~40 秒   | ~16 秒  | ~50 秒   |
| 20,000 IP | ~80 秒   | ~32 秒  | ~100 秒  |

### 资源消耗

| 资源 | 20K IP 扫描时 | 空闲时 |
|------|--------------|--------|
| CPU  | 10-30%       | <1%   |
| 内存 | ~10 MB       | ~5 MB  |

---

## 🔧 配置

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `NETMON_IP_PREFIX` | 192.168 | 网络前缀 |
| `NETMON_START_SUBNET` | 1 | 起始子网 |
| `NETMON_END_SUBNET` | 254 | 结束子网 |
| `NETMON_SCAN_IP_START` | 1 | IP 起始 |
| `NETMON_SCAN_IP_END` | 254 | IP 结束 |
| `NETMON_SCAN_MODE` | ping | 扫描模式 |
| `NETMON_TCP_PORT` | 22 | TCP 端口 |
| `NETMON_WEB_PORT` | 80 | Web 端口 |
| `NETMON_API_KEY` | - | API 密钥 |

---

## 🖥️ API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/scan` | POST | 触发扫描 |
| `/api/scan` | DELETE | 停止扫描 |
| `/api/results` | GET | 获取结果 |
| `/api/groups` | GET | 获取分组 |
| `/api/config` | GET/POST | 配置管理 |
| `/api/status` | GET | 状态查询 |

---

## 📁 项目结构

```
netmon/
├── core/                      # 核心扫描引擎
│   ├── realtime_subnet_monitor.py
│   └── realtime_subnet_monitor_v2.py
├── web/                       # 单用户 Web
│   ├── netmon_web.py
│   └── netmon_web_v2.py
├── multi/
│   └── api/                   # 多用户 Web
│       ├── netmon_web_multi.py
│       └── netmon_web_multi_v2.py
├── deploy/                    # 部署脚本
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── install-*.sh
│   └── netmon.service
└── docs/                      # 文档
    ├── 01-Environment_Prep.md
    ├── 02-Deployment.md
    └── 03-Software_Introduction.md
```

---

## 🛠️ 环境要求

| 资源 | 最低要求 | 推荐 |
|------|----------|------|
| Python | 3.8+ | 3.10+ |
| CPU | 2 核 | 4+ 核 |
| 内存 | 2 GB | 4 GB |

### 支持的系统
- ✅ macOS 12+
- ✅ Linux (Ubuntu 20.04+, Debian 11+)
- ✅ Windows (WSL2)

---

## 📄 许可证

MIT License - 详见 LICENSE 文件。

---

## 👥 作者

NetMon Team

---

*详细文档见 `docs/` 文件夹。*