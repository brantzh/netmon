#!/bin/bash
# NetMon 多用户版部署脚本
# 用于部署多用户版 NetMon

set -e  # 遇错即停

echo "==========================================="
echo "NetMon 多用户版部署脚本"
echo "==========================================="
echo ""

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "❌ 错误: 请使用 sudo 运行此脚本"
  echo "   例如: sudo $0"
  exit 1
fi

# 配置变量
INSTALL_DIR="/opt/netmon"
REPO_URL="https://github.com/brantzh/netmon.git"
BACK_UP_DIR="/tmp/netmon-multi-backup-$(date +%Y%m%d_%H%M%S)"

echo "📁 安装目录: $INSTALL_DIR"
echo "📦 备份目录: $BACK_UP_DIR"
echo ""

# 停止现有服务
echo "🛑 停止现有 NetMon 服务..."
systemctl stop netmon-multi 2>/dev/null || echo "多用户服务未运行"

echo ""
echo "💾 备份当前配置..."
mkdir -p $BACK_UP_DIR
cp -r $INSTALL_DIR/.env $BACK_UP_DIR/ 2>/dev/null || echo "没有 .env 文件需要备份"
cp /etc/systemd/system/netmon-multi.service $BACK_UP_DIR/ 2>/dev/null || echo "没有多用户服务文件需要备份"
echo "✅ 配置已备份到: $BACK_UP_DIR"

echo ""
echo "🔍 检查基础目录结构..."
if [ ! -d "$INSTALL_DIR/core" ] || [ ! -d "$INSTALL_DIR/multi/api" ]; then
  echo "📦 检测到基础文件缺失，下载最新代码..."
  cd /tmp
  rm -rf netmon-install-multi
  git clone $REPO_URL netmon-install-multi
  cd netmon-install-multi
  
  # 创建目录结构
  mkdir -p $INSTALL_DIR/{core,single,multi/api}
  
  # 复制所需文件 (v2.0)
  cp core/realtime_subnet_monitor_v2.py $INSTALL_DIR/core/realtime_subnet_monitor.py
  cp multi/api/netmon_web_multi_v2.py $INSTALL_DIR/multi/api/netmon_web_multi.py
  
  # 修复多用户版模块路径
  TEMP_MULTI=$(mktemp)
  cp $INSTALL_DIR/multi/api/netmon_web_multi.py $TEMP_MULTI
  sed -i '1i\
import sys, os\
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "core"))\
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))\
' $TEMP_MULTI
  cp $TEMP_MULTI $INSTALL_DIR/multi/api/netmon_web_multi.py
  chown www-data:www-data $INSTALL_DIR/multi/api/netmon_web_multi.py
  chmod 644 $INSTALL_DIR/multi/api/netmon_web_multi.py
  rm $TEMP_MULTI
  
  echo "✅ 基础文件已下载并修复模块路径"
else
  echo "✅ 基础目录结构已存在"
fi

echo ""
echo "🔒 确保文件权限正确..."
chown -R www-data:www-data $INSTALL_DIR/
chmod -R 644 $INSTALL_DIR/
chmod +x $INSTALL_DIR/multi/api/netmon_web_multi.py

echo ""
echo "⚙️ 检查配置文件..."
if [ ! -f "$INSTALL_DIR/.env" ]; then
  echo "🔧 创建默认配置文件..."
  cat > $INSTALL_DIR/.env << 'EOF'
NETMON_IP_PREFIX=192.168
NETMON_START_SUBNET=1
NETMON_END_SUBNET=254
NETMON_SCAN_IP_START=1
NETMON_SCAN_IP_END=254
NETMON_SCAN_MODE=ping
NETMON_TCP_PORT=22
NETMON_WEB_PORT=80
NETMON_MULTI_WEB_PORT=80
NETMON_REFRESH_INTERVAL=120
NETMON_API_KEY=netmon-api-key
NETMON_SUBNETS_PER_GROUP=4
NETMON_RETRY_COUNT=2
NETMON_PROGRESS_REFRESH_RATE=1.0
NETMON_DISPLAY_REFRESH_RATE=5.0
EOF
  chown www-data:www-data $INSTALL_DIR/.env
  chmod 644 $INSTALL_DIR/.env
  echo "✅ 默认配置文件已创建"
else
  echo "✅ 配置文件已存在"
fi

echo ""
echo "🔧 创建多用户版服务配置..."
cat > /tmp/netmon-multi.service << 'EOF'
[Unit]
Description=NetMon Multi-User Web API
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/netmon
Environment="PATH=/opt/netmon/venv/bin:/usr/bin"
EnvironmentFile=/opt/netmon/.env
ExecStart=/opt/netmon/venv/bin/python /opt/netmon/multi/api/netmon_web_multi.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cp /tmp/netmon-multi.service /etc/systemd/system/netmon-multi.service
echo "✅ 多用户版服务配置已创建"

echo ""
echo "🔄 重新加载 systemd 配置..."
systemctl daemon-reload

echo ""
echo "🔄 启动 NetMon 多用户版服务..."
systemctl enable netmon-multi
systemctl start netmon-multi

echo ""
echo "✅ 等待服务启动..."
sleep 5

echo ""
echo "🔍 检查服务状态..."
if systemctl is-active --quiet netmon-multi; then
  echo "🎉 NetMon 多用户版服务启动成功！"
  echo ""
  echo "📊 服务状态:"
  systemctl status netmon-multi --no-pager -l | head -10
  echo ""
  echo "🌐 访问地址:"
  echo "   多用户版: http://localhost:80"
  echo ""
else
  echo "❌ NetMon 多用户版服务启动失败"
  systemctl status netmon-multi --no-pager -l
  exit 1
fi

echo ""
echo "📋 部署完成信息:"
echo "   安装目录: $INSTALL_DIR"
echo "   多用户版: http://localhost:80"
echo "   服务管理: sudo systemctl [start|stop|restart|status] netmon-multi"
echo ""
echo "💡 注意: 多用户版支持多个用户同时访问，每个用户独立会话"

echo ""
echo "==========================================="
echo "✅ NetMon 多用户版部署完成！"
echo "==========================================="
echo ""
echo "如需验证功能，请访问 http://localhost:80"