#!/bin/bash
# NetMon - 精简部署脚本
# 仅包含必要的部署功能

set -e  # 出错即退出

echo "=== NetMon 精简部署脚本 ==="
echo ""

# 检查是否以 root 权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请以 root 权限运行此脚本 (sudo)"
  exit 1
fi

# 配置
INSTALL_DIR="/opt/netmon"
SERVICE_NAME="netmon"
USER="www-data"

echo "安装目录: $INSTALL_DIR"
echo "服务名称: $SERVICE_NAME"
echo ""

# 创建安装目录
echo "1. 创建安装目录..."
mkdir -p $INSTALL_DIR
chown $USER:$USER $INSTALL_DIR

# 复制应用文件 (v2.0)
echo "2. 复制应用文件..."
mkdir -p $INSTALL_DIR/core $INSTALL_DIR/single $INSTALL_DIR/multi/api
cp core/realtime_subnet_monitor_v2.py $INSTALL_DIR/core/realtime_subnet_monitor.py
cp web/netmon_web_v2.py $INSTALL_DIR/single/netmon_web.py
cp multi/api/netmon_web_multi_v2.py $INSTALL_DIR/multi/api/netmon_web_multi.py
chown -R $USER:$USER $INSTALL_DIR

# 创建虚拟环境
echo "3. 创建 Python 虚拟环境..."
cd $INSTALL_DIR
python3 -m venv venv
sudo -u $USER $INSTALL_DIR/venv/bin/pip install -r requirements.txt

# 创建示例配置文件（如果不存在）
if [ ! -f "$INSTALL_DIR/.env" ]; then
  echo "4. 创建配置文件..."
  cp .env.example $INSTALL_DIR/.env
  chown $USER:$USER $INSTALL_DIR/.env
fi

# 安装 systemd 服务
echo "5. 安装 systemd 服务..."
cp netmon.service /etc/systemd/system/$SERVICE_NAME.service
# 更新服务文件中的路径
sed -i "s|/opt/netmon|$INSTALL_DIR|g" /etc/systemd/system/$SERVICE_NAME.service

# 重载 systemd 配置
systemctl daemon-reload

# 启用并启动服务
echo "6. 启动服务..."
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

# 等待服务启动
sleep 3

# 检查服务状态
if systemctl is-active --quiet $SERVICE_NAME; then
  echo "✅ NetMon 服务启动成功！"
  echo ""
  echo "访问地址："
  echo "- 单用户版: http://localhost:5000"
  echo "- 多用户版: http://localhost:80"
  echo ""
  echo "服务管理命令："
  echo "- 查看状态: sudo systemctl status $SERVICE_NAME"
  echo "- 重启服务: sudo systemctl restart $SERVICE_NAME"
  echo "- 停止服务: sudo systemctl stop $SERVICE_NAME"
  echo ""
else
  echo "❌ NetMon 服务启动失败"
  systemctl status $SERVICE_NAME
  exit 1
fi

echo "=== 部署完成 ==="