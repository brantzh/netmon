FROM python:3.9-slim

LABEL maintainer="NetMon Team"
LABEL description="Network monitoring tool with single and multi-user support"

# 安装系统依赖
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# 设置工作目录
WORKDIR /app

# 克隆最新代码
RUN git clone https://github.com/brantzh/netmon.git ./

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 设置目录结构
RUN mkdir -p core single multi/api

# 复制应用文件 (v2.0)
RUN cp -r core/realtime_subnet_monitor_v2.py core/realtime_subnet_monitor.py && \
    cp -r web/netmon_web_v2.py single/netmon_web.py && \
    cp -r multi/api/netmon_web_multi_v2.py multi/api/netmon_web_multi.py

# 修复模块导入路径
RUN sed -i '1s/^/import sys, os\nsys.path.insert(0, "\.\/core")\nsys.path.insert(0, "\.\/single")\n/' single/netmon_web.py && \
    sed -i '1s/^/import sys, os\nsys.path.insert(0, "\.\/core")\nsys.path.insert(0, "\.\/multi\/api")\n/' multi/api/netmon_web_multi.py

# 创建非 root 用户
RUN useradd -m -u 1000 netmon

# 更改所有权
RUN chown -R netmon:netmon /app
USER netmon

# 暴露端口
EXPOSE 5000 80

# 默认运行多用户版在 80 端口
ENV NETMON_WEB_PORT=80
CMD ["python", "multi/api/netmon_web_multi.py"]