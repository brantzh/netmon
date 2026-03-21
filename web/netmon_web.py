#!/usr/bin/env python3
"""
NetMon Web API v2.0 - Flask-based REST API for NetMon
Designed to run behind Apache/Nginx as a WSGI application

Changes from v1.x:
  - Fixed race condition in api_scan() (added scan_lock)
  - Fixed thread safety for last_results and scan_in_progress
  - Fixed config update to stop ongoing scan first
  - Added thread-safe access to monitor
"""

import os
import sys
import json
import time
import threading
import logging
from datetime import datetime
from flask import Flask, jsonify, request, render_template_string, send_from_directory
from functools import wraps

# Import the monitor class
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from realtime_subnet_monitor import RealtimeSubnetMonitor

# ==================== Configuration ====================

app = Flask(__name__, 
            static_folder='web/static',
            template_folder='web/templates')

# Global monitor instance
monitor = None
monitor_lock = threading.Lock()
scan_lock = threading.Lock()  # Lock for scan state to prevent race conditions
scan_in_progress = False
last_results = {}
last_scan_time = None
last_scan_duration = None

# Configuration
CONFIG = {
    'ip_prefix': os.getenv('NETMON_IP_PREFIX', '192.168'),
    'start_subnet': int(os.getenv('NETMON_START_SUBNET', '1')),
    'end_subnet': int(os.getenv('NETMON_END_SUBNET', '254')),
    'scan_ip_start': int(os.getenv('NETMON_SCAN_IP_START', '1')),
    'scan_ip_end': int(os.getenv('NETMON_SCAN_IP_END', '254')),
    'scan_mode': os.getenv('NETMON_SCAN_MODE', 'ping'),
    'tcp_port': int(os.getenv('NETMON_TCP_PORT', '22')),
    'refresh_interval': int(os.getenv('NETMON_REFRESH_INTERVAL', '120')),
    'retry_count': int(os.getenv('NETMON_RETRY_COUNT', '2')),
    'subnets_per_group': int(os.getenv('NETMON_SUBNETS_PER_GROUP', '4')),
}

# Common TCP ports for quick selection
COMMON_TCP_PORTS = [
    (21, 'FTP'), (22, 'SSH'), (23, 'Telnet'), (25, 'SMTP'),
    (53, 'DNS'), (80, 'HTTP'), (110, 'POP3'), (143, 'IMAP'),
    (443, 'HTTPS'), (445, 'SMB'), (993, 'IMAPS'), (995, 'POP3S'),
    (3306, 'MySQL'), (3389, 'RDP'), (5432, 'PostgreSQL'), (6379, 'Redis'),
    (8080, 'HTTP-Alt'), (8443, 'HTTPS-Alt'), (9000, 'App'), (27017, 'MongoDB')
]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== Helper Functions ====================

def require_api_key(f):
    """Optional API key authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = os.getenv('NETMON_API_KEY')
        if api_key:
            provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            if provided_key != api_key:
                return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def init_monitor():
    """Initialize the monitor instance"""
    global monitor
    with monitor_lock:
        try:
            monitor = RealtimeSubnetMonitor(
                ip_prefix=CONFIG['ip_prefix'],
                start_subnet=CONFIG['start_subnet'],
                end_subnet=CONFIG['end_subnet'],
                scan_ip_start=CONFIG['scan_ip_start'],
                scan_ip_end=CONFIG['scan_ip_end'],
                scan_mode=CONFIG['scan_mode'],
                tcp_port=CONFIG['tcp_port'],
                refresh_interval=CONFIG['refresh_interval'],
                retry_count=CONFIG['retry_count'],
                subnets_per_group=CONFIG['subnets_per_group'],
                display_refresh_rate=5.0
            )
            logger.info(f"Monitor initialized: {CONFIG['ip_prefix']}.{CONFIG['start_subnet']}-{CONFIG['end_subnet']}")
        except Exception as e:
            logger.error(f"Failed to initialize monitor: {e}")
            raise

def run_scan_background():
    """Run scan in background thread (thread-safe)"""
    global scan_in_progress, last_results, last_scan_time, last_scan_duration, monitor
    
    start_time = time.time()
    scan_results = {}
    
    try:
        # Acquire monitor lock for scanning
        with monitor_lock:
            if not monitor:
                logger.error("Monitor not initialized")
                return
            monitor.scan_all_subnets()
            
            # Collect results while holding monitor lock
            scan_results = {
                'subnets': monitor.results.copy(),
                'active_hosts': monitor.active_hosts.copy(),
                'groups': {}
            }
            
            # Build group summaries
            for group_idx, group in monitor.subnet_groups.items():
                group_data = []
                for subnet in group['subnets']:
                    hosts = monitor.results.get(subnet, [])
                    group_data.append({
                        'subnet': subnet,
                        'hosts': hosts,
                        'count': len(hosts)
                    })
                scan_results['groups'][group_idx] = {
                    'name': group['name'],
                    'subnets': group_data,
                    'total': sum(g['count'] for g in group_data)
                }
            
            last_scan_duration = time.time() - start_time
            logger.info(f"Scan completed: {len(monitor.active_hosts)} hosts in {last_scan_duration:.2f}s")
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
    finally:
        # Update results with scan lock
        with scan_lock:
            last_results = scan_results
            scan_in_progress = False
            last_scan_time = datetime.now()

# ==================== Routes ====================

@app.route('/')
def index():
    """Serve the main web interface"""
    return render_template_string(HTML_TEMPLATE, config=CONFIG, common_ports=COMMON_TCP_PORTS)

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory(app.static_folder, filename)

@app.route('/api/status')
@require_api_key
def api_status():
    """Get current status (thread-safe)"""
    # Get progress information from the monitor if available
    progress_info = {}
    with monitor_lock:
        if monitor and hasattr(monitor, 'scan_progress'):
            progress_info = {
                'scan_progress': monitor.scan_progress,
                'scan_current': monitor.scan_current,
                'scan_total': monitor.scan_total,
                'is_scanning': monitor.is_scanning
            }
    
    # Read scan state under lock
    with scan_lock:
        current_scan_in_progress = scan_in_progress
        current_last_scan_time = last_scan_time
        current_last_scan_duration = last_scan_duration
    
    return jsonify({
        'status': 'running',
        'scan_in_progress': current_scan_in_progress,
        'last_scan_time': current_last_scan_time.isoformat() if current_last_scan_time else None,
        'last_scan_duration': current_last_scan_duration,
        'config': CONFIG,
        'timestamp': datetime.now().isoformat(),
        **progress_info
    })

@app.route('/api/scan')
@require_api_key
def api_scan_get():
    """Get scan status (GET)"""
    # Get progress information from the monitor if available
    progress_info = {}
    with monitor_lock:
        if monitor and hasattr(monitor, 'scan_progress'):
            progress_info = {
                'scan_progress': monitor.scan_progress,
                'scan_current': monitor.scan_current,
                'scan_total': monitor.scan_total,
                'is_scanning': monitor.is_scanning
            }
    
    # Read scan state under lock
    with scan_lock:
        current_scan_in_progress = scan_in_progress
        current_last_scan_duration = last_scan_duration
    
    return jsonify({
        'scan_in_progress': current_scan_in_progress,
        'last_scan_duration': current_last_scan_duration,
        **progress_info
    })

@app.route('/api/scan', methods=['POST'])
@require_api_key
def api_scan():
    """Trigger a new scan"""
    global scan_in_progress
    
    # Use lock to prevent race condition
    with scan_lock:
        if scan_in_progress:
            return jsonify({'error': 'Scan already in progress'}), 409
        scan_in_progress = True
    
    thread = threading.Thread(target=run_scan_background)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'started', 'message': 'Scan initiated'})

@app.route('/api/scan', methods=['DELETE'])
@require_api_key
def api_stop_scan():
    """Stop current scan"""
    global scan_in_progress, monitor
    
    with scan_lock:
        if not scan_in_progress:
            return jsonify({'status': 'idle', 'message': 'No scan in progress'}), 200
        
        scan_in_progress = False
    
    with monitor_lock:
        if monitor:
            monitor.running = False
            monitor.is_scanning = False
    
    logger.info("Scan stopped by user")
    return jsonify({'status': 'stopped', 'message': 'Scan terminated'})

@app.route('/api/scan/group/<int:group_id>', methods=['POST'])
@require_api_key
def api_scan_group(group_id):
    """Trigger scan for a specific group only"""
    global scan_in_progress
    
    with monitor_lock:
        if not monitor:
            return jsonify({'error': 'Monitor not initialized'}), 500
        
        if group_id < 0 or group_id >= len(monitor.subnet_groups):
            return jsonify({'error': f'Invalid group ID: {group_id}'}), 400
    
    # Use lock to prevent race condition
    with scan_lock:
        if scan_in_progress:
            return jsonify({'error': 'Scan already in progress'}), 409
        scan_in_progress = True
    
    def scan_single_group():
        global scan_in_progress, last_results, last_scan_time
        try:
            with monitor_lock:
                group = monitor.subnet_groups[group_id]
                logger.info(f"Starting scan for group {group_id}: {group['name']}")
                monitor.scan_group(group_id)
                logger.info(f"Group {group_id} scan completed")
                
                # Update results after scan
                with scan_lock:
                    last_results = {
                        'subnets': monitor.results.copy(),
                        'active_hosts': monitor.active_hosts.copy(),
                        'groups': {}
                    }
        except Exception as e:
            logger.error(f"Group {group_id} scan failed: {e}")
        finally:
            with scan_lock:
                scan_in_progress = False
                last_scan_time = datetime.now()
    
    thread = threading.Thread(target=scan_single_group)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'status': 'started',
        'message': f'Scanning group {group_id}',
        'group_id': group_id
    })

@app.route('/api/results')
@require_api_key
def api_results():
    """Get latest scan results (thread-safe)"""
    # Get progress information from the monitor if available
    progress_info = {}
    with monitor_lock:
        if monitor and hasattr(monitor, 'scan_progress'):
            progress_info = {
                'scan_progress': monitor.scan_progress,
                'scan_current': monitor.scan_current,
                'scan_total': monitor.scan_total,
                'is_scanning': monitor.is_scanning
            }
    
    # Read scan state and results under lock
    with scan_lock:
        current_scan_in_progress = scan_in_progress
        current_last_scan_time = last_scan_time
        current_last_scan_duration = last_scan_duration
        current_last_results = last_results.copy()
    
    return jsonify({
        'scan_in_progress': current_scan_in_progress,
        'last_scan_time': current_last_scan_time.isoformat() if current_last_scan_time else None,
        'last_scan_duration': current_last_scan_duration,
        'groups': current_last_results.get('groups', {}),
        'total_hosts': len(current_last_results.get('active_hosts', [])),
        **progress_info
    })

@app.route('/api/groups')
@require_api_key
def api_groups():
    """Get group list"""
    if monitor:
        groups = []
        for idx, group in monitor.subnet_groups.items():
            total = sum(len(monitor.results.get(s, [])) for s in group['subnets'])
            groups.append({
                'id': idx,
                'name': group['name'],
                'subnets': group['subnets'],
                'subnet_range': f"{group['subnets'][0].split('.')[2]}-{group['subnets'][-1].split('.')[2]}" if group['subnets'] else '',
                'total_hosts': total
            })
        return jsonify({'groups': groups})
    return jsonify({'groups': []})

@app.route('/api/group/<int:group_id>')
@require_api_key
def api_group_detail(group_id):
    """Get detailed results for a specific group"""
    if not monitor or group_id not in monitor.subnet_groups:
        return jsonify({'error': 'Group not found'}), 404
    
    group = monitor.subnet_groups[group_id]
    subnets = []
    
    for subnet in group['subnets']:
        hosts = monitor.results.get(subnet, [])
        # Build IP grid data
        ip_data = []
        for i in range(monitor.scan_ip_start, monitor.scan_ip_end + 1):
            ip = f"{subnet.split('/')[0].rsplit('.', 1)[0]}.{i}"
            ip_data.append({
                'ip': i,
                'active': ip in hosts
            })
        
        subnets.append({
            'subnet': subnet,
            'hosts': hosts,
            'count': len(hosts),
            'ip_grid': ip_data
        })
    
    return jsonify({
        'group': {
            'id': group_id,
            'name': group['name'],
            'subnets': subnets,
            'total': sum(s['count'] for s in subnets)
        }
    })

@app.route('/api/config', methods=['GET', 'POST'])
@require_api_key
def api_config():
    """Get or update configuration"""
    global CONFIG, monitor
    
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        # Stop any ongoing scan first to prevent conflicts
        with scan_lock:
            if scan_in_progress:
                scan_in_progress = False
                logger.info("Stopped ongoing scan due to config update")
        
        with monitor_lock:
            if monitor:
                monitor.running = False
                monitor.is_scanning = False
        
        # Update config
        for key in ['ip_prefix', 'scan_mode', 'tcp_port', 'refresh_interval', 'retry_count']:
            if key in data:
                CONFIG[key] = data[key]
        
        for key in ['start_subnet', 'end_subnet', 'scan_ip_start', 'scan_ip_end', 'subnets_per_group']:
            if key in data:
                CONFIG[key] = int(data[key])
        
        # Stop any ongoing scan first to prevent conflicts
        with scan_lock:
            if scan_in_progress:
                scan_in_progress = False
                logger.info("Stopped ongoing scan due to config update")
        
        with monitor_lock:
            if monitor:
                monitor.running = False
                monitor.is_scanning = False
        
        # Reinitialize monitor with new config
        init_monitor()
        
        logger.info(f"Configuration updated: {CONFIG}")
        return jsonify({'status': 'updated', 'config': CONFIG})
    
    return jsonify(CONFIG)

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

# ==================== HTML Template ====================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetMon - Cluster Network Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%);
            padding: 20px 30px;
            border-bottom: 1px solid #0f3460;
        }
        .header h1 { color: #00d9ff; font-size: 24px; }
        .header .subtitle { color: #888; font-size: 14px; margin-top: 5px; }
        .settings-panel {
            background: #16213e;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #0f3460;
        }
        .settings-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .form-group {
            display: flex;
            flex-direction: column;
        }
        .form-group label {
            color: #888;
            font-size: 12px;
            margin-bottom: 5px;
        }
        .form-group input, .form-group select {
            background: #1a1a2e;
            border: 1px solid #0f3460;
            color: #eee;
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 14px;
        }
        .form-group input:focus, .form-group select:focus {
            outline: none;
            border-color: #00d9ff;
        }
        .btn-save {
            background: #00ff88;
            color: #1a1a2e;
            margin-top: 15px;
        }
        .btn-save:hover { background: #00cc6a; }
        .status-bar .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.2s;
        }
        .btn-settings {
            background: #0f3460;
            color: #eee;
        }
        .btn-settings:hover { background: #00d9ff; color: #1a1a2e; }
        .btn-scan {
            background: #00d9ff;
            color: #1a1a2e;
        }
        .btn-scan:hover { background: #00b8d4; }
        .btn-stop {
            background: #ff4757;
            color: #fff;
        }
        .btn-stop:hover { background: #ff6b7a; }
        .hidden { display: none; }
        #tcp-port-group { display: flex; flex-direction: column; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .status-bar {
            display: flex;
            gap: 20px;
            padding: 15px 20px;
            background: #16213e;
            border-radius: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .status-item { display: flex; flex-direction: column; }
        .status-label { color: #888; font-size: 12px; }
        .status-value { color: #00d9ff; font-size: 18px; font-weight: bold; }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .btn-primary { background: #00d9ff; color: #1a1a2e; }
        .btn-primary:hover { background: #00b8d9; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 15px;
        }
        .card {
            background: #16213e;
            border-radius: 8px;
            padding: 20px;
            border: 1px solid #0f3460;
            transition: transform 0.2s, border-color 0.2s;
            cursor: pointer;
        }
        .card:hover {
            transform: translateY(-2px);
            border-color: #00d9ff;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .card-title { color: #00d9ff; font-size: 18px; font-weight: bold; }
        .card-count { 
            background: #00d9ff; 
            color: #1a1a2e; 
            padding: 4px 12px; 
            border-radius: 12px; 
            font-weight: bold;
        }
        .card-subnets { color: #888; font-size: 13px; margin-bottom: 10px; }
        .progress-bar {
            height: 6px;
            background: #0f3460;
            border-radius: 3px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            transition: width 0.3s;
        }
        .loading {
            text-align: center;
            padding: 60px 20px;
            color: #888;
        }
        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid #0f3460;
            border-top-color: #00d9ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        .scan-status { 
            padding: 10px 20px; 
            border-radius: 6px; 
            margin-bottom: 20px;
        }
        .scan-status.scanning { background: #00d9ff33; color: #00d9ff; }
        .scan-status.idle { background: #00ff8833; color: #00ff88; }
        .status-content {
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .progress-container {
            flex-grow: 1;
            margin-left: 15px;
            height: 8px;
            background: rgba(255,255,255,0.2);
            border-radius: 4px;
            overflow: hidden;
        }
        .progress-bar {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, #00d9ff, #00ff88);
            transition: width 0.3s ease;
            border-radius: 4px;
        }
        .hidden {
            display: none;
        }
        .detail-view { 
            background: #16213e; 
            border-radius: 8px; 
            padding: 20px;
            margin-top: 20px;
        }
        .detail-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #0f3460;
        }
        .subnet-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        .subnet-box {
            background: #1a1a2e;
            border-radius: 6px;
            padding: 15px;
            border: 1px solid #0f3460;
        }
        .subnet-title {
            color: #00d9ff;
            font-size: 14px;
            margin-bottom: 10px;
        }
        .ip-grid {
            display: grid;
            grid-template-columns: repeat(10, 1fr);
            gap: 4px;
        }
        .ip-cell {
            text-align: center;
            padding: 4px;
            font-size: 11px;
            border-radius: 3px;
            background: #0f3460;
            color: #666;
        }
        .ip-cell.active {
            background: #00ff88;
            color: #1a1a2e;
            font-weight: bold;
        }
        .back-btn {
            background: #0f3460;
            color: #eee;
        }
        .back-btn:hover { background: #16213e; }
        .rescan-btn {
            background: #00d9ff;
            color: #1a1a2e;
            font-weight: 500;
            padding: 8px 16px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.2s;
        }
        .rescan-btn:hover { background: #00b8d4; }
        .rescan-btn:disabled {
            background: #666;
            cursor: not-allowed;
        }
            cursor: not-allowed;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🖥️ NetMon</h1>
        <div class="subtitle">Large-Scale HPC/GPU Cluster Network Monitor</div>
    </div>
    
    <div class="container">
        <div class="status-bar">
            <span>Network: <strong>{{ config.ip_prefix }}.{{ config.start_subnet }}-{{ config.end_subnet }}</strong></span>
            <span>IP: <strong>{{ config.scan_ip_start }}-{{ config.scan_ip_end }}</strong></span>
            <span>Mode: <strong>{{ config.scan_mode.upper() }}{% if config.scan_mode == 'tcp' %}:{{ config.tcp_port }}{% endif %}</strong></span>
            <span>Last: <strong id="last-scan-time">--</strong></span>
            <span>Duration: <strong id="scan-duration">--</strong></span>
            <button class="btn btn-settings" onclick="toggleSettings()">⚙️ Settings</button>
            <button class="btn btn-scan" id="scan-btn" onclick="toggleScan()">🔄 Scan</button>
        </div>
        
        <div id="settings-panel" class="settings-panel hidden">
            <h3 style="color: #00d9ff; margin-bottom: 15px;">⚙️ Configuration</h3>
            <div class="settings-grid">
                <div class="form-group">
                    <label>Network Prefix</label>
                    <input type="text" id="cfg-ip-prefix" value="{{ config.ip_prefix }}">
                </div>
                <div class="form-group">
                    <label>Start Subnet</label>
                    <input type="number" id="cfg-start-subnet" value="{{ config.start_subnet }}">
                </div>
                <div class="form-group">
                    <label>End Subnet</label>
                    <input type="number" id="cfg-end-subnet" value="{{ config.end_subnet }}">
                </div>
                <div class="form-group">
                    <label>Subnets per Group</label>
                    <input type="number" id="cfg-subnets-per-group" value="{{ config.subnets_per_group }}" min="1" max="12">
                </div>
                <div class="form-group">
                    <label>IP Start</label>
                    <input type="number" id="cfg-ip-start" value="{{ config.scan_ip_start }}">
                </div>
                <div class="form-group">
                    <label>IP End</label>
                    <input type="number" id="cfg-ip-end" value="{{ config.scan_ip_end }}">
                </div>
                <div class="form-group">
                    <label>Scan Mode</label>
                    <select id="cfg-mode" onchange="togglePortInput()">
                        <option value="ping" {{ 'selected' if config.scan_mode == 'ping' }}>PING</option>
                        <option value="tcp" {{ 'selected' if config.scan_mode == 'tcp' }}>TCP</option>
                        <option value="nmap" {{ 'selected' if config.scan_mode == 'nmap' }}>NMAP</option>
                    </select>
                </div>
                <div class="form-group" id="tcp-port-group">
                    <label>TCP Port</label>
                    <select id="cfg-tcp-port-select" onchange="document.getElementById('cfg-tcp-port').value=this.value">
                        <option value="">Custom...</option>
                        {% for port, name in common_ports %}
                        <option value="{{ port }}" {{ 'selected' if config.tcp_port == port }}>{{ port }} ({{ name }})</option>
                        {% endfor %}
                    </select>
                    <input type="number" id="cfg-tcp-port" value="{{ config.tcp_port }}" style="margin-top:5px;">
                </div>
                <div class="form-group">
                    <label>Retry Count</label>
                    <input type="number" id="cfg-retry" value="{{ config.retry_count }}" min="0" max="5">
                </div>
                <div class="form-group">
                    <label>Refresh Interval (s)</label>
                    <input type="number" id="cfg-refresh" value="{{ config.refresh_interval }}" min="30" step="30">
                </div>
            </div>
            <button class="btn btn-save" onclick="saveConfig()">💾 Save & Restart Scan</button>
        </div>
        
        <div id="scan-status" class="scan-status idle">
            <div class="status-content">
                <span id="status-text">✓ Ready</span>
                <div id="progress-container" class="progress-container hidden">
                    <div id="progress-bar" class="progress-bar"></div>
                </div>
            </div>
        </div>
        
        <div id="content">
            <div class="loading">
                <div class="spinner"></div>
                <div>Loading...</div>
            </div>
        </div>
    </div>

    <script>
        let currentView = 'groups';
        let currentGroupId = null;
        let settingsOpen = false;
        
        function toggleSettings() {
            settingsOpen = !settingsOpen;
            document.getElementById('settings-panel').classList.toggle('hidden');
            if (settingsOpen) {
                loadConfig();
            }
        }
        
        function togglePortInput() {
            const mode = document.getElementById('cfg-mode').value;
            const portGroup = document.getElementById('tcp-port-group');
            if (mode === 'tcp') {
                portGroup.style.display = 'flex';
            } else {
                portGroup.style.display = 'none';
            }
        }
        
        function updateScanDuration(duration) {
            // Debug: Log the value
            console.log('updateScanDuration called with:', duration, typeof duration);
            const element = document.getElementById('scan-duration');
            if (element) {
                if (duration !== undefined && duration !== null && !isNaN(duration)) {
                    element.textContent = duration.toFixed(1) + 's';
                } else {
                    element.textContent = '--';
                }
            }
        }
        
        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const cfg = await res.json();
                document.getElementById('cfg-ip-prefix').value = cfg.ip_prefix;
                document.getElementById('cfg-start-subnet').value = cfg.start_subnet;
                document.getElementById('cfg-end-subnet').value = cfg.end_subnet;
                document.getElementById('cfg-subnets-per-group').value = cfg.subnets_per_group;
                document.getElementById('cfg-ip-start').value = cfg.scan_ip_start;
                document.getElementById('cfg-ip-end').value = cfg.scan_ip_end;
                document.getElementById('cfg-mode').value = cfg.scan_mode;
                document.getElementById('cfg-tcp-port').value = cfg.tcp_port;
                document.getElementById('cfg-retry').value = cfg.retry_count;
                document.getElementById('cfg-refresh').value = cfg.refresh_interval;
                togglePortInput();
            } catch (e) {
                console.error('Config load failed:', e);
            }
        }
        
        async function saveConfig() {
            const btn = document.querySelector('.btn-save');
            const originalText = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Saving...';
            
            try {
                const config = {
                    ip_prefix: document.getElementById('cfg-ip-prefix').value,
                    start_subnet: parseInt(document.getElementById('cfg-start-subnet').value),
                    end_subnet: parseInt(document.getElementById('cfg-end-subnet').value),
                    subnets_per_group: parseInt(document.getElementById('cfg-subnets-per-group').value),
                    scan_ip_start: parseInt(document.getElementById('cfg-ip-start').value),
                    scan_ip_end: parseInt(document.getElementById('cfg-ip-end').value),
                    scan_mode: document.getElementById('cfg-mode').value,
                    tcp_port: parseInt(document.getElementById('cfg-tcp-port').value),
                    retry_count: parseInt(document.getElementById('cfg-retry').value),
                    refresh_interval: parseInt(document.getElementById('cfg-refresh').value)
                };
                
                console.log('Saving config:', config);
                
                const res = await fetch('/api/config', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(config)
                });
                
                const contentType = res.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    const text = await res.text();
                    console.error('Non-JSON response:', text.substring(0, 200));
                    throw new Error('Server returned non-JSON response.');
                }
                
                const data = await res.json();
                
                if (res.ok) {
                    alert('Configuration saved! Starting new scan...');
                    toggleSettings();
                    triggerScan();
                    setTimeout(() => location.reload(), 2000);
                } else {
                    alert('Error: ' + (data.error || 'Failed to save'));
                }
            } catch (e) {
                console.error('Save error:', e);
                alert('Error saving config: ' + e.message);
            } finally {
                btn.disabled = false;
                btn.textContent = originalText;
            }
        }
        
        async function fetchStatus() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                // Update last scan time
                if (data.last_scan_time) {
                    const scanTime = new Date(data.last_scan_time);
                    document.getElementById('last-scan-time').textContent = scanTime.toLocaleTimeString();
                } else {
                    document.getElementById('last-scan-time').textContent = '--';
                }
                
                updateScanDuration(data.last_scan_duration);
                
                // Sync scan state
                scanInProgress = data.scan_in_progress;
                updateScanButton();
                
                const statusEl = document.getElementById('scan-status');
                const statusText = document.getElementById('status-text');
                const progressContainer = document.getElementById('progress-container');
                const progressBar = document.getElementById('progress-bar');
                
                if (data.scan_in_progress) {
                    statusEl.className = 'scan-status scanning';
                    statusText.textContent = '⏳ Scanning...';
                    
                    // Show progress bar if available in data
                    if (data.scan_progress !== undefined) {
                        progressContainer.classList.remove('hidden');
                        progressBar.style.width = data.scan_progress + '%';
                    } else {
                        progressContainer.classList.add('hidden');
                    }
                } else {
                    statusEl.className = 'scan-status idle';
                    statusText.textContent = '✓ Ready';
                    progressContainer.classList.add('hidden');
                    progressBar.style.width = '0%';
                }
            } catch (e) {
                console.error('Status fetch failed:', e);
            }
        }
        
        async function fetchGroups() {
            try {
                console.log('Fetching groups...');
                const res = await fetch('/api/groups');
                console.log('Groups API response status:', res.status);
                
                if (!res.ok) {
                    throw new Error(`API error: ${res.status}`);
                }
                
                const data = await res.json();
                console.log('Groups data received:', data);
                
                if (!data.groups) {
                    document.getElementById('content').innerHTML = `
                        <div class="loading">
                            <div>Error: Invalid response format. No groups data.</div>
                        </div>
                    `;
                    return;
                }
                
                if (data.groups.length === 0) {
                    document.getElementById('content').innerHTML = `
                        <div class="loading">
                            <div>No groups configured. Run a scan first.</div>
                        </div>
                    `;
                    return;
                }
                
                const grid = document.createElement('div');
                grid.className = 'grid';
                
                data.groups.forEach((group, index) => {
                    try {
                        const card = document.createElement('div');
                        card.className = 'card';
                        card.setAttribute('data-group-id', group.id);
                        card.onclick = function() {
                            showGroupDetail(this.getAttribute('data-group-id'));
                        };
                        card.innerHTML = `
                            <div class="card-header">
                                <span class="card-title">${group.name}</span>
                                <span class="card-count">${group.total_hosts || 0} ips</span>
                            </div>
                            <div class="card-subnets">${group.subnet_range || 'N/A'}</div>
                            <div class="card-subnets">${(group.subnets && group.subnets.length) || 0} subnets</div>
                            <div class="progress-bar">
                                <div class="progress-fill" style="width: ${Math.min(100, (group.total_hosts || 0) / 10)}%"></div>
                            </div>
                        `;
                        grid.appendChild(card);
                    } catch (innerErr) {
                        console.error(`Error creating card for group ${index}:`, innerErr);
                    }
                });
                
                document.getElementById('content').innerHTML = '';
                document.getElementById('content').appendChild(grid);
                console.log('Groups displayed successfully');
            } catch (e) {
                console.error('Groups fetch failed:', e);
                document.getElementById('content').innerHTML = `
                    <div class="loading">
                        <div>Error loading groups: ${e.message}</div>
                        <div>Please check browser console for details</div>
                    </div>
                `;
            }
        }
        
        async function showGroupDetail(groupId) {
            currentView = 'detail';
            currentGroupId = groupId;
            
            document.getElementById('content').innerHTML = `
                <div class="loading">
                    <div class="spinner"></div>
                    <div>Loading group details...</div>
                </div>
            `;
            
            try {
                const res = await fetch(`/api/group/${groupId}`);
                const data = await res.json();
                
                const detail = document.createElement('div');
                detail.className = 'detail-view';
                detail.innerHTML = `
                    <div class="detail-header">
                        <h2>${data.group.name} - ${data.group.total} ips</h2>
                        <div>
                            <button class="btn rescan-btn" onclick="rescanGroup(${groupId})">🔄 Rescan (R)</button>
                            <button class="btn back-btn" onclick="showGroups()">← Back</button>
                        </div>
                    </div>
                    <div class="subnet-grid">
                        ${data.group.subnets.map(subnet => `
                            <div class="subnet-box">
                                <div class="subnet-title">${subnet.subnet} (${subnet.count} ips)</div>
                                <div class="ip-grid">
                                    ${subnet.ip_grid.map(ip => `
                                        <div class="ip-cell ${ip.active ? 'active' : ''}">${ip.ip}</div>
                                    `).join('')}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                `;
                
                document.getElementById('content').innerHTML = '';
                document.getElementById('content').appendChild(detail);
                
                // Add keyboard listener with closure to capture groupId
                document.onkeydown = function(e) {
                    if (e.key === 'r' || e.key === 'R') {
                        rescanGroup(groupId);
                    } else if (e.key === 'Escape') {
                        showGroups();
                    }
                };
            } catch (e) {
                console.error('Detail fetch failed:', e);
            }
        }
        
        async function rescanGroup(groupId) {
            const btn = document.querySelector('.rescan-btn');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Scanning...';
            }
            
            // Record start time
            const startTime = Date.now();
            
            try {
                const res = await fetch(`/api/scan/group/${groupId}`, {
                    method: 'POST'
                });
                const data = await res.json();
                
                if (res.ok) {
                    console.log('Group scan started:', data.message);
                    if (btn) btn.textContent = '🔄 Scanning...';
                    
                    // Wait for scan to complete and update with duration
                    setTimeout(async () => {
                        // Update with duration
                        const duration = ((Date.now() - startTime) / 1000).toFixed(1);
                        if (btn) {
                            btn.textContent = `🔄 Rescan (R) - ${duration}s`;
                            
                            // Reset button text after delay
                            setTimeout(() => {
                                btn.textContent = '🔄 Rescan (R)';
                                btn.disabled = false;
                            }, 3000);
                        }
                        
                        // Refresh after delay
                        setTimeout(() => {
                            showGroupDetail(groupId);
                        }, 2000);
                    }, 3000);
                } else {
                    alert('Error: ' + (data.error || 'Failed to start scan'));
                    if (btn) {
                        btn.disabled = false;
                        btn.textContent = '🔄 Rescan (R)';
                    }
                }
            } catch (e) {
                console.error('Rescan error:', e);
                alert('Failed to start group scan');
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '🔄 Rescan (R)';
                }
            }
        }
        
        function showGroups() {
            currentView = 'groups';
            currentGroupId = null;
            fetchGroups();
        }
        
        let scanInProgress = false;

        function updateScanButton() {
            const btn = document.getElementById('scan-btn');
            if (!btn) return;
            
            if (scanInProgress) {
                btn.textContent = '⏹️ Stop';
                btn.classList.add('btn-stop');
            } else {
                btn.textContent = '🔄 Scan';
                btn.classList.remove('btn-stop');
            }
        }
        
        async function triggerScan() {
            try {
                const res = await fetch('/api/scan', { method: 'POST' });
                const data = await res.json();
                
                if (res.ok) {
                    scanInProgress = true;
                    updateScanButton();
                    fetchStatus(); // Refresh status immediately
                    
                    // Poll until scan completes
                    const pollScanStatus = async () => {
                        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 sec
                        const statusRes = await fetch('/api/status');
                        const statusData = await statusRes.json();
                        
                        if (statusData.scan_in_progress) {
                            pollScanStatus(); // Continue polling
                        } else {
                            scanInProgress = false;
                            updateScanButton();
                            fetchStatus(); // Final status update
                        }
                    };
                    
                    pollScanStatus();
                } else {
                    alert(data.error || 'Scan failed to start');
                    scanInProgress = false;
                    updateScanButton();
                }
            } catch (e) {
                console.error('Scan trigger failed:', e);
                scanInProgress = false;
                updateScanButton();
            }
        }
        
        async function stopScan() {
            try {
                const res = await fetch('/api/scan', { method: 'DELETE' });
                const data = await res.json();
                
                scanInProgress = false;
                updateScanButton();
                fetchStatus();
                console.log('Scan stopped:', data.message);
            } catch (e) {
                console.error('Stop failed:', e);
            }
        }
        
        function toggleScan() {
            if (scanInProgress) {
                if (confirm('Stop current scan?')) {
                    stopScan();
                }
            } else {
                triggerScan();
            }
        }
        
        // Initial load
        fetchStatus();
        fetchGroups();
        
        // Auto-refresh status every 2 seconds
        setInterval(fetchStatus, 2000);
        
        // Auto-refresh results every 10 seconds
        setInterval(() => {
            if (currentView === 'groups') fetchGroups();
        }, 10000);
    </script>
</body>
</html>
'''

# ==================== Main ====================

if __name__ == '__main__':
    init_monitor()
    
    # Start Flask app
    port = int(os.getenv('NETMON_WEB_PORT', '5000'))
    debug = os.getenv('NETMON_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting NetMon Web API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)
