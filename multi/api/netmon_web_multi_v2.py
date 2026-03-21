#!/usr/bin/env python3
"""
Multi-User Concurrent NetMon Web API v2.0
Supports multiple users scanning different network segments simultaneously

Changes from v1.x:
  - Fixed get_monitor() method missing (was causing API errors)
  - Fixed get_user_data() lock logic (was creating invalid temp locks)
  - Added ThreadPoolExecutor to limit concurrent scans (max 5)
  - Improved thread safety for user data access
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
import uuid
from collections import defaultdict

# Import the monitor class
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from realtime_subnet_monitor import RealtimeSubnetMonitor

# Thread pool for concurrent scans (limit to prevent system overload)
from concurrent.futures import ThreadPoolExecutor
scan_executor = ThreadPoolExecutor(max_workers=5)  # Max 5 concurrent scans

# ==================== Multi-User Architecture ====================

class UserManager:
    """Manages multiple user sessions and their isolated monitors"""
    
    def __init__(self):
        self.users = {}  # {user_id: {'monitor': monitor_instance, 'config': config, 'results': results}}
        self.user_locks = {}  # {user_id: threading.Lock()}
        self.global_lock = threading.Lock()  # For managing user list
        
    def create_user_session(self, user_id=None):
        """Create a new user session with isolated monitor"""
        if user_id is None:
            user_id = str(uuid.uuid4())
        
        with self.global_lock:
            if user_id not in self.users:
                # Default configuration for new user
                default_config = {
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
                
                # Create isolated monitor for this user
                monitor = RealtimeSubnetMonitor(
                    ip_prefix=default_config['ip_prefix'],
                    start_subnet=default_config['start_subnet'],
                    end_subnet=default_config['end_subnet'],
                    scan_ip_start=default_config['scan_ip_start'],
                    scan_ip_end=default_config['scan_ip_end'],
                    scan_mode=default_config['scan_mode'],
                    tcp_port=default_config['tcp_port'],
                    refresh_interval=default_config['refresh_interval'],
                    retry_count=default_config['retry_count'],
                    subnets_per_group=default_config['subnets_per_group'],
                    display_refresh_rate=5.0
                )
                
                self.users[user_id] = {
                    'monitor': monitor,
                    'config': default_config.copy(),
                    'results': {},
                    'scan_in_progress': False,
                    'last_scan_time': None,
                    'last_scan_duration': None,
                    'created_at': datetime.now().isoformat()
                }
                self.user_locks[user_id] = threading.Lock()
                
                logging.info(f"Created user session: {user_id}")
        
        return user_id
    
    def get_user_data(self, user_id):
        """Get user's data safely"""
        with self.global_lock:
            if user_id not in self.users:
                return None
            with self.user_locks.get(user_id, threading.Lock()):
                return self.users.get(user_id, None)
    
    def get_monitor(self, user_id):
        """Get user's monitor instance safely"""
        user_data = self.get_user_data(user_id)
        return user_data['monitor'] if user_data else None
    
    def update_user_config(self, user_id, new_config):
        """Update user's configuration and reinitialize monitor"""
        with self.user_locks[user_id]:
            user_data = self.users[user_id]
            
            # Update config
            for key, value in new_config.items():
                if key in user_data['config']:
                    if key in ['start_subnet', 'end_subnet', 'scan_ip_start', 'scan_ip_end', 'tcp_port', 'refresh_interval', 'retry_count', 'subnets_per_group']:
                        user_data['config'][key] = int(value)
                    else:
                        user_data['config'][key] = value
            
            # Reinitialize monitor with new config
            user_data['monitor'] = RealtimeSubnetMonitor(
                ip_prefix=user_data['config']['ip_prefix'],
                start_subnet=user_data['config']['start_subnet'],
                end_subnet=user_data['config']['end_subnet'],
                scan_ip_start=user_data['config']['scan_ip_start'],
                scan_ip_end=user_data['config']['scan_ip_end'],
                scan_mode=user_data['config']['scan_mode'],
                tcp_port=user_data['config']['tcp_port'],
                refresh_interval=user_data['config']['refresh_interval'],
                retry_count=user_data['config']['retry_count'],
                subnets_per_group=user_data['config']['subnets_per_group'],
                display_refresh_rate=5.0
            )
    
    def start_scan(self, user_id):
        """Start scan for specific user"""
        with self.user_locks[user_id]:
            user_data = self.users[user_id]
            if user_data['scan_in_progress']:
                return False, 'Scan already in progress'
            
            user_data['scan_in_progress'] = True
            return True, 'Scan started'
    
    def complete_scan(self, user_id, results, duration, scan_time):
        """Complete scan for specific user"""
        with self.user_locks[user_id]:
            user_data = self.users[user_id]
            user_data['scan_in_progress'] = False
            user_data['last_scan_time'] = scan_time
            user_data['last_scan_duration'] = duration
            user_data['results'] = results
    
    def stop_scan(self, user_id):
        """Stop scan for specific user"""
        with self.user_locks[user_id]:
            user_data = self.users[user_id]
            if user_data['scan_in_progress']:
                user_data['monitor'].running = False
                user_data['monitor'].is_scanning = False
                user_data['scan_in_progress'] = False
                return True, 'Scan stopped'
            return False, 'No scan in progress'
    
    def get_results(self, user_id):
        """Get results for specific user"""
        with self.user_locks[user_id]:
            user_data = self.users[user_id]
            return {
                'scan_in_progress': user_data['scan_in_progress'],
                'last_scan_time': user_data['last_scan_time'].isoformat() if user_data['last_scan_time'] else None,
                'last_scan_duration': user_data['last_scan_duration'],
                'config': user_data['config'],
                'results': user_data['results']
            }

# Initialize user manager
user_manager = UserManager()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__, 
            static_folder='web/static',
            template_folder='web/templates')

# API Key (simple auth for now)
API_KEY = os.getenv('NETMON_API_KEY', 'netmon-api-key')

def require_api_key(f):
    """Decorator to require API key"""
    @wraps(f)
    def decorated(*args, **kwargs):
        provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        if provided_key != API_KEY:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def get_user_id_from_request():
    """Extract user ID from request"""
    user_id = request.headers.get('X-User-ID') or request.args.get('user_id')
    if not user_id:
        # Create new session if no user ID provided
        user_id = user_manager.create_user_session()
    elif user_id not in user_manager.users:
        # Create session if user doesn't exist
        user_id = user_manager.create_user_session(user_id)
    return user_id

# ==================== Routes ====================

@app.route('/')
def index():
    """Serve the main web interface"""
    user_id = get_user_id_from_request()
    user_data = user_manager.get_user_data(user_id)
    config = user_data['config'] if user_data else {}
    
    # Common TCP ports for quick selection
    COMMON_TCP_PORTS = [
        (22, 'SSH'),
        (80, 'HTTP'), 
        (443, 'HTTPS'),
        (445, 'SMB'),
        (3389, 'RDP'),
        (8080, 'HTTP-Alt'),
        (139, 'NetBIOS'),
        (53, 'DNS'),
        (3306, 'MySQL'),
        (5432, 'PostgreSQL'),
        (6379, 'Redis'),
        (27017, 'MongoDB'),
    ]
    
    return render_template_string(HTML_TEMPLATE, config=config, common_ports=COMMON_TCP_PORTS, user_id=user_id)

@app.route('/api/status')
@require_api_key
def api_status():
    """Get current user's status"""
    user_id = get_user_id_from_request()
    results = user_manager.get_results(user_id)
    monitor = user_manager.get_monitor(user_id)
    
    # Get progress information from the monitor if available
    progress_info = {}
    if monitor and hasattr(monitor, 'scan_progress'):
        progress_info = {
            'scan_progress': monitor.scan_progress,
            'scan_current': monitor.scan_current,
            'scan_total': monitor.scan_total,
            'is_scanning': monitor.is_scanning
        }
    
    return jsonify({
        'status': 'running',
        'user_id': user_id,
        'scan_in_progress': results['scan_in_progress'],
        'last_scan_time': results['last_scan_time'],
        'last_scan_duration': results['last_scan_duration'],
        'config': results['config'],
        'timestamp': datetime.now().isoformat(),
        **progress_info
    })

@app.route('/api/scan', methods=['POST'])
@require_api_key
def api_scan():
    """Trigger a new scan for current user"""
    user_id = get_user_id_from_request()
    
    success, message = user_manager.start_scan(user_id)
    if not success:
        return jsonify({'error': message}), 409
    
    # Run scan in background thread using thread pool (limits concurrent scans)
    def run_user_scan():
        user_data = user_manager.get_user_data(user_id)
        if not user_data:
            return
        monitor = user_data['monitor']
        
        start_time = time.time()
        try:
            monitor.scan_all_subnets()
            
            # Prepare results
            results = {
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
                results['groups'][group_idx] = {
                    'name': group['name'],
                    'subnets': group_data,
                    'total': sum(g['count'] for g in group_data)
                }
            
            duration = time.time() - start_time
            scan_time = datetime.now()
            
            # Complete scan
            user_manager.complete_scan(user_id, results, duration, scan_time)
            logger.info(f"User {user_id} scan completed: {len(monitor.active_hosts)} hosts in {duration:.2f}s")
            
        except Exception as e:
            logger.error(f"User {user_id} scan failed: {e}")
            # Mark scan as complete even if failed
            user_manager.complete_scan(user_id, {}, 0, datetime.now())
    
    # Use thread pool to limit concurrent scans (max 5)
    scan_executor.submit(run_user_scan)
    
    return jsonify({'status': 'started', 'message': 'User scan initiated', 'user_id': user_id})

@app.route('/api/scan', methods=['DELETE'])
@require_api_key
def api_stop_scan():
    """Stop current user's scan"""
    user_id = get_user_id_from_request()
    
    success, message = user_manager.stop_scan(user_id)
    return jsonify({'status': 'success' if success else 'error', 'message': message, 'user_id': user_id})

@app.route('/api/scan/group/<int:group_id>', methods=['POST'])
@require_api_key
def api_scan_group(group_id):
    """Trigger scan for a specific group for current user"""
    user_id = get_user_id_from_request()
    
    user_data = user_manager.get_user_data(user_id)
    if not user_data:
        return jsonify({'error': 'User not found'}), 404
    
    monitor = user_data['monitor']
    if group_id < 0 or group_id >= len(monitor.subnet_groups):
        return jsonify({'error': f'Invalid group ID: {group_id}'}), 400
    
    success, message = user_manager.start_scan(user_id)
    if not success:
        return jsonify({'error': message}), 409
    
    def run_group_scan():
        try:
            monitor.scan_group(group_id)
            duration = 0  # We don't track individual group duration here
            scan_time = datetime.now()
            
            # Just complete the scan status
            user_manager.complete_scan(user_id, user_data['results'], duration, scan_time)
            logger.info(f"User {user_id} group {group_id} scan completed")
        except Exception as e:
            logger.error(f"User {user_id} group {group_id} scan failed: {e}")
            user_manager.complete_scan(user_id, user_data['results'], 0, datetime.now())
    
    # Use thread pool to limit concurrent scans
    scan_executor.submit(run_group_scan)
    
    return jsonify({
        'status': 'started',
        'message': f'User {user_id} scanning group {group_id}',
        'user_id': user_id,
        'group_id': group_id
    })

@app.route('/api/results')
@require_api_key
def api_results():
    """Get latest scan results for current user"""
    user_id = get_user_id_from_request()
    results = user_manager.get_results(user_id)
    monitor = user_manager.get_monitor(user_id)
    
    # Get progress information from the monitor if available
    progress_info = {}
    if monitor and hasattr(monitor, 'scan_progress'):
        progress_info = {
            'scan_progress': monitor.scan_progress,
            'scan_current': monitor.scan_current,
            'scan_total': monitor.scan_total,
            'is_scanning': monitor.is_scanning
        }
    
    return jsonify({
        'user_id': user_id,
        'scan_in_progress': results['scan_in_progress'],
        'last_scan_time': results['last_scan_time'],
        'last_scan_duration': results['last_scan_duration'],
        'groups': results['results'].get('groups', {}),
        'total_hosts': len(results['results'].get('active_hosts', [])),
        **progress_info
    })

@app.route('/api/groups')
@require_api_key
def api_groups():
    """Get group list for current user"""
    user_id = get_user_id_from_request()
    user_data = user_manager.get_user_data(user_id)
    
    if user_data and user_data['monitor']:
        monitor = user_data['monitor']
        groups = []
        for idx, group in monitor.subnet_groups.items():
            # Use the current results from the monitor, not stored results
            total = sum(len(monitor.results.get(s, [])) for s in group['subnets'])
            groups.append({
                'id': idx,
                'name': group['name'],
                'subnets': group['subnets'],
                'subnet_range': f"{group['subnets'][0].split('.')[2]}-{group['subnets'][-1].split('.')[2]}" if group['subnets'] else '',
                'total_hosts': total
            })
        return jsonify({'user_id': user_id, 'groups': groups})
    
    return jsonify({'user_id': user_id, 'groups': []})

@app.route('/api/group/<int:group_id>')
@require_api_key
def api_group_detail(group_id):
    """Get detailed results for a specific group for current user"""
    user_id = get_user_id_from_request()
    user_data = user_manager.get_user_data(user_id)
    
    if not user_data or group_id not in user_data['monitor'].subnet_groups:
        return jsonify({'error': 'Group not found'}), 404
    
    monitor = user_data['monitor']
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
        'user_id': user_id,
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
    """Get or update current user's configuration"""
    user_id = get_user_id_from_request()
    
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON'}), 400
        
        user_manager.update_user_config(user_id, data)
        user_data = user_manager.get_user_data(user_id)
        
        logger.info(f"User {user_id} configuration updated")
        return jsonify({'status': 'updated', 'config': user_data['config'], 'user_id': user_id})
    
    # GET request
    user_data = user_manager.get_user_data(user_id)
    if user_data:
        return jsonify({'config': user_data['config'], 'user_id': user_id})
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/health')
def health():
    """Health check endpoint"""
    active_users = len(user_manager.users)
    return jsonify({
        'status': 'healthy', 
        'timestamp': datetime.now().isoformat(),
        'active_users': active_users
    })

# ==================== HTML Template ====================

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetMon - Multi-User Network Monitor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            line-height: 1.6;
        }
        .header {
            background: #0f3460;
            padding: 20px;
            text-align: center;
            border-bottom: 2px solid #00d9ff;
        }
        .header h1 { color: #00d9ff; margin-bottom: 10px; }
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
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: #16213e;
            border-radius: 8px;
            padding: 15px;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
            border: 2px solid #0f3460;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.3);
            border-color: #00d9ff;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #0f3460;
        }
        .card-title { color: #00d9ff; font-size: 18px; font-weight: bold; }
        .card-count { 
            background: #00d9ff; 
            color: #1a1a2e; 
            padding: 2px 8px; 
            border-radius: 12px; 
            font-weight: bold; 
        }
        .card-subnets { color: #aaa; font-size: 14px; margin: 5px 0; }
        .progress-bar {
            width: 100%;
            height: 6px;
            background: #333;
            border-radius: 3px;
            margin-top: 10px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00d9ff, #00b8d4);
            transition: width 0.3s;
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
            border-bottom: 2px solid #0f3460;
        }
        .detail-header h2 { color: #00d9ff; }
        .subnet-grid { display: flex; flex-direction: column; gap: 20px; }
        .subnet-box {
            background: #0f3460;
            border-radius: 6px;
            padding: 15px;
        }
        .subnet-title {
            color: #00d9ff;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .ip-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(40px, 1fr));
            gap: 5px;
        }
        .ip-cell {
            background: #16213e;
            border: 1px solid #333;
            border-radius: 3px;
            padding: 5px;
            text-align: center;
            font-size: 12px;
        }
        .ip-cell.active {
            background: #00ff88;
            color: #1a1a2e;
            font-weight: bold;
        }
        .settings-panel {
            position: fixed;
            top: 0;
            right: 0;
            width: 400px;
            height: 100vh;
            background: #16213e;
            padding: 20px;
            box-shadow: -5px 0 15px rgba(0,0,0,0.5);
            overflow-y: auto;
            z-index: 1000;
        }
        .settings-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        .form-group {
            display: flex;
            flex-direction: column;
        }
        .form-group label {
            margin-bottom: 5px;
            color: #00d9ff;
            font-weight: bold;
        }
        .form-group input, .form-group select {
            padding: 8px;
            border: 1px solid #333;
            border-radius: 4px;
            background: #0f3460;
            color: #eee;
        }
        .btn-save {
            background: #00d9ff;
            color: #1a1a2e;
            padding: 12px;
            font-weight: bold;
        }
        .btn-save:hover { background: #00cc6a; }
        .btn-stop {
            background: #ff4757;
            color: #fff;
        }
        .btn-stop:hover { background: #ff6b7a; }
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
        .back-btn {
            background: #0f3460;
            color: #eee;
        }
        .back-btn:hover { background: #16213e; }
        .loading {
            text-align: center;
            padding: 50px;
            color: #00d9ff;
        }
        .spinner {
            border: 4px solid #333;
            border-top: 4px solid #00d9ff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .scan-status {
            padding: 8px 12px;
            border-radius: 4px;
            font-weight: bold;
            margin-left: auto;
        }
        .scanning {
            background: #ff9800;
            color: #000;
        }
        .idle {
            background: #4CAF50;
            color: white;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🖥️ NetMon Multi-User</h1>
        <div class="subtitle">Concurrent Network Monitor - User: {{ user_id[:8] }}...</div>
    </div>
    
    <div class="container">
        <div class="status-bar">
            <span>User: <strong>{{ user_id[:8] }}...</strong></span>
            <span>Network: <strong>{{ config.ip_prefix }}.{{ config.start_subnet }}-{{ config.end_subnet }}</strong></span>
            <span>IP: <strong>{{ config.scan_ip_start }}-{{ config.scan_ip_end }}</strong></span>
            <span>Mode: <strong>{{ config.scan_mode.upper() }}{% if config.scan_mode == 'tcp' %}:{{ config.tcp_port }}{% endif %}</strong></span>
            <span>Last: <strong id="last-scan">--</strong></span>
            <span>Duration: <strong id="scan-duration">--</strong></span>
            <div class="scan-status idle" id="scan-status">✓ Ready</div>
            <button class="btn btn-settings" onclick="toggleSettings()">⚙️ Settings</button>
            <button class="btn btn-scan" id="scan-btn" onclick="toggleScan()">🔄 Scan</button>
        </div>
        
        <div id="content">
            <div class="loading">
                <div class="spinner"></div>
                <div>Loading groups...</div>
            </div>
        </div>
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
    
    <div id="group-detail" class="detail-view hidden">
        <div class="detail-header">
            <h2 id="group-title">Group Details</h2>
            <div>
                <button class="btn rescan-btn" id="rescan-btn">🔄 Rescan (R)</button>
                <button class="btn back-btn" onclick="showGroups()">← Back</button>
            </div>
        </div>
        <div id="ip-grid" class="ip-grid">
            <!-- IP grid will be populated here -->
        </div>
    </div>

    <script>
        let currentView = 'groups';
        let currentGroupId = null;
        let settingsOpen = false;
        let scanInProgress = false;
        let currentUser = '{{ user_id }}';  // Include user ID in JavaScript
        
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
                portGroup.style.flexDirection = 'column';
            } else {
                portGroup.style.display = 'none';
            }
        }
        
        function updateScanDuration(duration) {
            document.getElementById('scan-duration').textContent = duration ? duration.toFixed(1) + 's' : '--';
        }
        
        async function loadConfig() {
            try {
                const res = await fetch(`/api/config?user_id=${currentUser}`);
                const cfg = await res.json();
                
                document.getElementById('cfg-ip-prefix').value = cfg.config.ip_prefix;
                document.getElementById('cfg-start-subnet').value = cfg.config.start_subnet;
                document.getElementById('cfg-end-subnet').value = cfg.config.end_subnet;
                document.getElementById('cfg-subnets-per-group').value = cfg.config.subnets_per_group;
                document.getElementById('cfg-ip-start').value = cfg.config.scan_ip_start;
                document.getElementById('cfg-ip-end').value = cfg.config.scan_ip_end;
                document.getElementById('cfg-mode').value = cfg.config.scan_mode;
                document.getElementById('cfg-tcp-port').value = cfg.config.tcp_port;
                document.getElementById('cfg-retry').value = cfg.config.retry_count;
                document.getElementById('cfg-refresh').value = cfg.config.refresh_interval;
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
                
                const res = await fetch(`/api/config?user_id=${currentUser}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-User-ID': currentUser
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
                    setTimeout(() => location.reload(), 2000);  // Reload to get new user context
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
        
        async function toggleScan() {
            if (scanInProgress) {
                await stopScan();
            } else {
                await triggerScan();
            }
        }
        
        async function triggerScan() {
            try {
                const res = await fetch(`/api/scan?user_id=${currentUser}`, { 
                    method: 'POST',
                    headers: { 'X-User-ID': currentUser }
                });
                const data = await res.json();
                
                if (res.ok) {
                    scanInProgress = true;
                    updateScanButton();
                    fetchStatus(); // Refresh status immediately
                    
                    // Poll until scan completes
                    const pollScanStatus = async () => {
                        await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 sec
                        const statusRes = await fetch(`/api/status?user_id=${currentUser}`);
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
                const res = await fetch(`/api/scan?user_id=${currentUser}`, { 
                    method: 'DELETE',
                    headers: { 'X-User-ID': currentUser }
                });
                const data = await res.json();
                
                scanInProgress = false;
                updateScanButton();
                fetchStatus();
                console.log('Scan stopped:', data.message);
            } catch (e) {
                console.error('Stop failed:', e);
            }
        }
        
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
        
        async function fetchStatus() {
            try {
                const res = await fetch(`/api/status?user_id=${currentUser}`);
                const data = await res.json();
                
                // Update last scan time
                if (data.last_scan_time) {
                    const scanTime = new Date(data.last_scan_time);
                    document.getElementById('last-scan').textContent = scanTime.toLocaleTimeString();
                } else {
                    document.getElementById('last-scan').textContent = '--';
                }
                
                updateScanDuration(data.last_scan_duration);
                
                // Sync scan state
                scanInProgress = data.scan_in_progress;
                updateScanButton();
                
                const statusEl = document.getElementById('scan-status');
                if (data.scan_in_progress) {
                    statusEl.className = 'scan-status scanning';
                    statusEl.textContent = '⏳ Scanning...';
                } else {
                    statusEl.className = 'scan-status idle';
                    statusEl.textContent = '✓ Ready';
                }
            } catch (e) {
                console.error('Status fetch failed:', e);
            }
        }
        
        async function fetchGroups() {
            try {
                console.log('Fetching groups for user:', currentUser);
                const res = await fetch(`/api/groups?user_id=${currentUser}`);
                const data = await res.json();
                
                if (!data.groups || data.groups.length === 0) {
                    document.getElementById('content').innerHTML = `
                        <div class="loading">
                            <div>No groups configured. Run a scan first.</div>
                        </div>
                    `;
                    return;
                }
                
                const grid = document.createElement('div');
                grid.className = 'grid';
                
                data.groups.forEach(group => {
                    const card = document.createElement('div');
                    card.className = 'card';
                    card.onclick = () => showGroupDetail(group.id);
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
                });
                
                document.getElementById('content').innerHTML = '';
                document.getElementById('content').appendChild(grid);
            } catch (e) {
                console.error('Groups fetch failed:', e);
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
                const res = await fetch(`/api/group/${groupId}?user_id=${currentUser}`);
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
                
                // Add keyboard listener
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
                const res = await fetch(`/api/scan/group/${groupId}?user_id=${currentUser}`, {
                    method: 'POST',
                    headers: { 'X-User-ID': currentUser }
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
    port = int(os.getenv('NETMON_WEB_PORT', '80'))  # Changed from 5000 to 80
    debug = os.getenv('NETMON_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Starting Multi-User NetMon Web API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug, threaded=True)