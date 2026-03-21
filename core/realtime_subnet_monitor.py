#!/usr/bin/env python3
"""
Real-time Subnet Monitor Script v2.0
Monitors active IPs in specified subnets with multiple scan modes:
  - PING: Fast async ping sweep (optimized)
  - TCP: TCP port scan (selectable ports)
  - NMAP: Use nmap for advanced scanning (if available)

Changes from v1.x:
  - Fixed Windows ping timeout (500ms -> 5000ms)
  - Fixed TCP retry logic (only retry on timeout, not connection refused)
  - Added thread-safe locks for results and active_hosts
  - Fixed NMAP parsing with regex for robustness
  - Added NMAP batch processing to avoid command line limits
  - Increased default thread pool size (500 -> 800, scalable to CPU × 80)
  - Supports variable IP ranges (e.g., /26 subnet with 64 IPs)
"""

import subprocess
import threading
import queue
import time
import logging
from datetime import datetime
import argparse
import sys
import os
from ipaddress import IPv4Network
import json
import signal
import select
import math
import socket
import multiprocessing
import re

# ANSI Color codes
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    MAGENTA = '\033[95m'


def get_key_press(timeout=0.01):
    """Cross-platform non-blocking keyboard input with timeout."""
    try:
        if sys.platform.startswith('win'):
            import msvcrt
            if msvcrt.kbhit():
                key = msvcrt.getch()
                return key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else key
        else:
            # Use select with small timeout to catch key presses
            if select.select([sys.stdin], [], [], timeout)[0]:
                return sys.stdin.read(1)
    except Exception:
        pass
    return None


class RealtimeSubnetMonitor:
    # Available TCP ports for selection
    TCP_PORTS_AVAILABLE = {
        '22': 22,    # SSH
        '80': 80,    # HTTP
        '443': 443,  # HTTPS
        '445': 445,  # SMB
        '3389': 3389,# RDP
        '8080': 8080,# HTTP Alt
        '139': 139,  # NetBIOS
        '53': 53,    # DNS
    }

    def __init__(self, log_file=None, refresh_interval=30, scan_mode='ping',
                 start_subnet=1, end_subnet=254, groups_per_row=4, progress_refresh_rate=1.0,
                 tcp_port=22, ip_prefix='192.168', scan_ip_start=1, scan_ip_end=254,
                 display_refresh_rate=5.0, subnets_per_group=None, retry_count=2):
        import os
        self.pid = os.getpid()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Set default log file with PID if not provided
        if log_file is None:
            log_file = f'realtime_subnet_monitor_{self.pid}.log'
        
        self.log_file = log_file
        self.refresh_interval = refresh_interval
        self.scan_mode = scan_mode

        self.start_subnet = start_subnet
        self.end_subnet = end_subnet
        # subnets_per_group takes precedence, fallback to groups_per_row for backwards compat
        self.subnets_per_group = subnets_per_group if subnets_per_group is not None else groups_per_row
        self.progress_refresh_rate = progress_refresh_rate
        self.tcp_port = tcp_port  # Single port for TCP mode
        
        # Display refresh rate (seconds) - reduced for stability
        self.display_refresh_rate = display_refresh_rate

        # Network prefix (first two octets)
        self.ip_prefix = ip_prefix  # e.g., "10.100"

        # Fourth octet scan range
        self.scan_ip_start = scan_ip_start  # Default 1
        self.scan_ip_end = scan_ip_end      # Default 254

        # Logger setup - file only
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()
        file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

        # Scan progress tracking
        self.scan_progress = 0
        self.scan_current = 0
        self.scan_total = 0
        self.is_scanning = False
        self.last_scan_time = None
        self.last_scan_duration = None  # Track last scan duration in seconds
        self.auto_scan_enabled = True
        
        # Retry settings for missed hosts
        self.retry_count = retry_count  # Number of retries for unresponsive hosts (default: 2)

        # Define subnets using configurable prefix
        self.subnets = [f'{self.ip_prefix}.{i}.0/24' for i in range(self.start_subnet, self.end_subnet + 1)]

        # Organize subnets into groups (configurable subnets per group)
        self.subnet_groups = {}
        for i, subnet in enumerate(self.subnets):
            group_idx = i // self.subnets_per_group
            if group_idx not in self.subnet_groups:
                start_ip = self.start_subnet + group_idx * self.subnets_per_group
                end_ip = start_ip + self.subnets_per_group - 1
                self.subnet_groups[group_idx] = {'name': f'G{group_idx+1}', 'subnets': []}
            self.subnet_groups[group_idx]['subnets'].append(subnet)

        self.results = {}
        self.active_hosts = []
        self.running = True

        # TCP port for current scan
        self.tcp_ports = [tcp_port]  # Single port mode
        self.nmap_available = self._check_nmap()

        # Dynamic thread pool size based on CPU cores (increased for large networks)
        self.max_threads = min(800, max(200, multiprocessing.cpu_count() * 80))

        # Thread locks for thread-safe access to shared data structures
        self._results_lock = threading.Lock()
        self._active_hosts_lock = threading.Lock()

        # Only register signal handlers in main thread (not in web mode)
        try:
            if threading.current_thread() is threading.main_thread():
                signal.signal(signal.SIGINT, self.signal_handler)
                signal.signal(signal.SIGTERM, self.signal_handler)
        except ValueError:
            # Already in a child thread, skip signal registration
            pass

    def _check_nmap(self):
        """Check if nmap is installed"""
        try:
            result = subprocess.run(['nmap', '--version'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if result.returncode == 0:
                self.logger.info("Nmap is available")
                return True
        except FileNotFoundError:
            pass
        self.logger.info("Nmap is not available")
        return False

    def signal_handler(self, sig, frame):
        """Handle interrupt signal gracefully"""
        print(f'\n{Colors.YELLOW}Shutting down monitor...{Colors.RESET}')
        self.running = False
        self.is_scanning = False
        # Give some time for threads to finish
        time.sleep(0.5)
        sys.exit(0)

    # ==================== PING MODE ====================

    def ping_host(self, host, result_queue):
        """Ping a single host with retry mechanism"""
        # Try up to (1 + retry_count) times
        for attempt in range(1 + self.retry_count):
            try:
                if sys.platform.startswith('win'):
                    result = subprocess.run(['ping', '-n', '1', '-w', '5000', str(host)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(host)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
                if result.returncode == 0:
                    result_queue.put(str(host))
                    if attempt > 0:
                        self.logger.debug(f"Host {host} is alive (retry #{attempt})")
                    else:
                        self.logger.debug(f"Host {host} is alive")
                    return  # Success, no need to retry
            except subprocess.TimeoutExpired:
                if attempt < self.retry_count:
                    self.logger.debug(f"Host {host} ping timed out, retrying ({attempt + 1}/{self.retry_count})")
                    time.sleep(0.1)  # Small delay before retry
                else:
                    self.logger.debug(f"Host {host} ping timed out (all retries exhausted)")
            except Exception as e:
                if attempt < self.retry_count:
                    self.logger.debug(f"Error pinging {host}: {e}, retrying ({attempt + 1}/{self.retry_count})")
                    time.sleep(0.1)
                else:
                    self.logger.debug(f"Error pinging {host}: {e} (all retries exhausted)")

    def scan_subnet_ping(self, subnet_str):
        """Scan subnet using ping"""
        self.logger.debug(f"Scanning subnet (ping): {subnet_str}")
        network = IPv4Network(subnet_str, strict=False)
        result_queue = queue.Queue()
        threads = []

        # Only scan configured IP range
        hosts = [f"{subnet_str.split('/')[0].rsplit('.', 1)[0]}.{i}" 
                 for i in range(self.scan_ip_start, self.scan_ip_end + 1)]

        for host in hosts:
            thread = threading.Thread(target=self.ping_host, args=(host, result_queue))
            threads.append(thread)
            thread.start()

            if len(threads) >= self.max_threads:
                threads[0].join(timeout=1)
                threads.pop(0)

        for thread in threads:
            thread.join(timeout=5)

        active_hosts = []
        while not result_queue.empty():
            host = result_queue.get()
            active_hosts.append(host)
            # Thread-safe update of active_hosts
            with self._active_hosts_lock:
                if host not in self.active_hosts:
                    self.active_hosts.append(host)

        # Thread-safe update of results
        with self._results_lock:
            self.results[subnet_str] = active_hosts
        self.logger.debug(f"Found {len(active_hosts)} active hosts in {subnet_str}")
        return active_hosts

    # ==================== TCP SCAN MODE ====================

    def scan_port_tcp(self, host, port, timeout=0.5):
        """Scan a single TCP port with retry mechanism"""
        # Try up to (1 + retry_count) times, but only retry on timeout/exception
        for attempt in range(1 + self.retry_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((str(host), port))
                sock.close()
                if result == 0:
                    if attempt > 0:
                        self.logger.debug(f"Host {host}:{port} open (retry #{attempt})")
                    return True
                # Connection refused/closed - don't retry, host is down
                return False
            except socket.timeout:
                # Only retry on timeout
                if attempt < self.retry_count:
                    self.logger.debug(f"Host {host}:{port} timeout, retrying ({attempt + 1}/{self.retry_count})")
                    time.sleep(0.1)
                else:
                    self.logger.debug(f"Host {host}:{port} timeout (all retries exhausted)")
            except Exception as e:
                if attempt < self.retry_count:
                    time.sleep(0.1)
                else:
                    self.logger.debug(f"TCP scan error for {host}:{port}: {e}")
        return False

    def scan_host_tcp(self, host, result_queue):
        """Scan single TCP port on a host"""
        port = self.tcp_ports[0]  # Single port mode
        if self.scan_port_tcp(host, port):
            result_queue.put((str(host), port))
            # Thread-safe update of active_hosts
            with self._active_hosts_lock:
                if host not in self.active_hosts:
                    self.active_hosts.append(host)
            self.logger.debug(f"Host {host} has port {port} open")

    def scan_subnet_tcp(self, subnet_str):
        """Scan subnet using TCP port scan (single port)"""
        self.logger.debug(f"Scanning subnet (TCP:{self.tcp_ports[0]}): {subnet_str}")
        result_queue = queue.Queue()
        threads = []

        # Only scan configured IP range
        base_prefix = subnet_str.split('/')[0].rsplit('.', 1)[0]
        hosts = [f"{base_prefix}.{i}" for i in range(self.scan_ip_start, self.scan_ip_end + 1)]

        for host in hosts:
            thread = threading.Thread(target=self.scan_host_tcp, args=(host, result_queue))
            threads.append(thread)
            thread.start()

            if len(threads) >= self.max_threads:
                threads[0].join(timeout=1)
                threads.pop(0)

        for thread in threads:
            thread.join(timeout=10)

        active_hosts = []
        while not result_queue.empty():
            host, port = result_queue.get()
            if host not in active_hosts:
                active_hosts.append(host)

        # Thread-safe update of results
        with self._results_lock:
            self.results[subnet_str] = active_hosts
        self.logger.debug(f"Found {len(active_hosts)} active hosts in {subnet_str} on port {self.tcp_ports[0]}")
        return active_hosts

    # ==================== NMAP MODE ====================

    def scan_subnet_nmap(self, subnet_str):
        """Scan subnet using nmap"""
        self.logger.debug(f"Scanning subnet (nmap): {subnet_str}")
        try:
            # Build IP list for nmap (batch to avoid command line length limits)
            base_prefix = subnet_str.split('/')[0].rsplit('.', 1)[0]
            all_ips = [f"{base_prefix}.{i}" for i in range(self.scan_ip_start, self.scan_ip_end + 1)]
            
            active_hosts = []
            # Process in batches to avoid command line length limits
            batch_size = 50
            for i in range(0, len(all_ips), batch_size):
                batch_ips = all_ips[i:i+batch_size]
                ip_list = ','.join(batch_ips)
                
                result = subprocess.run(
                    ['nmap', '-sn', '-PR', '--max-retries', '1', '--host-timeout', '5s', ip_list],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30
                )

                # Use regex for robust IP parsing
                ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
                for line in result.stdout.decode('utf-8', errors='ignore').split('\n'):
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        # Filter out obviously invalid addresses
                        if ip and not ip.startswith('255.') and not ip.startswith('0.'):
                            if ip not in active_hosts:
                                active_hosts.append(ip)

            # Thread-safe update of results and active_hosts
            with self._results_lock:
                self.results[subnet_str] = active_hosts
            with self._active_hosts_lock:
                for host in active_hosts:
                    if host not in self.active_hosts:
                        self.active_hosts.append(host)

            self.logger.debug(f"Found {len(active_hosts)} active hosts in {subnet_str}")
            return active_hosts

        except subprocess.TimeoutExpired:
            self.logger.error(f"Nmap scan timeout for {subnet_str}")
            return []
        except Exception as e:
            self.logger.error(f"Nmap scan error: {e}")
            return []

    # ==================== UNIFIED SCAN INTERFACE ====================

    def scan_subnet(self, subnet_str):
        """Scan subnet using current mode"""
        if self.scan_mode == 'ping':
            return self.scan_subnet_ping(subnet_str)
        elif self.scan_mode == 'tcp':
            return self.scan_subnet_tcp(subnet_str)
        elif self.scan_mode == 'nmap':
            return self.scan_subnet_nmap(subnet_str)
        return self.scan_subnet_ping(subnet_str)

    def scan_all_subnets(self):
        """Scan all defined subnets"""
        self.logger.info(f"Starting scan of {len(self.subnets)} subnets (mode: {self.scan_mode}, tcp_port: {self.tcp_port}, ip_range: {self.scan_ip_start}-{self.scan_ip_end})")
        start_time = time.time()

        self.results.clear()
        self.active_hosts.clear()

        self.scan_total = len(self.subnets)
        self.scan_current = 0
        self.scan_progress = 0
        self.is_scanning = True

        batch_size = 5  # Reduced from 10 for better scalability with many subnets
        for i in range(0, len(self.subnets), batch_size):
            if not self.is_scanning or not self.running:
                self.logger.info("Scan interrupted by user")
                break

            batch = self.subnets[i:i+batch_size]
            threads = []

            for subnet in batch:
                thread = threading.Thread(target=self.scan_subnet, args=(subnet,))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()

            self.scan_current = min(i + batch_size, len(self.subnets))
            self.scan_progress = int((self.scan_current / self.scan_total) * 100)

        # Build active_hosts from all results (thread-safe)
        with self._active_hosts_lock:
            for subnet, hosts in self.results.items():
                for host in hosts:
                    if host not in self.active_hosts:
                        self.active_hosts.append(host)

        self.is_scanning = False
        self.last_scan_time = datetime.now()
        end_time = time.time()
        self.last_scan_duration = end_time - start_time  # Record scan duration
        self.logger.info(f"Scan completed in {self.last_scan_duration:.2f} seconds. Found {len(self.active_hosts)} active hosts.")
        return self.results

    def scan_group(self, group_id):
        """Scan a specific group only"""
        if group_id < 0 or group_id >= len(self.subnet_groups):
            self.logger.error(f"Invalid group ID: {group_id}")
            return {}
        
        group = self.subnet_groups[group_id]
        self.logger.info(f"Starting scan for group {group_id}: {group['name']}")
        
        start_time = time.time()
        group_results = {}
        
        # Scan all subnets in this group
        for subnet in group['subnets']:
            if not self.is_scanning or not self.running:
                self.logger.info("Group scan interrupted by user")
                break
            self.logger.debug(f"Scanning subnet: {subnet}")
            hosts = self.scan_subnet(subnet)
            group_results[subnet] = hosts
        
        # Update global results (thread-safe)
        with self._results_lock:
            self.results.update(group_results)
        
        # Update active hosts for this group (thread-safe)
        with self._active_hosts_lock:
            for subnet, hosts in group_results.items():
                for host in hosts:
                    if host not in self.active_hosts:
                        self.active_hosts.append(host)
        
        end_time = time.time()
        self.logger.info(f"Group {group_id} scan completed in {end_time - start_time:.2f}s")
        return group_results

    # ==================== DISPLAY FUNCTIONS ====================

    def clear_screen(self):
        """Clear the screen"""
        print("\033[2J\033[H", end="")
        sys.stdout.flush()

    def get_mode_display(self):
        """Get current mode display string"""
        if self.scan_mode == 'ping':
            return f'{Colors.GREEN}PING{Colors.RESET}'
        elif self.scan_mode == 'tcp':
            return f'{Colors.YELLOW}TCP:{self.tcp_port}{Colors.RESET}'
        elif self.scan_mode == 'nmap':
            return f'{Colors.CYAN}NMAP{Colors.RESET}'
        return self.scan_mode

    def display_config_panel(self, terminal_width):
        """Display configuration panel at top of screen"""
        print(f"{Colors.BOLD}{'='*terminal_width}{Colors.RESET}")
        print(f"{Colors.BOLD}  CONFIGURATION{Colors.RESET}")
        print(f"{Colors.GRAY}{'-'*terminal_width}{Colors.RESET}")
        
        # Compact layout - tighter spacing (2 spaces between items)
        mode_str = f"{Colors.BOLD}{self.scan_mode.upper()}{Colors.RESET}"
        if self.scan_mode == 'tcp':
            mode_str += f" ({Colors.YELLOW}{self.tcp_port}{Colors.RESET})"
        
        print(f"  {Colors.CYAN}[A]{Colors.RESET} Network: {self.ip_prefix}  " +
              f"{Colors.CYAN}[B]{Colors.RESET} Subnet: {self.start_subnet}-{self.end_subnet}  " +
              f"{Colors.CYAN}[C]{Colors.RESET} IP Range: {self.scan_ip_start}-{self.scan_ip_end}")
        print(f"  {Colors.CYAN}[D]{Colors.RESET} Refresh: {self.refresh_interval}s  " +
              f"{Colors.CYAN}[E]{Colors.RESET} Subnets/Group: {self.subnets_per_group}  " +
              f"{Colors.CYAN}[F]{Colors.RESET} Mode: {mode_str}")
        print(f"  {Colors.CYAN}[G]{Colors.RESET} Display: {self.display_refresh_rate}s  " +
              f"{Colors.CYAN}[H]{Colors.RESET} Attempts: {self.retry_count + 1}  " +
              f"{Colors.GRAY}(1 initial + {self.retry_count} retries){Colors.RESET}")
        
        print(f"{Colors.GRAY}{'-'*terminal_width}{Colors.RESET}")
        print(f"  {Colors.CYAN}[a-h]{Colors.RESET} Settings | {Colors.CYAN}[m]{Colors.RESET} Change Mode | {Colors.CYAN}[r]{Colors.RESET} Scan | {Colors.CYAN}[c]{Colors.RESET} Cancel | {Colors.CYAN}[q]{Colors.RESET} Quit")
        print(f"{Colors.GRAY}{'='*terminal_width}{Colors.RESET}")

    def display_summary_view(self, input_buffer=""):
        """Display the main summary view"""
        self.clear_screen()
        
        try:
            terminal_width = os.get_terminal_size().columns
        except Exception:
            terminal_width = 120

        # Top: Configuration panel
        self.display_config_panel(terminal_width)
        
        # Status line with last scan duration
        duration_str = f"{self.last_scan_duration:.1f}s" if self.last_scan_duration else "--"
        print(f"Last Updated: {Colors.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}  |  Groups: {len(self.subnet_groups)}  |  Last Scan: {Colors.CYAN}{duration_str}{Colors.RESET}  |  Mode: {self.get_mode_display()}")

        # Scan progress
        if self.is_scanning:
            progress_bar_len = 40
            filled_len = int(progress_bar_len * self.scan_progress / 100)
            bar = f'{Colors.GREEN}{"█" * filled_len}{Colors.RESET}{Colors.GRAY}{"░" * (progress_bar_len - filled_len)}{Colors.RESET}'
            print(f"Status: {Colors.GREEN}SCANNING{Colors.RESET} [{bar}] {Colors.BOLD}{self.scan_progress}%{Colors.RESET} ({self.scan_current}/{self.scan_total})")
        elif self.last_scan_time and self.auto_scan_enabled:
            elapsed = (datetime.now() - self.last_scan_time).total_seconds()
            progress = min(elapsed / self.refresh_interval, 1.0)
            progress_bar_len = 40
            filled_len = int(progress_bar_len * progress)
            bar = f'{Colors.BLUE}{"▓" * filled_len}{Colors.RESET}{Colors.GRAY}{"░" * (progress_bar_len - filled_len)}{Colors.RESET}'
            remaining = max(0, int(self.refresh_interval - elapsed))
            print(f"Status: {Colors.BLUE}WAITING{Colors.RESET} [{bar}] Next in {Colors.BOLD}{remaining}s{Colors.RESET}")
        else:
            print(f"Status: {Colors.GRAY}IDLE{Colors.RESET}")

        if self.scan_mode == 'nmap' and not self.nmap_available:
            print(f"{Colors.RED}WARNING: Nmap not found! Press 'm' to switch mode.{Colors.RESET}")

        # Subnet groups display - 8 groups per row
        print(f"\n{Colors.BOLD}{'='*terminal_width}{Colors.RESET}")
        print(f"{Colors.BOLD}  SUBNET MONITOR{Colors.RESET}")
        print(f"{Colors.GRAY}{'-'*terminal_width}{Colors.RESET}")

        groups_per_row = 8  # Fixed: 8 groups per row
        group_box_width = (terminal_width - 20) // groups_per_row  # Calculate box width
        group_box_width = max(10, min(group_box_width, 14))  # Constrain width
        num_groups = len(self.subnet_groups)
        num_rows = math.ceil(num_groups / groups_per_row)

        for row in range(num_rows):
            name_parts = []
            range_parts = []
            count_parts = []

            for col in range(groups_per_row):
                group_idx = row * groups_per_row + col
                if group_idx < num_groups:
                    group = self.subnet_groups[group_idx]
                    total_active = sum(len(self.results.get(subnet, [])) for subnet in group['subnets'])

                    name = group['name']
                    if group['subnets']:
                        subnets = group['subnets']
                        first_third = subnets[0].split('.')[2]
                        last_third = subnets[-1].split('.')[2]
                        ip_range = f"({first_third}-{last_third})"
                    else:
                        ip_range = "(-)"

                    # Color code based on active hosts - center the number
                    count_plain = str(total_active).center(group_box_width)
                    if total_active > 0:
                        count_str = f"{Colors.GREEN}{count_plain}{Colors.RESET}"
                    else:
                        count_str = f"{Colors.GRAY}{count_plain}{Colors.RESET}"

                    name_parts.append(name.center(group_box_width))
                    range_parts.append(ip_range.center(group_box_width))
                    count_parts.append(count_str)
                else:
                    name_parts.append("".center(group_box_width))
                    range_parts.append("".center(group_box_width))
                    count_parts.append("".center(group_box_width))

            print("│".join(name_parts))
            print("│".join(range_parts))
            print("│".join(count_parts))
            print(f"{Colors.GRAY}{'─' * terminal_width}{Colors.RESET}")

        # Input prompt - simple, no duplicate shortcuts
        print(f"\n{Colors.BOLD}{'='*terminal_width}{Colors.RESET}")
        if input_buffer:
            print(f">>> Group: {Colors.YELLOW}{input_buffer}{Colors.RESET} (Enter to view)")
        else:
            num_groups = len(self.subnet_groups)
            print(f">>> Enter group number (1-{num_groups}) and press Enter")

    def display_group_detail(self, group_idx, input_buffer=""):
        """Display detailed view for a specific group - 2 subnets per row"""
        self.clear_screen()
        group = self.subnet_groups[group_idx]
        
        try:
            terminal_width = os.get_terminal_size().columns
        except Exception:
            terminal_width = 120

        # Config panel
        self.display_config_panel(terminal_width)
        
        # Status line with scan progress and last scan duration (same as summary view)
        duration_str = f"{self.last_scan_duration:.1f}s" if self.last_scan_duration else "--"
        print(f"Last Updated: {Colors.CYAN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}  |  Groups: {len(self.subnet_groups)}  |  Last Scan: {Colors.CYAN}{duration_str}{Colors.RESET}  |  Mode: {self.get_mode_display()}")

        # Scan progress bar
        if self.is_scanning:
            progress_bar_len = 40
            filled_len = int(progress_bar_len * self.scan_progress / 100)
            bar = f'{Colors.GREEN}{"█" * filled_len}{Colors.RESET}{Colors.GRAY}{"░" * (progress_bar_len - filled_len)}{Colors.RESET}'
            print(f"Status: {Colors.GREEN}SCANNING{Colors.RESET} [{bar}] {Colors.BOLD}{self.scan_progress}%{Colors.RESET} ({self.scan_current}/{self.scan_total})")
        elif self.last_scan_time and self.auto_scan_enabled:
            elapsed = (datetime.now() - self.last_scan_time).total_seconds()
            progress = min(elapsed / self.refresh_interval, 1.0)
            progress_bar_len = 40
            filled_len = int(progress_bar_len * progress)
            bar = f'{Colors.BLUE}{"▓" * filled_len}{Colors.RESET}{Colors.GRAY}{"░" * (progress_bar_len - filled_len)}{Colors.RESET}'
            remaining = max(0, int(self.refresh_interval - elapsed))
            print(f"Status: {Colors.BLUE}WAITING{Colors.RESET} [{bar}] Next in {Colors.BOLD}{remaining}s{Colors.RESET}")
        else:
            print(f"Status: {Colors.GRAY}IDLE{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{'='*terminal_width}{Colors.RESET}")
        print(f"{Colors.BOLD}GROUP {group_idx + 1} DETAIL VIEW [{self.get_mode_display()}]{Colors.RESET}")
        print(f"{Colors.GRAY}{'-'*terminal_width}{Colors.RESET}")
        print(f"Subnets: {Colors.CYAN}{', '.join(group['subnets'])}{Colors.RESET}")
        print(f"{Colors.GRAY}{'='*terminal_width}{Colors.RESET}")

        # Display subnets with adaptive layout based on count
        subnets = group['subnets']
        num_subnets = len(subnets)
        
        # Determine subnets per row for 2-row layout
        # Even count: split evenly (e.g., 8 → 4+4)
        # Odd count: first row has one more (e.g., 9 → 5+4)
        # Always aim for 2 rows maximum
        if num_subnets <= 2:
            subnets_per_row = 2  # 1-2 subnets → 1 row
        elif num_subnets <= 4:
            subnets_per_row = 2  # 3-4 subnets → 2 rows of 2
        elif num_subnets <= 6:
            subnets_per_row = 3  # 5-6 subnets → 2 rows of 3
        elif num_subnets <= 8:
            subnets_per_row = 4  # 7-8 subnets → 2 rows of 4
        elif num_subnets <= 10:
            subnets_per_row = 5  # 9-10 subnets → 2 rows of 5 (9 = 5+4)
        else:
            subnets_per_row = 6  # 11-12 subnets → 2 rows of 6 (11 = 6+5)
        
        # Fixed: 10 IPs per row for detail view (reduces vertical space)
        hosts_per_row = 10
        # Each IP takes 3 chars + 1 space separator, but last IP has no trailing space
        # So total width = hosts_per_row * 3 + (hosts_per_row - 1) = hosts_per_row * 4 - 1
        subnet_width = hosts_per_row * 4 - 1  # 39 chars for 10 IPs
        
        # Build all output first to reduce flicker
        output_lines = []
        
        for row_start in range(0, num_subnets, subnets_per_row):
            row_subnets = subnets[row_start:row_start + subnets_per_row]
            
            # Build grids for all subnets in this row with SAME hosts_per_row
            grids = [self._build_subnet_grid_fixed(s, subnet_width, hosts_per_row) for s in row_subnets]
            
            # Merge line by line with separators
            max_lines = max(len(g) for g in grids) if grids else 0
            for i in range(max_lines):
                line_parts = []
                for j, grid in enumerate(grids):
                    if i < len(grid):
                        line_parts.append(grid[i])
                    else:
                        line_parts.append(' ' * subnet_width)
                
                # Join with separators
                separator = f" {Colors.GRAY}║{Colors.RESET} "
                output_lines.append(separator.join(line_parts))
            
            # Add separator between rows (but not after last row)
            if row_start + subnets_per_row < num_subnets:
                output_lines.append(f"{Colors.GRAY}{'─' * terminal_width}{Colors.RESET}")
        
        # Print all at once
        print('\n'.join(output_lines))

        print(f"\n{Colors.GRAY}{'='*terminal_width}{Colors.RESET}")
        # Simple shortcut bar for detail view
        print(f">>> {Colors.CYAN}[s]{Colors.RESET} Summary | {Colors.CYAN}[q]{Colors.RESET} Quit")
        if input_buffer:
            print(f">>> Input: {Colors.YELLOW}{input_buffer}{Colors.RESET}")
    
    def _build_subnet_grid(self, subnet, available_width):
        """Build IP grid for a single subnet, return list of lines"""
        if not subnet:
            return []
        
        lines = []
        active_hosts = self.results.get(subnet, [])
        active_set = set(active_hosts)
        
        # Get subnet base
        subnet_base = subnet.split('/')[0]
        base_parts = subnet_base.split('.')
        base_prefix = '.'.join(base_parts[:3])
        
        # Fixed: 10 IPs per row for consistency
        hosts_per_row = 10
        # Width = hosts_per_row * 4 - 1 (39 chars for 10 IPs)
        grid_width = hosts_per_row * 4 - 1
        
        # Build IP grid first
        ip_rows = []
        row_chars = []
        for i in range(self.scan_ip_start, self.scan_ip_end + 1):
            full_ip = f"{base_prefix}.{i}"
            last_octet = str(i)
            if full_ip in active_set:
                row_chars.append(f"{Colors.GREEN}{last_octet:>3}{Colors.RESET}")
            else:
                row_chars.append(f"{Colors.GRAY}{last_octet:>3}{Colors.RESET}")
            
            # End of row
            if len(row_chars) >= hosts_per_row:
                ip_rows.append(' '.join(row_chars))
                row_chars = []
        
        # Handle partial last row
        if row_chars:
            ip_rows.append(' '.join(row_chars))
        
        # Header line - centered above the grid
        header_text = f"{subnet} [{len(active_hosts)}]"
        # Calculate visual width (excluding ANSI codes)
        header_len = len(header_text)
        left_pad = (grid_width - header_len) // 2
        right_pad = grid_width - header_len - left_pad
        header = ' ' * left_pad + f"{Colors.BOLD}{header_text}{Colors.RESET}" + ' ' * right_pad
        lines.append(header)
        
        # Add IP rows
        lines.extend(ip_rows)
        
        return lines
    
    def _build_subnet_grid_fixed(self, subnet, grid_width, hosts_per_row):
        """Build IP grid with fixed hosts_per_row for consistent alignment"""
        if not subnet:
            return []
        
        lines = []
        active_hosts = self.results.get(subnet, [])
        active_set = set(active_hosts)
        
        # Get subnet base
        subnet_base = subnet.split('/')[0]
        base_parts = subnet_base.split('.')
        base_prefix = '.'.join(base_parts[:3])
        
        # Build IP grid first
        ip_rows = []
        row_chars = []
        for i in range(self.scan_ip_start, self.scan_ip_end + 1):
            full_ip = f"{base_prefix}.{i}"
            last_octet = str(i)
            if full_ip in active_set:
                row_chars.append(f"{Colors.GREEN}{last_octet:>3}{Colors.RESET}")
            else:
                row_chars.append(f"{Colors.GRAY}{last_octet:>3}{Colors.RESET}")
            
            # End of row
            if len(row_chars) >= hosts_per_row:
                ip_rows.append(' '.join(row_chars))
                row_chars = []
        
        # Handle partial last row - pad with spaces to match full row width
        if row_chars:
            # Pad partial row to full width for alignment
            while len(row_chars) < hosts_per_row:
                row_chars.append('   ')  # 3 spaces
            ip_rows.append(' '.join(row_chars))
        
        # Header line - centered above the grid
        # Note: grid_width = hosts_per_row * 4 - 1 (e.g., 39 for 10 IPs)
        header_text = f"{subnet} [{len(active_hosts)}]"
        header_len = len(header_text)
        left_pad = (grid_width - header_len) // 2
        right_pad = grid_width - header_len - left_pad
        header = ' ' * left_pad + f"{Colors.BOLD}{header_text}{Colors.RESET}" + ' ' * right_pad
        lines.append(header)
        
        # Add IP rows
        lines.extend(ip_rows)
        
        return lines

    def display_mode_select(self):
        """Display mode selection menu"""
        try:
            terminal_width = os.get_terminal_size().columns
        except Exception:
            terminal_width = 80
        
        self.clear_screen()
        print(f"{Colors.BOLD}{'='*terminal_width}{Colors.RESET}")
        print(f"{Colors.BOLD}SELECT SCAN MODE{Colors.RESET}")
        print(f"{Colors.GRAY}{'-'*terminal_width}{Colors.RESET}\n")
        print(f"  {Colors.GREEN}[P]{Colors.RESET} PING  - Fast async ping sweep (recommended)")
        print(f"  {Colors.YELLOW}[T]{Colors.RESET} TCP   - Single port scan")
        print(f"  {Colors.CYAN}[N]{Colors.RESET} NMAP  - Use nmap (requires nmap installed)")
        print(f"\nCurrent mode: {Colors.BOLD}{self.scan_mode.upper()}{Colors.RESET}")
        if self.scan_mode == 'tcp':
            print(f"TCP Port: {Colors.YELLOW}{self.tcp_port}{Colors.RESET}")
        if self.scan_mode == 'nmap' and not self.nmap_available:
            print(f"{Colors.RED}WARNING: Nmap is not installed!{Colors.RESET}")
        print(f"\n{Colors.GRAY}{'-'*terminal_width}{Colors.RESET}")

    def change_scan_mode(self):
        """Change scan mode"""
        self.display_mode_select()
        while True:
            try:
                choice = input("Mode [p/t/n]: ").strip().lower()
                if choice in ['p', 'ping']:
                    self.scan_mode = 'ping'
                    break
                elif choice in ['t', 'tcp']:
                    self.scan_mode = 'tcp'
                    self.select_tcp_port()
                    break
                elif choice in ['n', 'nmap']:
                    if self.nmap_available:
                        self.scan_mode = 'nmap'
                        break
                    else:
                        print(f"{Colors.RED}Nmap is not installed. Choose another mode.{Colors.RESET}")
                elif choice == '':
                    break
                else:
                    print(f"{Colors.RED}Invalid choice. Enter p, t, or n.{Colors.RESET}")
            except (KeyboardInterrupt, EOFError):
                break
        self.logger.info(f"Scan mode changed to: {self.scan_mode}")

    def select_tcp_port(self):
        """Select TCP port for scanning"""
        print(f"\n{Colors.BOLD}SELECT TCP PORT{Colors.RESET}")
        print(f"{Colors.GRAY}{'-'*60}{Colors.RESET}")
        ports = list(self.TCP_PORTS_AVAILABLE.keys())
        for i, port in enumerate(ports, 1):
            desc = {
                '22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '445': 'SMB',
                '3389': 'RDP', '8080': 'HTTP-Alt', '139': 'NetBIOS', '53': 'DNS'
            }
            marker = " <- current" if str(self.tcp_port) == port else ""
            print(f"  [{i}] Port {port:<5} ({desc.get(port, '')}){marker}")
        print(f"{Colors.GRAY}{'-'*60}{Colors.RESET}")
        
        while True:
            try:
                choice = input(f"Select port [1-{len(ports)}] or Enter for current ({self.tcp_port}): ").strip()
                if choice == '':
                    break
                if choice.isdigit() and 1 <= int(choice) <= len(ports):
                    self.tcp_port = int(ports[int(choice) - 1])
                    self.tcp_ports = [self.tcp_port]
                    print(f"{Colors.GREEN}TCP port set to {self.tcp_port}{Colors.RESET}")
                    break
                else:
                    print(f"{Colors.RED}Invalid choice.{Colors.RESET}")
            except (KeyboardInterrupt, EOFError):
                break

    def update_setting(self, setting_key):
        """Update a specific setting by letter key"""
        setting_key = setting_key.lower()
        try:
            if setting_key == 'a':
                new_val = input(f"\nNetwork prefix (current: {self.ip_prefix}): ").strip()
                if new_val:
                    parts = new_val.split('.')
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        if 0 <= int(parts[0]) <= 255 and 0 <= int(parts[1]) <= 255:
                            self.ip_prefix = f"{parts[0]}.{parts[1]}"
                            self._recalculate_subnets()
                            print(f"{Colors.GREEN}Network prefix updated to {self.ip_prefix}{Colors.RESET}")
                        else:
                            print(f"{Colors.RED}Invalid values. Must be 0-255.0-255.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Invalid format. Use X.Y format (e.g., 10.100).{Colors.RESET}")
            elif setting_key == 'b':
                new_val = input(f"Subnet range (current: {self.start_subnet}-{self.end_subnet}): ").strip()
                if '-' in new_val:
                    parts = new_val.split('-')
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        start, end = int(parts[0]), int(parts[1])
                        if 0 <= start <= 255 and 0 <= end <= 255:
                            self.start_subnet = min(start, end)
                            self.end_subnet = max(start, end)
                            self._recalculate_subnets()
                            print(f"{Colors.GREEN}Subnet range updated to {self.start_subnet}-{self.end_subnet}{Colors.RESET}")
                        else:
                            print(f"{Colors.RED}Invalid value. Must be 0-255.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Invalid format. Use start-end format.{Colors.RESET}")
                elif new_val.isdigit():
                    print(f"{Colors.RED}Use start-end format (e.g., 64-171).{Colors.RESET}")
            elif setting_key == 'c':
                new_val = input(f"IP scan range (current: {self.scan_ip_start}-{self.scan_ip_end}): ").strip()
                if '-' in new_val:
                    parts = new_val.split('-')
                    if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                        start, end = int(parts[0]), int(parts[1])
                        if 1 <= start <= 254 and 1 <= end <= 254:
                            self.scan_ip_start = min(start, end)
                            self.scan_ip_end = max(start, end)
                            print(f"{Colors.GREEN}IP range updated to {self.scan_ip_start}-{self.scan_ip_end}{Colors.RESET}")
                        else:
                            print(f"{Colors.RED}Invalid value. Must be 1-254.{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Invalid format. Use start-end format.{Colors.RESET}")
            elif setting_key == 'd':
                new_val = input(f"Refresh interval (current: {self.refresh_interval}s, min 5): ").strip()
                if new_val.isdigit() and int(new_val) >= 5:
                    self.refresh_interval = int(new_val)
                    print(f"{Colors.GREEN}Refresh interval updated to {self.refresh_interval}s{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Invalid value. Must be >= 5 seconds.{Colors.RESET}")
            elif setting_key == 'e':
                new_val = input(f"Subnets per group (current: {self.subnets_per_group}, 1-12): ").strip()
                if new_val.isdigit() and 1 <= int(new_val) <= 12:
                    self.subnets_per_group = int(new_val)
                    self._recalculate_subnets()
                    print(f"{Colors.GREEN}Subnets per group updated to {self.subnets_per_group} ({len(self.subnet_groups)} groups total){Colors.RESET}")
                else:
                    print(f"{Colors.RED}Invalid value. Must be 1-12.{Colors.RESET}")
            elif setting_key == 'f':
                # [F] shows current mode, use [M] to change it
                print(f"\n{Colors.YELLOW}Current mode: {self.scan_mode.upper()}" +
                      (f" (Port: {self.tcp_port})" if self.scan_mode == 'tcp' else "") +
                      f". Press {Colors.CYAN}[M]{Colors.RESET} to change mode.{Colors.RESET}")
                time.sleep(1)
                return
            elif setting_key == 'g':
                new_val = input(f"Display refresh rate (current: {self.display_refresh_rate}s, 1-10): ").strip()
                try:
                    val = float(new_val)
                    if 1 <= val <= 10:
                        self.display_refresh_rate = val
                        print(f"{Colors.GREEN}Display refresh rate updated to {self.display_refresh_rate}s{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}Invalid value. Must be 1-10 seconds.{Colors.RESET}")
                except ValueError:
                    print(f"{Colors.RED}Invalid value. Must be a number.{Colors.RESET}")
            elif setting_key == 'h':
                new_val = input(f"Scan attempts (current: {self.retry_count + 1}, 1-6): ").strip()
                # User enters total attempts (1-6), convert to retry_count (0-5)
                if new_val.isdigit() and 1 <= int(new_val) <= 6:
                    self.retry_count = int(new_val) - 1
                    print(f"{Colors.GREEN}Scan attempts updated to {int(new_val)} (1 initial + {self.retry_count} retries){Colors.RESET}")
                else:
                    print(f"{Colors.RED}Invalid value. Must be 1-6.{Colors.RESET}")
            else:
                print(f"{Colors.RED}Invalid setting key. Use a-h.{Colors.RESET}")
        except (ValueError, EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}Cancelled.{Colors.RESET}")
        time.sleep(0.5)

    def _recalculate_subnets(self):
        """Recalculate subnets based on current settings"""
        if self.start_subnet > self.end_subnet:
            self.start_subnet, self.end_subnet = self.end_subnet, self.start_subnet

        self.subnets = [f'{self.ip_prefix}.{i}.0/24' for i in range(self.start_subnet, self.end_subnet + 1)]
        self.subnet_groups = {}
        for i, subnet in enumerate(self.subnets):
            group_idx = i // self.subnets_per_group
            if group_idx not in self.subnet_groups:
                start_ip = self.start_subnet + group_idx * self.subnets_per_group
                end_ip = start_ip + self.subnets_per_group - 1
                self.subnet_groups[group_idx] = {'name': f'G{group_idx+1}', 'subnets': []}
            self.subnet_groups[group_idx]['subnets'].append(subnet)

        for subnet in self.subnets:
            if subnet not in self.results:
                self.results[subnet] = []

        self.logger.info(f"Subnets recalculated: {self.ip_prefix}.{self.start_subnet}-{self.end_subnet}.0/24, {self.subnets_per_group} per group, total {len(self.subnet_groups)} groups")

    # ==================== MAIN LOOP ====================

    def run_realtime_monitor(self):
        """Run the real-time monitor with interactive controls"""
        self.logger.info("Starting real-time monitor...")

        for subnet in self.subnets:
            self.results[subnet] = []

        input_buffer = ""
        current_view = "summary"
        detail_group_idx = 0
        last_scan_was_triggered = False

        # Separate tracking for content refresh (5s) and progress bar refresh (high frequency)
        last_content_refresh_time = 0
        last_displayed_progress = -1
        last_displayed_countdown = -1
        last_displayed_view = None
        last_displayed_scanning = None
        last_displayed_duration = None

        while self.running:
            current_scanning = self.is_scanning
            current_progress = self.scan_progress
            current_time = time.time()

            current_countdown = 0
            if self.last_scan_time and self.auto_scan_enabled and not self.is_scanning:
                elapsed = (datetime.now() - self.last_scan_time).total_seconds()
                current_countdown = max(0, int(self.refresh_interval - elapsed))

            # Determine what needs refresh
            view_changed = (current_view != last_displayed_view)
            scanning_changed = (current_scanning != last_displayed_scanning)
            scan_just_finished = (last_displayed_scanning and not current_scanning)  # Scan completed
            progress_changed = (current_scanning and current_progress != last_displayed_progress)
            countdown_changed = (not current_scanning and current_countdown != last_displayed_countdown)
            duration_changed = (self.last_scan_duration != last_displayed_duration and self.last_scan_duration is not None)
            
            # Content refresh: every 5 seconds or on state change
            content_refresh_needed = (current_time - last_content_refresh_time >= self.display_refresh_rate)
            
            # Progress bar refresh: high frequency during scanning
            progress_refresh_needed = progress_changed or countdown_changed
            
            # Full display refresh conditions
            # Important: scan_just_finished forces refresh to show results
            needs_full_refresh = (view_changed or scanning_changed or scan_just_finished or duration_changed or content_refresh_needed)
            
            # Update tracking variables
            if view_changed or scanning_changed:
                last_displayed_view = current_view
                last_displayed_scanning = current_scanning
                last_displayed_progress = current_progress
                last_displayed_countdown = current_countdown
                last_displayed_duration = self.last_scan_duration
            elif current_scanning and progress_changed:
                last_displayed_progress = current_progress
            elif not current_scanning and countdown_changed:
                last_displayed_countdown = current_countdown
            
            if duration_changed:
                last_displayed_duration = self.last_scan_duration

            # Display based on current view
            if needs_full_refresh:
                if current_view == "summary":
                    self.display_summary_view(input_buffer)
                elif current_view == "detail":
                    self.display_group_detail(detail_group_idx, input_buffer)
                last_content_refresh_time = current_time

            # Quick key poll loop for responsive input
            key = get_key_press(0.02)
            key_pressed = False
            
            while key and not key_pressed:
                key_byte = key if isinstance(key, bytes) else key.encode() if isinstance(key, str) else key
                is_enter = key_byte in [b'\r', b'\n']
                key_char = key_byte.decode('utf-8', errors='ignore').lower() if isinstance(key_byte, bytes) else key_byte.lower()
                key_pressed = True

                if key_char == 'c' and self.is_scanning:
                    self.is_scanning = False
                    self.logger.info("Scan cancelled by user")
                    print(f"\n{Colors.YELLOW}Scan cancelled.{Colors.RESET}")
                    time.sleep(0.3)
                    last_content_refresh_time = 0  # Force refresh
                    continue

                if is_enter:
                    if current_view == "summary" and input_buffer.isdigit():
                        group_num = int(input_buffer)
                        if 1 <= group_num <= len(self.subnet_groups):
                            current_view = "detail"
                            detail_group_idx = group_num - 1
                            last_content_refresh_time = 0  # Force refresh
                    elif current_view == "detail":
                        # Enter in detail view does nothing, just clear buffer
                        pass
                    input_buffer = ""
                elif key_byte in [b'\b', b'\x7f']:
                    if input_buffer:
                        input_buffer = input_buffer[:-1]
                        last_content_refresh_time = 0  # Force refresh
                elif key_char == 'q':
                    self.is_scanning = False
                    self.running = False
                    continue
                elif key_char == 'r':
                    # Manual scan trigger - behavior differs by view
                    if not self.is_scanning:
                        if current_view == "detail":
                            # Scan only current group in detail view
                            scan_thread = threading.Thread(target=self.scan_group, args=(detail_group_idx,))
                            print(f"\n{Colors.GREEN}Scanning group {detail_group_idx + 1}...{Colors.RESET}")
                        else:
                            # Scan all subnets in summary view
                            scan_thread = threading.Thread(target=self.scan_all_subnets)
                            print(f"\n{Colors.GREEN}Manual scan started.{Colors.RESET}")
                        scan_thread.start()
                        time.sleep(0.3)
                        last_content_refresh_time = 0  # Force refresh
                elif key_char == 's':
                    # Switch between summary and detail view
                    if current_view == "detail":
                        current_view = "summary"
                        input_buffer = ""
                        last_content_refresh_time = 0  # Force refresh
                elif key_char == 'm':
                    # Change scan mode - available in both views
                    self.is_scanning = False
                    time.sleep(0.1)
                    self.change_scan_mode()
                    scan_thread = threading.Thread(target=self.scan_all_subnets)
                    scan_thread.start()
                    last_content_refresh_time = 0  # Force refresh
                elif key_char in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']:
                    # Settings available in both views
                    self.update_setting(key_char)
                    last_content_refresh_time = 0  # Force refresh after setting change
                elif key_char.isdigit():
                    if current_view == "summary" and len(input_buffer) < 3:
                        input_buffer += key_char
                        last_content_refresh_time = 0  # Force refresh

                # Poll for more keys after handling
                time.sleep(0.02)
                key = get_key_press(0.02)
                if key:
                    key_pressed = False

            # Main loop timing
            # Check for auto-scan interval (no initial scan thread)
            if self.auto_scan_enabled and self.last_scan_time and not self.is_scanning:
                elapsed = (datetime.now() - self.last_scan_time).total_seconds()
                if elapsed >= self.refresh_interval:
                    scan_thread = threading.Thread(target=self.scan_all_subnets)
                    scan_thread.start()

            time.sleep(0.05)

    def save_results_json(self, filename=None):
        """Save results to JSON file with unique identifier"""
        import os
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pid = os.getpid()
            filename = f'realtime_subnet_scan_results_{timestamp}_{pid}.json'
        
        results_data = {
            'timestamp': datetime.now().isoformat(),
            'scan_mode': self.scan_mode,
            'tcp_port': self.tcp_port,
            'ip_prefix': self.ip_prefix,
            'subnet_range': f"{self.start_subnet}-{self.end_subnet}",
            'ip_range': f"{self.scan_ip_start}-{self.scan_ip_end}",
            'subnets': self.subnets,
            'results': {subnet: hosts for subnet, hosts in self.results.items()},
            'total_active_hosts': len(set(self.active_hosts)),
            'process_id': os.getpid(),
            'session_timestamp': datetime.now().isoformat()
        }

        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)

        self.logger.info(f"JSON results saved: {filename}")


def main():
    import os
    parser = argparse.ArgumentParser(description='Real-time Subnet Monitor with multiple scan modes')
    parser.add_argument('--log-file', help='Log file path (default: realtime_subnet_monitor_<PID>.log)')
    parser.add_argument('--refresh-interval', type=int, default=120, help='Refresh interval (default: 120s)')
    parser.add_argument('--json-output', help='JSON output file (default: realtime_subnet_scan_results_<timestamp>_<PID>.json)')
    parser.add_argument('--mode', choices=['ping', 'tcp', 'nmap'], default='ping', help='Scan mode')
    parser.add_argument('--tcp-port', type=int, default=22, help='TCP port for scan (default: 22)')
    parser.add_argument('--ip-prefix', default='192.168', help='Network prefix (default: 192.168)')
    parser.add_argument('--start-subnet', type=int, default=1, help='Starting subnet 3rd octet')
    parser.add_argument('--end-subnet', type=int, default=254, help='Ending subnet 3rd octet')
    parser.add_argument('--scan-ip-start', type=int, default=1, help='Starting IP 4th octet (default: 1)')
    parser.add_argument('--scan-ip-end', type=int, default=254, help='Ending IP 4th octet (default: 254)')
    parser.add_argument('--groups-per-row', '--subnets-per-group', type=int, default=4, dest='subnets_per_group',
                        help='Subnets per group (default: 4, max 12)')
    parser.add_argument('--progress-refresh-rate', type=float, default=1.0, help='Progress refresh rate (s)')
    parser.add_argument('--display-refresh-rate', type=float, default=5.0, help='Display refresh rate for detail view (default: 5.0s)')
    parser.add_argument('--retry-count', type=int, default=2, help='Retry count for unresponsive hosts (default: 2, 0-5)')

    args = parser.parse_args()

    # Set default filenames if not provided
    if args.log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pid = os.getpid()
        args.log_file = f'realtime_subnet_monitor_{pid}.log'
    
    if args.json_output is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pid = os.getpid()
        args.json_output = f'realtime_subnet_scan_results_{timestamp}_{pid}.json'

    monitor = RealtimeSubnetMonitor(
        log_file=args.log_file,
        refresh_interval=args.refresh_interval,
        scan_mode=args.mode,
        tcp_port=args.tcp_port,
        ip_prefix=args.ip_prefix,
        start_subnet=args.start_subnet,
        end_subnet=args.end_subnet,
        scan_ip_start=args.scan_ip_start,
        scan_ip_end=args.scan_ip_end,
        subnets_per_group=args.subnets_per_group,
        progress_refresh_rate=args.progress_refresh_rate,
        display_refresh_rate=args.display_refresh_rate,
        retry_count=args.retry_count
    )

    print(f"{Colors.GREEN}Starting monitor in {args.mode.upper()} mode...{Colors.RESET}")
    print(f"Network: {args.ip_prefix}.{args.start_subnet}-{args.end_subnet}.0/24")
    print(f"IP Range: {args.scan_ip_start}-{args.scan_ip_end}  |  TCP Port: {args.tcp_port}")
    print(f"Log file: {args.log_file}  |  Results: {args.json_output}")
    if args.mode == 'nmap' and not monitor.nmap_available:
        print(f"{Colors.RED}WARNING: Nmap not installed! Using ping mode.{Colors.RESET}")
        monitor.scan_mode = 'ping'

    try:
        monitor.run_realtime_monitor()
    except (KeyboardInterrupt, SystemExit):
        print(f'\n{Colors.YELLOW}Shutting down...{Colors.RESET}')
    finally:
        monitor.save_results_json(args.json_output)
        print(f"{Colors.GREEN}Results saved to {args.json_output}{Colors.RESET}")


if __name__ == '__main__':
    main()
