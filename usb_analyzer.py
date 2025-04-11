#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import json
import logging
import signal
from logging.handlers import RotatingFileHandler
import getpass
import platform
import subprocess
from typing import Dict, Set, List, Tuple, Optional, Any
from dataclasses import dataclass
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pywinusb.hid as hid  # Windows USB detection
import wmi  # Windows drive mapping
import usb.core  # Linux USB detection
import psutil  # Performance monitoring
import gpgme  # File encryption
import requests  # For VirusTotal API integration
import ctypes  # For admin rights check
import win32com.client  # For WMI events
import win32security  # For Windows security
import win32api  # For Windows API
import win32con  # For Windows constants
import re
from datetime import datetime
from pathlib import Path
import gnupg
import win32service
import win32serviceutil
import win32event
import servicemanager
import socket

# Check for admin rights on Windows
if platform.system() == "Windows" and not ctypes.windll.shell32.IsUserAnAdmin():
    print("Admin rights required!")
    sys.exit(1)

@dataclass
class Config:
    """Configuration settings for USB Analyzer"""
    LOG_DIR: str = os.environ.get("LOG_DIR", "C:\\USBLogs" if platform.system() == "Windows" else "/var/log/usb_threat")
    QUARANTINE_DIR: str = os.path.join(LOG_DIR, "quarantine")
    WHITELIST_FILE: str = os.path.join(LOG_DIR, "whitelist.txt")
    CURRENT_LOG: str = os.path.join(LOG_DIR, "current_usb.log")
    PREV_LOG: str = os.path.join(LOG_DIR, "prev_usb.log")
    DIFF_LOG: str = os.path.join(LOG_DIR, "diff_usb.log")
    ALERT_LOG: str = os.path.join(LOG_DIR, "alert.log")
    VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")
    MAX_CPU: float = 5.0  # Percent
    MAX_MEMORY: int = 50 * 1024 * 1024  # 50MB in bytes
    LARGE_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    EVENT_WINDOW: int = 5  # Seconds
    EVENT_THRESHOLD: int = 10  # Files per window
    VIRUSTOTAL_RATE_LIMIT: int = 4  # Requests per minute
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    CHUNK_SIZE: int = 4096  # For file reading
    RETRY_ATTEMPTS: int = 3
    RETRY_DELAY: int = 1  # Seconds

    def __post_init__(self):
        """Create necessary directories after initialization"""
        os.makedirs(self.LOG_DIR, exist_ok=True)
        os.makedirs(self.QUARANTINE_DIR, exist_ok=True)

# Initialize configuration
config = Config()

# Setup logging
os.makedirs(config.LOG_DIR, exist_ok=True)
os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
logger = logging.getLogger("USBAnalyzer")
logger.setLevel(logging.INFO)
formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "device": "%(device)s"}')
handler = RotatingFileHandler(config.ALERT_LOG, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUP_COUNT)
handler.setFormatter(formatter)
logger.addHandler(handler)

class VirusTotal:
    """VirusTotal API client with rate limiting and caching"""
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_request_time = 0
        self.cache: Dict[str, Tuple[Any, float]] = {}  # {hash: (result, timestamp)}
        self.cache_duration = 3600  # 1 hour cache

    def _rate_limit(self) -> None:
        """Implement rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < (60.0 / config.VIRUSTOTAL_RATE_LIMIT):
            time.sleep((60.0 / config.VIRUSTOTAL_RATE_LIMIT) - time_since_last)
        self.last_request_time = time.time()

    def _check_cache(self, file_hash: str) -> Optional[Dict]:
        """Check if result is in cache and not expired"""
        if file_hash in self.cache:
            result, timestamp = self.cache[file_hash]
            if time.time() - timestamp < self.cache_duration:
                return result
        return None

    def _update_cache(self, file_hash: str, result: Dict) -> None:
        """Update cache with new result"""
        self.cache[file_hash] = (result, time.time())

    def request(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make API request with retries and error handling"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return None

        headers = {"x-apikey": self.api_key}
        
        for attempt in range(config.RETRY_ATTEMPTS):
            try:
                self._rate_limit()
                response = requests.get(
                    f"{self.base_url}/{endpoint}",
                    headers=headers,
                    params=params,
                    timeout=10
                )
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"VirusTotal API error (attempt {attempt + 1}/{config.RETRY_ATTEMPTS}): {e}")
                if attempt < config.RETRY_ATTEMPTS - 1:
                    time.sleep(config.RETRY_DELAY * (attempt + 1))
                else:
                    return None

    def check_file(self, file_hash: str) -> Optional[Dict]:
        """Check file hash against VirusTotal with caching"""
        # Check cache first
        cached_result = self._check_cache(file_hash)
        if cached_result:
            return cached_result

        # Make API request
        result = self.request("files", params={"query": file_hash})
        if result:
            self._update_cache(file_hash, result)
        return result

# Dependency check
def check_dependencies():
    required_tools = ["lsblk", "diff"] if platform.system() != "Windows" else ["fc"]
    for tool in required_tools:
        if subprocess.run(f"which {tool}" if platform.system() != "Windows" else f"where {tool}", shell=True, stdout=subprocess.PIPE).returncode != 0:
            logger.error(f"Required tool '{tool}' is not installed.")
            sys.exit(1)

    # Check for required Python libraries
    try:
        import pywinusb.hid
        import wmi
        import usb.core
        import psutil
        import gpgme
    except ImportError as e:
        logger.error(f"Missing required Python library: {e}")
        sys.exit(1)

check_dependencies()

# Whitelist management
def load_whitelist():
    whitelist = {"vids": set(), "pids": set(), "serials": set(), "dirs": set()}
    if os.path.exists(config.WHITELIST_FILE):
        with open(config.WHITELIST_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("VID_"): whitelist["vids"].add(line)
                elif line.startswith("PID_"): whitelist["pids"].add(line)
                elif line.startswith("SERIAL_"): whitelist["serials"].add(line)
                else: whitelist["dirs"].add(os.path.abspath(line))
    return whitelist

# USB device detection
def get_usb_devices():
    devices = []
    if platform.system() == "Windows":
        all_devices = hid.HidDeviceFilter().get_devices()
        c = wmi.WMI()
        usb_map = {f"VID_{device.vendor_id:04x}:PID_{device.product_id:04x}": None for device in all_devices}
        for disk in c.Win32_LogicalDisk():
            if disk.DriveType == 2:  # Removable drive
                for vid_pid in usb_map:
                    if usb_map[vid_pid] is None:
                        usb_map[vid_pid] = disk.DeviceID + "\\"
                        break
        devices = [(vid_pid, path) for vid_pid, path in usb_map.items() if path]
    else:
        devices_usb = usb.core.find(find_all=True)
        for dev in devices_usb:
            vid_pid = f"VID_{dev.idVendor:04x}:PID_{dev.idProduct:04x}"
            dev_path = None
            for sys_dev in os.listdir("/sys/bus/usb/devices"):
                try:
                    with open(f"/sys/bus/usb/devices/{sys_dev}/idVendor") as f:
                        if f.read().strip() == f"{dev.idVendor:04x}":
                            with open(f"/sys/bus/usb/devices/{sys_dev}/idProduct") as f:
                                if f.read().strip() == f"{dev.idProduct:04x}":
                                    for subdir in os.listdir(f"/sys/bus/usb/devices/{sys_dev}"):
                                        if subdir.startswith("block"):
                                            dev_name = os.listdir(f"/sys/bus/usb/devices/{sys_dev}/{subdir}")[0]
                                            dev_path = f"/dev/{dev_name}"
                                            break
                                    break
                except (IOError, IndexError):
                    continue
            if dev_path:
                devices.append((vid_pid, dev_path))
    return devices

def get_mountpoint(device_info):
    vid_pid, dev_path = device_info
    if platform.system() == "Windows":
        return dev_path
    else:
        try:
            result = subprocess.run(["lsblk", "-o", "MOUNTPOINT", dev_path], capture_output=True, text=True)
            return result.stdout.strip() if result.stdout else None
        except Exception as e:
            logger.error(f"Error getting mountpoint for {dev_path}: {e}")
            return None

# Signal handling for graceful shutdown
def signal_handler(sig, frame):
    logger.info("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class ResourceMonitor:
    """Monitor system resources"""
    @staticmethod
    def check_resources() -> bool:
        """Check if system resources are within limits"""
        process = psutil.Process()
        try:
            cpu_percent = process.cpu_percent()
            memory_info = process.memory_info()
            return cpu_percent <= config.MAX_CPU and memory_info.rss <= config.MAX_MEMORY
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Resource monitoring error: {e}")
            return False

class FileAnalyzer:
    """Handle file analysis operations"""
    def __init__(self, vt: VirusTotal):
        self.vt = vt

    def analyze_file(self, file_path: str) -> bool:
        """Analyze file for threats"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False

            if os.path.getsize(file_path) > config.LARGE_FILE_SIZE:
                logger.warning(f"Large file detected: {file_path}")
                return True

            file_hash = self._compute_hash(file_path)
            response = self.vt.check_file(file_hash)
            
            if response and response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0) > 0:
                logger.warning(f"Threat detected in {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"File analysis error: {e}")
            return False

    def _compute_hash(self, file_path: str) -> str:
        """Compute SHA-256 hash of file"""
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(config.CHUNK_SIZE), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Hash computation error: {e}")
            return ""

class WindowsSecurity:
    """Handle Windows-specific security operations"""
    @staticmethod
    def block_usb_storage() -> bool:
        """Block USB storage via registry"""
        try:
            # Block via registry
            subprocess.run(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f',
                shell=True, check=True, capture_output=True, text=True
            )
            logger.info("USB storage blocked via registry")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block USB storage: {e.stderr}")
            return False

    @staticmethod
    def block_device_access(mountpoint: str) -> bool:
        """Block device access using icacls"""
        try:
            subprocess.run(
                f"icacls {mountpoint} /deny Everyone:(W)",
                shell=True, check=True, capture_output=True, text=True
            )
            logger.info(f"Device access blocked: {mountpoint}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block device access: {e.stderr}")
            return False

class WMIMonitor:
    """Monitor USB events using WMI"""
    def __init__(self):
        self.wmi = win32com.client.GetObject("winmgmts:")
        self.running = True

    def start_monitoring(self):
        """Start monitoring USB events"""
        try:
            # Register for USB device arrival events
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_USBControllerDevice'"
            watcher = self.wmi.ExecNotificationQuery(query)
            
            while self.running:
                try:
                    event = watcher.NextEvent(1000)  # 1 second timeout
                    if event:
                        self._handle_usb_event(event)
                except Exception as e:
                    if "timeout" not in str(e).lower():
                        logger.error(f"WMI event error: {e}")
        except Exception as e:
            logger.error(f"WMI monitoring error: {e}")

    def _handle_usb_event(self, event):
        """Handle USB device event"""
        try:
            device = event.TargetInstance
            vid_pid = f"VID_{device.DeviceID.split('\\')[1]}" if device.DeviceID else "unknown"
            logger.info(f"USB device detected: {vid_pid}")
            
            # Trigger Windows Defender scan
            self._scan_device(device.DeviceID)
        except Exception as e:
            logger.error(f"Error handling USB event: {e}")

    def _scan_device(self, device_id: str):
        """Scan USB device with Windows Defender"""
        try:
            subprocess.run(
                ["powershell", "-Command", f"Start-MpScan -ScanType Custom -ScanPath '{device_id}'"],
                check=True, capture_output=True, text=True
            )
            logger.info(f"Windows Defender scan initiated for device: {device_id}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Windows Defender scan failed: {e.stderr}")

    def stop(self):
        """Stop WMI monitoring"""
        self.running = False

class USBEventHandler(FileSystemEventHandler):
    """Handle USB device events"""
    def __init__(self, mountpoint: str, whitelist: Dict[str, Set[str]]):
        self.mountpoint = mountpoint
        self.whitelist = whitelist
        self.event_count = 0
        self.event_time = time.time()
        self.vt = VirusTotal(config.VIRUSTOTAL_API_KEY)
        self.file_analyzer = FileAnalyzer(self.vt)
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Setup logging for this handler"""
        logging.getLogger().handlers[0].setFormatter(
            logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "device": "' + self.mountpoint + '"}')
        )

    def on_any_event(self, event) -> None:
        """Handle any filesystem event"""
        if event.is_directory or self._is_whitelisted(event.src_path):
            return

        if not ResourceMonitor.check_resources():
            logger.warning("Resource limits exceeded, throttling...")
            time.sleep(1)
            return

        self._check_rapid_file_copy()
        
        if self.file_analyzer.analyze_file(event.src_path):
            self.block_writes()
            self.quarantine_file(event.src_path)

    def _is_whitelisted(self, path: str) -> bool:
        """Check if path is in whitelist"""
        return any(d in path for d in self.whitelist["dirs"])

    def _check_rapid_file_copy(self) -> None:
        """Check for rapid file copy activity"""
        current_time = time.time()
        if current_time - self.event_time <= config.EVENT_WINDOW:
            self.event_count += 1
            if self.event_count >= config.EVENT_THRESHOLD:
                logger.warning("Rapid file copy detected")
                self.block_writes()
        else:
            self.event_count = 1
            self.event_time = current_time

    def block_writes(self) -> None:
        """Block write access to the device"""
        try:
            if platform.system() == "Windows":
                # Block via registry and device access
                if WindowsSecurity.block_usb_storage():
                    WindowsSecurity.block_device_access(self.mountpoint)
            else:
                subprocess.run(f"chmod -w {self.mountpoint}", shell=True, check=True)
                logger.info("Write access blocked")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block writes: {e}")

    def quarantine_file(self, file_path: str) -> bool:
        """Quarantine suspicious file using GPG encryption."""
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False

            # Initialize GPG context
            gpg = gnupg.GPG()
            
            # Check for existing keys
            if not list(gpg.list_keys()):
                logger.error("No GPG keys found in keyring!")
                return False
            
            # Create quarantine directory if it doesn't exist
            quarantine_dir = Path(self.config.quarantine_dir)
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate encrypted filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            encrypted_name = f"{Path(file_path).stem}_{timestamp}.gpg"
            encrypted_path = quarantine_dir / encrypted_name
            
            # Encrypt file
            with open(file_path, 'rb') as f:
                status = gpg.encrypt_file(
                    f,
                    recipients=[self.config.gpg_key_id],
                    output=str(encrypted_path),
                    armor=False
                )
            
            if status.ok:
                logger.info(f"File quarantined: {encrypted_path}")
                # Remove original file
                os.remove(file_path)
                return True
            else:
                logger.error(f"Encryption failed: {status.status}")
                return False
                
        except Exception as e:
            logger.error(f"Error quarantining file: {e}")
            return False

class DeviceManager:
    """Manage USB device detection and monitoring"""
    def __init__(self):
        self.observers: Dict[str, Observer] = {}
        self.whitelist = load_whitelist()

    def get_usb_devices(self) -> List[Dict[str, str]]:
        """Get list of USB devices."""
        devices = []
        if sys.platform == "win32":
            devices = self._get_windows_devices()
        else:
            devices = self._get_linux_devices()
        return devices

    def _get_windows_devices(self) -> List[Dict[str, str]]:
        """Get USB devices on Windows"""
        devices = []
        try:
            all_devices = hid.HidDeviceFilter().get_devices()
            c = wmi.WMI()
            usb_map = {f"VID_{device.vendor_id:04x}:PID_{device.product_id:04x}": None for device in all_devices}
            for disk in c.Win32_LogicalDisk():
                if disk.DriveType == 2:  # Removable drive
                    for vid_pid in usb_map:
                        if usb_map[vid_pid] is None:
                            usb_map[vid_pid] = disk.DeviceID + "\\"
                            break
            devices = [(vid_pid, path) for vid_pid, path in usb_map.items() if path]
        except Exception as e:
            logger.error(f"Windows device detection error: {e}")
        return devices

    def _get_linux_devices(self) -> List[Dict[str, str]]:
        """Get Linux USB devices using lsblk."""
        devices = []
        try:
            # Use lsblk to get device information in JSON format
            result = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,VENDOR,MODEL,SERIAL,TYPE,MOUNTPOINT"],
                capture_output=True,
                text=True,
                check=True
            )
            
            data = json.loads(result.stdout)
            for device in data.get("blockdevices", []):
                if device.get("type") == "disk":
                    vid = device.get("vendor", "").strip()
                    pid = device.get("model", "").strip()
                    
                    # Validate VID/PID format
                    if not re.match(r"^[0-9a-fA-F]{4}$", vid) or not re.match(r"^[0-9a-fA-F]{4}$", pid):
                        logger.error(f"Skipping invalid VID/PID: {vid}:{pid}")
                        continue
                    
                    devices.append({
                        "device": device["name"],
                        "vendor_id": vid,
                        "product_id": pid,
                        "serial": device.get("serial", ""),
                        "mount_point": device.get("mountpoint", "")
                    })
                    logger.info(f"Found USB device: {device['name']} (VID:{vid} PID:{pid})")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to get device list: {e}")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse lsblk output: {e}")
        except Exception as e:
            logger.error(f"Error getting Linux devices: {e}")
        
        return devices

    def update_device_monitoring(self) -> None:
        """Update device monitoring based on current devices"""
        current_devices = self.get_usb_devices()
        current_paths = set(get_mountpoint(device) for device in current_devices)

        # Start monitoring new devices
        for device in current_devices:
            mountpoint = get_mountpoint(device)
            if mountpoint and mountpoint not in self.observers and not self._is_device_whitelisted(device):
                self._start_monitoring(mountpoint)

        # Stop monitoring removed devices
        for path in list(self.observers.keys()):
            if path not in current_paths:
                self._stop_monitoring(path)

    def _is_device_whitelisted(self, device: Dict[str, str]) -> bool:
        """Check if device is whitelisted"""
        vid_pid = f"{device['vendor_id']}:{device['product_id']}"
        return any(x in vid_pid for x in self.whitelist["vids"]) and any(x in device['serial'] for x in self.whitelist["serials"])

    def _start_monitoring(self, mountpoint: str) -> None:
        """Start monitoring a device"""
        try:
            handler = USBEventHandler(mountpoint, self.whitelist)
            observer = Observer()
            observer.schedule(handler, mountpoint, recursive=True)
            observer.start()
            self.observers[mountpoint] = observer
            logger.info(f"Started monitoring {mountpoint}")
        except Exception as e:
            logger.error(f"Error starting monitoring for {mountpoint}: {e}")

    def _stop_monitoring(self, path: str) -> None:
        """Stop monitoring a device"""
        try:
            self.observers[path].stop()
            self.observers[path].join()
            del self.observers[path]
            logger.info(f"Stopped monitoring {path}")
        except Exception as e:
            logger.error(f"Error stopping monitoring for {path}: {e}")

    def cleanup(self) -> None:
        """Cleanup all observers"""
        for path in list(self.observers.keys()):
            self._stop_monitoring(path)

def main() -> None:
    """Main function"""
    try:
        device_manager = DeviceManager()
        wmi_monitor = None
        
        if platform.system() == "Windows":
            wmi_monitor = WMIMonitor()
            # Start WMI monitoring in a separate thread
            import threading
            wmi_thread = threading.Thread(target=wmi_monitor.start_monitoring)
            wmi_thread.daemon = True
            wmi_thread.start()
        
        # Setup signal handlers
        def cleanup_handler(signum: int, frame: Any) -> None:
            logger.info("Shutting down gracefully...")
            if wmi_monitor:
                wmi_monitor.stop()
            device_manager.cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, cleanup_handler)
        signal.signal(signal.SIGTERM, cleanup_handler)

        while True:
            try:
                device_manager.update_device_monitoring()
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(5)  # Wait before retrying
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()