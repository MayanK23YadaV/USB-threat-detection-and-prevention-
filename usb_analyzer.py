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
import usb.util  # For USB descriptor parsing
import psutil  # Performance monitoring
import gnupg  # File encryption
import requests  # For VirusTotal API integration
import ctypes  # For admin rights check
import win32com.client  # For WMI events
import win32security  # For Windows security
import win32api  # For Windows API
import win32con  # For Windows constants
import re
from datetime import datetime
from pathlib import Path
import threading

# Check for admin rights on Windows
if platform.system() == "Windows" and not ctypes.windll.shell32.IsUserAnAdmin():
    print("Admin rights required!")
    sys.exit(1)

@dataclass
class Config:
    """Configuration settings for USB Analyzer"""
    BASE_DIR = os.environ.get("USB_THREAT_DIR",
        "C:\\ProgramData\\USBThreat" if platform.system() == "Windows"
        else "/etc/usb_threat"
    )
    LOG_DIR = os.environ.get("USB_THREAT_LOG_DIR",
        "C:\\ProgramData\\USBThreat" if platform.system() == "Windows"
        else "/var/log/usb_threat"
    )
    WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.conf")
    QUARANTINE_DIR = os.path.join(LOG_DIR, "quarantine")
    CURRENT_LOG = os.path.join(LOG_DIR, "current_usb.log")
    PREV_LOG = os.path.join(LOG_DIR, "prev_usb.log")
    DIFF_LOG = os.path.join(LOG_DIR, "diff_usb.log")
    ALERT_LOG = os.path.join(LOG_DIR, "alert.log")
    VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
    MAX_CPU = 5.0  # Percent
    MAX_MEMORY = 50 * 1024 * 1024  # 50MB in bytes
    LARGE_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    EVENT_WINDOW = 5  # Seconds
    EVENT_THRESHOLD = 10  # Files per window
    VIRUSTOTAL_RATE_LIMIT = 4  # Requests per minute
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    CHUNK_SIZE = 4096  # For file reading
    RETRY_ATTEMPTS = 3
    RETRY_DELAY = 1  # Seconds
    GPG_KEY_ID = os.environ.get("GPG_KEY_ID", "your-default-key-id")
    BADUSB_POLL_INTERVAL = 2  # Seconds to check for interface changes
    BADUSB_SUSPICIOUS_CLASSES = {0x03, 0x08, 0xe0}  # HID, Mass Storage, Wireless
    BADUSB_CHANGE_THRESHOLD = 3  # Number of interface changes to flag as suspicious
    BADUSB_TIME_WINDOW = 60  # Seconds to track changes

    def __post_init__(self):
        """Create necessary directories and validate configuration after initialization"""
        os.makedirs(self.BASE_DIR, exist_ok=True)
        os.makedirs(self.LOG_DIR, exist_ok=True)
        os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
        if not self.VIRUSTOTAL_API_KEY:
            logger.critical("VirusTotal API key is not set. Please set VIRUSTOTAL_API_KEY environment variable.")
            sys.exit(1)
        gpg = gnupg.GPG()
        if not list(gpg.list_keys(keys=[self.GPG_KEY_ID])):
            logger.critical(f"GPG key {self.GPG_KEY_ID} not found. Please configure a valid GPG key.")
            sys.exit(1)

# Initialize configuration
config = Config()

class DeviceLoggerAdapter(logging.LoggerAdapter):
    """Automatically injects 'device' field if missing"""
    def process(self, msg, kwargs):
        kwargs.setdefault("extra", {}).setdefault("device", "system")
        return super().process(msg, kwargs)

# Logger initialization
base_logger = logging.getLogger("USBAnalyzer")
base_logger.setLevel(logging.INFO)
formatter = logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "device": "%(device)s"}')
handler = RotatingFileHandler(config.ALERT_LOG, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUP_COUNT)
handler.setFormatter(formatter)
base_logger.addHandler(handler)
logger = DeviceLoggerAdapter(base_logger, {})

class VirusTotal:
    """VirusTotal API client with rate limiting and caching"""
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.last_request_time = 0
        self.cache: Dict[str, Tuple[Any, float]] = {}
        self.cache_duration = 3600  # 1 hour cache
        self.lock = threading.Lock()

    def _rate_limit(self) -> None:
        """Implement rate limiting"""
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < (60.0 / config.VIRUSTOTAL_RATE_LIMIT):
                time.sleep((60.0 / config.VIRUSTOTAL_RATE_LIMIT) - time_since_last)
            self.last_request_time = time.time()

    def _check_cache(self, file_hash: str) -> Optional[Dict]:
        """Check if result is in cache and not expired"""
        with self.lock:
            if file_hash in self.cache:
                result, timestamp = self.cache[file_hash]
                if time.time() - timestamp < self.cache_duration:
                    return result
        return None

    def _update_cache(self, file_hash: str, result: Dict) -> None:
        """Update cache with new result"""
        with self.lock:
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
        with self.lock:
            cached_result = self._check_cache(file_hash)
            if cached_result:
                return cached_result

            result = self.request("files", params={"query": file_hash})
            if result:
                self._update_cache(file_hash, result)
            return result

def check_dependencies():
    required_python = {
        "pywinusb.hid": "Windows-only",
        "wmi": "Windows-only",
        "usb.core": "Linux-only",
        "usb.util": "Linux-only",
        "psutil": True,
        "gnupg": True,
        "requests": True,
        "watchdog": True,
        "pyudev": "Linux-only"  # Added for udev monitoring
    }

    missing = []
    for lib, condition in required_python.items():
        try:
            if (condition == "Windows-only" and platform.system() != "Windows") or \
               (condition == "Linux-only" and platform.system() != "Linux"):
                continue
            __import__(lib.split('.')[0])
        except ImportError:
            missing.append(lib)

    if missing:
        logger.error(f"Missing Python libraries: {', '.join(missing)}")
        sys.exit(1)

    required_tools = ["lsblk", "diff"] if platform.system() != "Windows" else []
    for tool in required_tools:
        cmd = f"command -v {tool}"
        if subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
            logger.error(f"Required tool '{tool}' not found")
            sys.exit(1)

check_dependencies()

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

def block_usb_device(device_id: str) -> bool:
    """Block a USB device on Windows or Linux"""
    try:
        if platform.system() == "Windows":
            subprocess.run(
                ["powershell", "-Command", f"Get-PnpDevice -InstanceId '{device_id}' | Disable-PnpDevice -Confirm:$false"],
                check=True, capture_output=True, text=True
            )
            logger.info(f"Blocked USB device: {device_id}", extra={"device": device_id})
            return True
        else:
            subprocess.run(
                ["/bin/echo", "0", ">", f"/sys/bus/usb/devices/{device_id}/authorized"],
                check=True, shell=True
            )
            logger.info(f"Blocked USB device: {device_id}", extra={"device": device_id})
            return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block device {device_id}: {e}", extra={"device": device_id})
        return False

class BADUSBDetector:
    """Detect BADUSB attacks by monitoring USB device interfaces and descriptors"""
    def __init__(self, whitelist: Dict[str, Set[str]]):
        self.whitelist = whitelist
        self.device_cache: Dict[str, Set[int]] = {}  # device_id: set of interface classes
        self.change_counts: Dict[str, List[float]] = {}  # device_id: list of change timestamps
        self.lock = threading.Lock()

    def inspect_device(self, device_id: str, device: Any) -> bool:
        """Inspect a USB device for BADUSB traits"""
        try:
            vid_pid = f"VID_{device.idVendor:04x}:PID_{device.idProduct:04x}" if hasattr(device, "idVendor") else device_id
            if any(vid_pid.startswith(vid) for vid in self.whitelist["vids"]):
                return False

            # Get current interfaces
            current_interfaces = set()
            if platform.system() == "Windows":
                hid_dev = hid.find_all_hid_devices()
                for dev in hid_dev:
                    if f"VID_{dev.vendor_id:04x}&PID_{dev.product_id:04x}" in device_id:
                        current_interfaces.add(dev.device_interface)
            else:
                for cfg in device:
                    for intf in cfg:
                        current_interfaces.add(intf.bInterfaceClass)

            # Check for suspicious classes
            suspicious = any(cls in config.BADUSB_SUSPICIOUS_CLASSES for cls in current_interfaces)
            if suspicious:
                logger.warning(f"Suspicious interface class detected: {current_interfaces}", extra={"device": device_id})

            # Check for rapid interface changes
            with self.lock:
                if device_id in self.device_cache:
                    prev_interfaces = self.device_cache[device_id]
                    if current_interfaces != prev_interfaces:
                        self._record_change(device_id)
                        if self._is_rapid_change(device_id):
                            logger.warning(f"Rapid interface change detected: {prev_interfaces} -> {current_interfaces}", extra={"device": device_id})
                            return True
                self.device_cache[device_id] = current_interfaces

            return suspicious
        except Exception as e:
            logger.error(f"Error inspecting device {device_id}: {e}", extra={"device": device_id})
            return False

    def _record_change(self, device_id: str) -> None:
        """Record timestamp of interface change"""
        with self.lock:
            if device_id not in self.change_counts:
                self.change_counts[device_id] = []
            self.change_counts[device_id].append(time.time())
            # Clean up old timestamps
            self.change_counts[device_id] = [
                ts for ts in self.change_counts[device_id]
                if time.time() - ts <= config.BADUSB_TIME_WINDOW
            ]

    def _is_rapid_change(self, device_id: str) -> bool:
        """Check if interface changes exceed threshold"""
        with self.lock:
            if device_id in self.change_counts:
                return len(self.change_counts[device_id]) >= config.BADUSB_CHANGE_THRESHOLD
            return False

def get_usb_devices() -> List[Dict[str, Any]]:
    """Get list of USB devices with detailed attributes"""
    devices = []
    if platform.system() == "Windows":
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
            for vid_pid, path in usb_map.items():
                if path:
                    parts = vid_pid.split(":")
                    vendor = parts[0].split("_")[1] if "_" in parts[0] else ""
                    product = parts[1].split("_")[1] if "_" in parts[1] else ""
                    devices.append({
                        "vendor_id": vendor,
                        "product_id": product,
                        "mount_point": path,
                        "serial": "",
                        "device_id": vid_pid,
                        "raw_device": None  # Not directly accessible
                    })
        except Exception as e:
            logger.error(f"Windows device detection error: {e}")
    else:
        try:
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
                devices.append({
                    "vendor_id": f"{dev.idVendor:04x}",
                    "product_id": f"{dev.idProduct:04x}",
                    "mount_point": dev_path,
                    "serial": dev.serial_number if hasattr(dev, "serial_number") else "",
                    "device_id": vid_pid,
                    "raw_device": dev
                })
        except Exception as e:
            logger.error(f"Linux device detection error: {e}")
    return devices

def get_mountpoint(device_info):
    if isinstance(device_info, dict):
        return device_info.get("mount_point")
    elif isinstance(device_info, tuple):
        _, dev_path = device_info
        return dev_path
    else:
        return None

def signal_handler(sig, frame):
    logger.info("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class ResourceMonitor:
    @staticmethod
    def check_resources() -> bool:
        process = psutil.Process()
        try:
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_info = process.memory_info()
            return cpu_percent <= config.MAX_CPU and memory_info.rss <= config.MAX_MEMORY
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            logger.error(f"Resource monitoring error: {e}")
            return False

class FileAnalyzer:
    def __init__(self, vt: VirusTotal):
        self.vt = vt

    def analyze_file(self, file_path: str) -> bool:
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
        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(config.CHUNK_SIZE), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Hash computation error: {e}")
            return ""

class LinuxSecurity:
    @staticmethod
    def block_usb_storage() -> bool:
        try:
            subprocess.run(
                ["/usr/sbin/modprobe", "-r", "usb_storage"],
                check=True,
                stderr=subprocess.PIPE
            )
            logger.info("USB storage kernel module removed")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block USB storage: {e.stderr.decode()}")
            return False

    @staticmethod
    def block_device_access(mountpoint: str) -> bool:
        try:
            subprocess.run(
                ["/bin/chmod", "000", mountpoint],
                check=True,
                stderr=subprocess.PIPE
            )
            logger.info(f"Linux device access blocked: {mountpoint}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block device: {e.stderr.decode()}")
            return False

class WMIMonitor:
    def __init__(self, whitelist: Dict[str, Set[str]], device_manager, badusb_detector):
        self.wmi = win32com.client.GetObject("winmgmts:")
        self.running = True
        self.whitelist = whitelist
        self.device_manager = device_manager
        self.badusb_detector = badusb_detector

    def start_monitoring(self):
        try:
            query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_USBControllerDevice'"
            watcher = self.wmi.ExecNotificationQuery(query)
            
            while self.running:
                try:
                    event = watcher.NextEvent(1000)
                    if event:
                        self._handle_usb_event(event)
                except Exception as e:
                    if "timeout" not in str(e).lower():
                        logger.error(f"WMI event error: {e}")
        except Exception as e:
            logger.error(f"WMI monitoring error: {e}")

    def _handle_usb_event(self, event):
        try:
            device = event.TargetInstance
            device_id = device.DeviceID if device.DeviceID else "unknown"
            vid_pid = f"VID_{device_id.split('\\')[1]}" if '\\' in device_id else "unknown"
            
            if any(vid_pid.startswith(vid) for vid in self.whitelist["vids"]):
                logger.info(f"Whitelisted USB device detected: {vid_pid}", extra={"device": device_id})
                return

            logger.info(f"USB device detected: {vid_pid}", extra={"device": device_id})
            
            # Check for BADUSB traits
            if self.badusb_detector.inspect_device(device_id, None):
                logger.warning(f"BADUSB traits detected, blocking device: {device_id}", extra={"device": device_id})
                block_usb_device(device_id)
                return

            # Scan device with Windows Defender
            self._scan_device(device_id)
            
            # Update device manager
            self.device_manager.update_device_monitoring()
        except Exception as e:
            logger.error(f"Error handling USB event: {e}", extra={"device": device_id})

    def _scan_device(self, device_id: str):
        try:
            c = wmi.WMI()
            for disk in c.Win32_LogicalDisk():
                if disk.DriveType == 2:
                    subprocess.run(
                        ["powershell", "-Command", f"Start-MpScan -ScanType Custom -ScanPath '{disk.DeviceID}\\'"],
                        check=True, capture_output=True, text=True
                    )
                    logger.info(f"Windows Defender scan initiated for device: {device_id}", extra={"device": device_id})
                    break
        except subprocess.CalledProcessError as e:
            logger.error(f"Windows Defender scan failed: {e.stderr}", extra={"device": device_id})

    def stop(self):
        self.running = False

# Import pyudev for Linux udev monitoring
if platform.system() != "Windows":
    import pyudev

class UdevMonitor:
    """Monitor USB devices on Linux using udev events"""
    def __init__(self, whitelist: Dict[str, Set[str]], device_manager, badusb_detector):
        self.running = True
        self.whitelist = whitelist
        self.device_manager = device_manager
        self.badusb_detector = badusb_detector
        self.context = pyudev.Context()

    def start_monitoring(self):
        try:
            monitor = pyudev.Monitor.from_netlink(self.context)
            monitor.filter_by(subsystem='usb')
            observer = pyudev.MonitorObserver(monitor, self._handle_udev_event)
            observer.start()
            logger.info("Started udev monitoring")
            while self.running:
                time.sleep(1)  # Keep thread alive
        except Exception as e:
            logger.error(f"Udev monitoring error: {e}")

    def _handle_udev_event(self, device):
        try:
            if device.action != "add":
                return
            device_id = device.get('ID_PATH', 'unknown')
            vid = device.get('ID_VENDOR_ID', '')
            pid = device.get('ID_MODEL_ID', '')
            vid_pid = f"VID_{vid}:PID_{pid}" if vid and pid else "unknown"

            if any(vid_pid.startswith(vid) for vid in self.whitelist["vids"]):
                logger.info(f"Whitelisted USB device detected: {vid_pid}", extra={"device": device_id})
                return

            logger.info(f"USB device detected: {vid_pid}", extra={"device": device_id})

            # Check for BADUSB traits
            if self.badusb_detector.inspect_device(device_id, None):
                logger.warning(f"BADUSB traits detected, blocking device: {device_id}", extra={"device": device_id})
                block_usb_device(device_id)
                return

            # Update device manager
            self.device_manager.update_device_monitoring()
        except Exception as e:
            logger.error(f"Error handling udev event: {e}", extra={"device": device_id})

    def stop(self):
        self.running = False

class USBEventHandler(FileSystemEventHandler):
    def __init__(self, mountpoint: str, whitelist: Dict[str, Set[str]]):
        self.mountpoint = mountpoint
        self.whitelist = whitelist
        self.event_count = 0
        self.event_time = time.time()
        self.vt = VirusTotal(config.VIRUSTOTAL_API_KEY)
        self.file_analyzer = FileAnalyzer(self.vt)
        self._setup_logging()

    def _setup_logging(self) -> None:
        handler = RotatingFileHandler(config.ALERT_LOG, maxBytes=config.LOG_MAX_BYTES, backupCount=config.LOG_BACKUP_COUNT)
        handler.setFormatter(logging.Formatter('{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s", "device": "' + self.mountpoint + '"}'))
        self.logger = logging.getLogger(f"USBEventHandler.{self.mountpoint}")
        self.logger.addHandler(handler)

    def on_any_event(self, event) -> None:
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
        return any(d in path for d in self.whitelist["dirs"])

    def _check_rapid_file_copy(self) -> None:
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
        try:
            if platform.system() == "Windows":
                subprocess.run(
                    ["icacls", self.mountpoint, "/deny", "Everyone:(W)"],
                    check=True,
                    capture_output=True
                )
                logger.info(f"Write access blocked: {self.mountpoint}")
            else:
                if LinuxSecurity.block_usb_storage():
                    LinuxSecurity.block_device_access(self.mountpoint)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block writes: {e}")

    def quarantine_file(self, file_path: str) -> bool:
        try:
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False

            gpg = gnupg.GPG()
            if not list(gpg.list_keys(keys=[config.GPG_KEY_ID])):
                logger.error(f"GPG key {config.GPG_KEY_ID} not found")
                return False
            
            quarantine_dir = Path(config.QUARANTINE_DIR)
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            encrypted_name = f"{Path(file_path).stem}_{timestamp}.gpg"
            encrypted_path = quarantine_dir / encrypted_name
            
            with open(file_path, 'rb') as f:
                status = gpg.encrypt_file(
                    f,
                    recipients=[config.GPG_KEY_ID],
                    output=str(encrypted_path),
                    armor=False
                )
            
            if status.ok and os.path.exists(encrypted_path):
                os.remove(file_path)
                logger.info(f"File quarantined: {encrypted_path}")
                return True
            else:
                logger.error(f"Encryption failed: {status.status}")
                return False
        except Exception as e:
            logger.error(f"Error quarantining file: {e}")
            return False

class DeviceManager:
    def __init__(self):
        self.observers: Dict[str, Observer] = {}
        self.whitelist = load_whitelist()
        self.badusb_detector = BADUSBDetector(self.whitelist)

    def get_usb_devices(self) -> List[Dict[str, Any]]:
        return get_usb_devices()

    def update_device_monitoring(self) -> None:
        current_devices = self.get_usb_devices()
        current_paths = set(get_mountpoint(device) for device in current_devices)

        for device in current_devices:
            mountpoint = get_mountpoint(device)
            vid_pid = f"VID_{device['vendor_id']}:PID_{device['product_id']}"
            device_id = device.get("device_id", vid_pid)
            
            # Check for BADUSB traits
            if self.badusb_detector.inspect_device(device_id, device.get("raw_device")):
                logger.warning(f"BADUSB traits detected, blocking device: {device_id}", extra={"device": device_id})
                block_usb_device(device_id)
                continue

            if mountpoint and mountpoint not in self.observers and not any(vid_pid.startswith(vid) for vid in self.whitelist["vids"]):
                self._start_monitoring(mountpoint)

        for path in list(self.observers.keys()):
            if path not in current_paths:
                self._stop_monitoring(path)

    def _start_monitoring(self, mountpoint: str) -> None:
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
        try:
            self.observers[path].stop()
            self.observers[path].join()
            del self.observers[path]
            logger.info(f"Stopped monitoring {path}")
        except Exception as e:
            logger.error(f"Error stopping monitoring for {path}: {e}")

    def cleanup(self) -> None:
        for path in list(self.observers.keys()):
            self._stop_monitoring(path)

def main() -> None:
    try:
        logger.info("Starting USB Analyzer as primary controller for USB threat detection and prevention")
        device_manager = DeviceManager()
        wmi_monitor = None
        udev_monitor = None
        
        # Create lock file
        lock_file = os.path.join(config.BASE_DIR, "usb_analyzer.lock")
        with open(lock_file, "w") as f:
            f.write(str(os.getpid()))
        
        if platform.system() == "Windows":
            wmi_monitor = WMIMonitor(device_manager.whitelist, device_manager, device_manager.badusb_detector)
            wmi_thread = threading.Thread(target=wmi_monitor.start_monitoring)
            wmi_thread.daemon = True
            wmi_thread.start()
        else:
            udev_monitor = UdevMonitor(device_manager.whitelist, device_manager, device_manager.badusb_detector)
            udev_thread = threading.Thread(target=udev_monitor.start_monitoring)
            udev_thread.daemon = True
            udev_thread.start()
        
        def cleanup_handler(signum: int, frame: Any) -> None:
            logger.info("Shutting down gracefully...")
            if wmi_monitor:
                wmi_monitor.stop()
            if udev_monitor:
                udev_monitor.stop()
            device_manager.cleanup()
            if os.path.exists(lock_file):
                os.remove(lock_file)
            sys.exit(0)

        signal.signal(signal.SIGINT, cleanup_handler)
        signal.signal(signal.SIGTERM, cleanup_handler)

        while True:
            try:
                if platform.system() != "Windows" and not udev_monitor:  # Fallback for Linux if udev fails
                    device_manager.update_device_monitoring()
                time.sleep(config.BADUSB_POLL_INTERVAL)
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(config.BADUSB_POLL_INTERVAL)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if os.path.exists(lock_file):
            os.remove(lock_file)
        sys.exit(1)

if __name__ == "__main__":
    main()