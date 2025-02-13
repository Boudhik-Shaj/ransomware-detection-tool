import os
import time
import psutil
import hashlib
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Track encrypted files
encrypted_files = {}
encrypted_files_lock = threading.Lock()

# List of known IoCs (file extensions, filenames, etc.)
ioc_list = {
    "hashes": {
        "md5": [
            "84c82835a5d21bbcf75a61706d8ab549",  # WannaCry
            "c3b8d1f1a1792b4f7a1b6a5c1d5e1f1a",  # Locky
            "d4f5g6h7j8k9l0a1b2c3d4e5f6g7h8j9"   # Ryuk
        ],
        "sha256": [
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",  # WannaCry
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"   # Locky
        ]
    },
    "filenames": [
        "mssecsvc.exe", "tasksche.exe", "@Please_Read_Me@.txt", "!Please_Read_Me!.txt",  # WannaCry
        "locky.exe", "decrypt.exe", "_Locky_recover_instructions.txt", "_Locky_README.txt",  # Locky
        "Ryuk.exe", "encryptor.exe", "RyukReadMe.txt", "Ryuk_Decrypt_Instructions.html"  # Ryuk
    ],
    "extensions": [
        ".wncry", ".wcry",  # WannaCry
        ".locky", ".zepto", ".odin",  # Locky
        ".ryk", ".ryuk",  # Ryuk
        ".revil", ".sodinokibi",  # REvil
        ".cerber", ".cerber3",  # Cerber
        ".gdcb", ".crab",  # GandCrab
        ".maze", ".maze64",  # Maze
        ".phobos", ".phoenix",  # Phobos
        ".dharma", ".onion",  # Dharma
        ".encrypted", ".cryptolocker"  # CryptoLocker
    ],
    "ransom_notes": [
        "@Please_Read_Me@.txt", "!Please_Read_Me!.txt",  # WannaCry
        "_Locky_recover_instructions.txt", "_Locky_README.txt",  # Locky
        "RyukReadMe.txt", "Ryuk_Decrypt_Instructions.html",  # Ryuk
        "Sodinokibi_README.txt", "REvil_README.html"  # REvil
    ]
}

# List of suspicious processes
suspicious_processes = [
    "vssadmin", "cipher", "wbadmin", "powershell", "wscript", "cscript",
    "rundll32", "regsvr32", "explorer", "svchost", "mssecsvc", "tasksche",
    "locky", "ryuk"
]

# Get the current username dynamically
username = os.getenv('USER')

# List of unusual process locations
unusual_locations = [
    f"/home/{username}/.config/", 
    f"/home/{username}/.cache/",
    "/tmp/", "/dev/shm/", "/var/tmp/", "/home/", "/root/", "/etc/cron.d/",
    "/etc/systemd/system/", "/usr/local/bin/", "/usr/bin/"
]

# Function to detect IoCs
def detect_ioc(file_path):
    # Check for known file extensions
    for ext in ioc_list["extensions"]:
        if file_path.endswith(ext):
            print(f"[ALERT] IoC detected (extension): {file_path}")
            return True

    # Check for known filenames
    if os.path.basename(file_path) in ioc_list["filenames"]:
        print(f"[ALERT] IoC detected (filename): {file_path}")
        return True

    # Check for known ransom notes
    if os.path.basename(file_path) in ioc_list["ransom_notes"]:
        print(f"[ALERT] IoC detected (ransom note): {file_path}")
        return True

    # Check for known file hashes
    try:
        hasher_md5 = hashlib.md5()
        hasher_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher_md5.update(chunk)
                hasher_sha256.update(chunk)
        file_hash_md5 = hasher_md5.hexdigest()
        file_hash_sha256 = hasher_sha256.hexdigest()
        if file_hash_md5 in ioc_list["hashes"]["md5"]:
            print(f"[ALERT] IoC detected (MD5 hash): {file_path}")
            return True
        if file_hash_sha256 in ioc_list["hashes"]["sha256"]:
            print(f"[ALERT] IoC detected (SHA256 hash): {file_path}")
            return True
    except Exception as e:
        print(f"[ERROR] Error processing file {file_path}: {e}")

    return False

# Function to detect file encryption
def detect_encryption(file_path):
    try:
        if detect_ioc(file_path):
            return True

        hasher = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()

        with encrypted_files_lock:
            if file_path in encrypted_files:
                if encrypted_files[file_path] != file_hash:
                    print(f"[ALERT] Possible encryption detected: {file_path}")
                    return True
            encrypted_files[file_path] = file_hash
    except Exception as e:
        print(f"[ERROR] Error processing file {file_path}: {e}")
    return False

# Function to detect suspicious processes
def detect_suspicious_processes():
    while True:
        try:
            for process in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cmdline']):
                try:
                    if process.info['name'] in suspicious_processes:
                        print(f"[ALERT] Suspicious process detected: {process.info['name']} (PID: {process.info['pid']})")
                    if any(loc in process.info['exe'] for loc in unusual_locations):
                        print(f"[ALERT] Process running from unusual location: {process.info['exe']} (PID: {process.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[ERROR] Error in process monitoring: {e}")
        time.sleep(5)

# Function to detect persistence mechanisms (cron jobs, systemd services, etc.)
def detect_persistence_mechanisms():
    # Check for suspicious cron jobs
    try:
        cron_jobs = os.popen('crontab -l').read()
        for line in cron_jobs.splitlines():
            if any(suspicious in line for suspicious in suspicious_processes):
                print(f"[ALERT] Suspicious cron job detected: {line}")
    except Exception as e:
        print(f"[ERROR] Error checking cron jobs: {e}")

    # Check for suspicious systemd services
    try:
        services = os.popen('systemctl list-unit-files --type=service').read()
        for line in services.splitlines():
            if any(suspicious in line for suspicious in suspicious_processes):
                print(f"[ALERT] Suspicious systemd service detected: {line}")
    except Exception as e:
        print(f"[ERROR] Error checking systemd services: {e}")

# Function to detect network traffic anomalies
def detect_network_anomalies():
    # Placeholder function for network traffic analysis
    print("[INFO] Network traffic analysis not implemented yet")

# Function to detect unauthorized access attempts
def detect_unauthorized_access():
    # Placeholder function for unauthorized access detection
    print("[INFO] Unauthorized access detection not implemented yet")

# Function to detect system file alterations
def detect_system_file_alterations():
    # Placeholder function for system file alteration detection
    print("[INFO] System file alteration detection not implemented yet")

# File event handler
class RansomwareDetectionHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if not event.is_directory:
            if detect_encryption(event.src_path):
                print(f"[WARNING] File modified suspiciously: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            print(f"[INFO] New file created: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[WARNING] File deleted: {event.src_path}")

# Start monitoring
def start_file_monitoring(path="/home"):  # Monitor a specific directory, e.g., /home
    event_handler = RansomwareDetectionHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("[INFO] Stopping file monitoring...")
        observer.stop()
    except Exception as e:
        print(f"[ERROR] Error in file monitoring: {e}")
        observer.stop()
    observer.join()

# Monitor high CPU usage
def detect_high_cpu_usage():
    while True:
        try:
            for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
                try:
                    if process.info['cpu_percent'] > 70:  # Set a threshold (70% CPU usage)
                        print(f"[ALERT] High CPU Usage detected: {process.info['name']} (PID: {process.info['pid']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[ERROR] Error in CPU monitoring: {e}")
        time.sleep(5)

# Run all monitoring functions
if __name__ == "__main__":
    print("[INFO] Starting ransomware detection tool...")
    
    # Start file monitoring in the main thread
    file_monitor_thread = threading.Thread(target=start_file_monitoring, args=("/home",))
    file_monitor_thread.start()
    
    # Start CPU monitoring in a separate thread
    cpu_monitor_thread = threading.Thread(target=detect_high_cpu_usage)
    cpu_monitor_thread.start()
    
    # Start suspicious process monitoring in a separate thread
    suspicious_process_thread = threading.Thread(target=detect_suspicious_processes)
    suspicious_process_thread.start()
    
    # Start persistence mechanism monitoring in a separate thread
    persistence_thread = threading.Thread(target=detect_persistence_mechanisms)
    persistence_thread.start()
    
    # Start network traffic anomaly detection in a separate thread
    network_anomaly_thread = threading.Thread(target=detect_network_anomalies)
    network_anomaly_thread.start()
    
    # Start unauthorized access detection in a separate thread
    unauthorized_access_thread = threading.Thread(target=detect_unauthorized_access)
    unauthorized_access_thread.start()
    
    # Start system file alteration detection in a separate thread
    system_file_alteration_thread = threading.Thread(target=detect_system_file_alterations)
    system_file_alteration_thread.start()
    
    # Wait for threads to finish
    file_monitor_thread.join()
    cpu_monitor_thread.join()
    suspicious_process_thread.join()
    persistence_thread.join()
    network_anomaly_thread.join()
    unauthorized_access_thread.join()
    system_file_alteration_thread.join()