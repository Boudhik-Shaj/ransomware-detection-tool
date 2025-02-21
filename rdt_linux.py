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
            "d4f5g6h7j8k9l0a1b2c3d4e5f6g7h8j9",   # Ryuk
            "e9f5c5d5e5f5a5b5c5d5e5f5a5b5c5d5",   # GandCrab
            "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6"   # REvil
        ],
        "sha256": [
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",  # WannaCry
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",   # Locky
            "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",   # GandCrab
            "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3"     # REvil
        ]
    },
    "filenames": [
        "@Please_Read_Me@.txt", "!Please_Read_Me!.txt",  # WannaCry
        "_Locky_recover_instructions.txt", "_Locky_README.txt",  # Locky
        "RyukReadMe.txt", "Ryuk_Decrypt_Instructions.html",  # Ryuk
        "README.txt"
    ],
    "extensions": [
        ".wncry", ".wcry", ".locky", ".ryk", ".ryuk",
        ".encrypted", ".cryptolocker", ".crypt", ".locked"
    ],
    "ransom_notes": [
        "README_FOR_DECRYPT.txt", "HOW_TO_DECRYPT.html",
        "RESTORE_FILES_INFO.txt", "DECRYPT_INSTRUCTIONS.html", "README.txt"
    ]
}

# List of suspicious processes
suspicious_processes = [
    "vssadmin", "cipher", "chattr", "mount", "umount",
    "cryptsetup", "gpg", "openssl", "shred", "dd"
]

# Get the current username dynamically
username = os.getenv('USER')

# List of unusual process locations
unusual_locations = [
    f"/home/{username}/Documents",
    f"/home/{username}/Downloads",
    f"/home/{username}/.cache/",
    "/tmp/", "/dev/shm/", "/var/tmp/", "/etc/cron.d/",
    "/etc/systemd/system/", "/usr/local/bin/"
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
                    proc_name = process.info['name'].lower() if process.info['name'] else ""
                    exe_path = process.info['exe'] or ""
                    
                    # Check for suspicious process names
                    if any(suspicious in proc_name for suspicious in suspicious_processes):
                        if process.info['pid'] > 10000:
                            print(f"[ALERT] Suspicious process detected: {proc_name} (PID: {process.info['pid']})")
                            # Attempt to terminate the process
                            try:
                                process.terminate()
                                print(f"[ACTION] Terminated process {proc_name} (PID: {process.info['pid']})")
                            except Exception as term_err:
                                print(f"[ERROR] Could not terminate process {proc_name} (PID: {process.info['pid']}): {term_err}")
                    
                    # Check for unusual locations
                    if exe_path and any(loc in exe_path for loc in unusual_locations):
                        print(f"[ALERT] Process running from unusual location: {exe_path} (PID: {process.info['pid']})")
                        try:
                            process.terminate()
                            print(f"[ACTION] Terminated process from unusual location: {exe_path} (PID: {process.info['pid']})")
                        except Exception as term_err:
                            print(f"[ERROR] Could not terminate process from unusual location (PID: {process.info['pid']}): {term_err}")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[ERROR] Error in process monitoring: {e}")
        time.sleep(5)

# Function to detect persistence mechanisms
def detect_persistence_mechanisms():
    # Check cron jobs
    try:
        cron_jobs = os.popen('crontab -l 2>/dev/null').read()
        for line in cron_jobs.splitlines():
            if line.strip().startswith('@') or any(suspicious in line for suspicious in suspicious_processes):
                print(f"[ALERT] Suspicious cron job: {line.strip()}")
    except Exception as e:
        print(f"[ERROR] Error checking cron jobs: {e}")

    # Check systemd services
    try:
        services = os.popen('systemctl list-unit-files --type=service --no-legend').read()
        for line in services.splitlines():
            service = line.split()[0]
            if any(suspicious in service for suspicious in suspicious_processes):
                print(f"[ALERT] Suspicious systemd service: {service}")
    except Exception as e:
        print(f"[ERROR] Error checking systemd services: {e}")

# Function to detect system file alterations
def detect_system_file_alterations():
    class SystemFileHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if not event.is_directory:
                print(f"[ALERT] System file modified: {event.src_path}")

        def on_created(self, event):
            if not event.is_directory:
                print(f"[ALERT] New system file created: {event.src_path}")

        def on_deleted(self, event):
            if not event.is_directory:
                print(f"[ALERT] System file deleted: {event.src_path}")

    system_paths = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin']
    event_handler = SystemFileHandler()
    observer = Observer()
    
    for path in system_paths:
        if os.path.exists(path):
            observer.schedule(event_handler, path, recursive=True)
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# File event handler for user files
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

# Start user file monitoring
def start_file_monitoring(path="/home/boudhik/Documents/important-folder"):
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
            for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent', 'cmdline']):
                try:         
                    if process.info['cpu_percent'] > 70:# and process.info['pid'] > 10000:
                        print(f"[ALERT] High CPU Usage: {process.info['name']} (PID: {process.info['pid']})")
                        cmdline = ' '.join(process.info['cmdline']) if process.info['cmdline'] else 'N/A'
                        if process.info['name'] == "python3" and "ransomware" in cmdline:
                            # print(f"[INFO] Process info: {process.info}")
                            # Attempt to terminate the processs
                            try:
                                process.terminate()
                                print(f"[ACTION] Terminated process {process.info['name']} (PID: {process.info['pid']})")
                            except Exception as term_err:
                                print(f"[ERROR] Could not terminate process {process.info['name']} (PID: {process.info['pid']}): {term_err}")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            print(f"[ERROR] Error in CPU monitoring: {e}")
        time.sleep(1)

if __name__ == "__main__":
    print("[INFO] Starting Linux Ransomware Detection Tool...")
    
    # Start monitoring threads
    threads = [
        threading.Thread(target=start_file_monitoring),
        threading.Thread(target=detect_high_cpu_usage),
        threading.Thread(target=detect_suspicious_processes),
        threading.Thread(target=detect_persistence_mechanisms),
        threading.Thread(target=detect_system_file_alterations)
    ]

    for t in threads:
        t.daemon = True
        t.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down detection tool...")
