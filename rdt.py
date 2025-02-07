import os
import time
import psutil
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Track encrypted files
encrypted_files = {}

# Function to detect file encryption (Checks if file contents change abnormally)
def detect_encryption(file_path):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_hash = hashlib.md5(file_data).hexdigest()

            if file_path in encrypted_files:
                if encrypted_files[file_path] != file_hash:
                    print(f"[ALERT] Possible encryption detected: {file_path}")
                    return True
            encrypted_files[file_path] = file_hash
    except:
        pass
    return False

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
def start_file_monitoring(path="."):
    event_handler = RansomwareDetectionHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# Monitor high CPU usage (Possible ransomware encryption process)
def detect_high_cpu_usage():
    while True:
        for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
            if process.info['cpu_percent'] > 70:  # Set a threshold (70% CPU usage)
                print(f"[ALERT] High CPU Usage detected: {process.info['name']} (PID: {process.info['pid']})")
        time.sleep(5)

# Run both file monitoring and CPU monitoring
if __name__ == "__main__":
    print("[INFO] Starting ransomware detection tool...")
    start_file_monitoring("C:\")  # folder you want to monitor
