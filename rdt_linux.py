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

# Function to detect file encryption
def detect_encryption(file_path):
    try:
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

# Run both file monitoring and CPU monitoring
if __name__ == "__main__":
    print("[INFO] Starting ransomware detection tool...")
    
    # Start file monitoring in the main thread
    file_monitor_thread = threading.Thread(target=start_file_monitoring, args=("/home",))  # Monitor a specific directory, e.g., /home
    file_monitor_thread.start()
    
    # Start CPU monitoring in a separate thread
    cpu_monitor_thread = threading.Thread(target=detect_high_cpu_usage)
    cpu_monitor_thread.start()
    
    # Wait for threads to finish
    file_monitor_thread.join()
    cpu_monitor_thread.join()