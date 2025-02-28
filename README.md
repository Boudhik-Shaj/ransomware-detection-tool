# 🛡️ Linux Ransomware Detection Tool

## 📌 Overview

The **Linux Ransomware Detection Tool** is a security monitoring system designed to detect, alert, and mitigate potential ransomware attacks in real time. It continuously monitors file modifications, detects suspicious processes, identifies persistence mechanisms, and analyzes system file changes to prevent encryption-based attacks.

## 🚀 Features

✅ **Real-time File Monitoring**: Tracks file modifications and detects encryption attempts.
✅ **Suspicious Process Detection**: Identifies and terminates potential ransomware processes.
✅ **Persistence Mechanism Detection**: Flags unauthorized cron jobs and systemd services.
✅ **System File Integrity Check**: Alerts on system file modifications in critical directories.
✅ **High CPU Usage Monitoring**: Detects and kills high-resource-consuming ransomware processes.
✅ **IoC-Based Threat Detection**: Uses a list of known ransomware indicators (hashes, filenames, extensions, ransom notes).

## 🛠️ Installation

### **1. Clone the Repository**

```bash
git clone https://github.com/Boudhik-Shaj/ransomware-detection-tool.git
cd linux-ransomware-detection
```

### **2. Linux Installation Steps**

1. Ensure you have **Python 3** installed:
   ```bash
   sudo apt update && sudo apt install python3 python3-pip -y
   ```
2. Install required dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```
3. Run the tool:
   ```bash
   python3 rdt_linux.py
   ```

## ⚙️ Configuration

- Modify the **monitored directory** in `start_file_monitoring(path)` to protect specific folders.
- Update **IoCs** (`ioc_list` dictionary) to include new ransomware indicators.
- Customize **CPU usage threshold** in `detect_high_cpu_usage()` for better performance.

## 🔍 How It Works

### **File Encryption Detection**

- Computes file hashes to detect unauthorized modifications.
- Monitors for common ransomware file extensions.
- Alerts when ransom notes appear in directories.

### **Process Monitoring**

- Checks running processes for suspicious names and execution paths.
- Terminates known ransomware-associated processes.

### **Persistence Mechanisms**

- Scans cron jobs and systemd services for malicious entries.
- Detects unauthorized scripts set to execute on startup.

### **System File Alteration Detection**

- Monitors critical directories (`/etc`, `/usr/bin`, etc.).
- Alerts when system files are modified or deleted.

### **High CPU Usage Detection**

- Identifies processes consuming excessive CPU (possible encryption activity).
- Terminates high-usage Python-based ransomware processes.


## 🛡️ Security Recommendations

- Run the tool with **root privileges** for complete process monitoring.
- Regularly update **IoC lists** to detect new ransomware variants.
- Enable **automated alerts** (email, webhook) for real-time notifications.


## 📜 License

This project is licensed under the **MIT License**.


---

⚠️ **Disclaimer:** This tool is intended for security research and educational purposes only. Use it responsibly!

