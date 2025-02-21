# ransomware-detection-tool
ransomeware detection tool to detect ransomware activity by monitoring file operations, system behaviour, and indicators of compromise

##
Run the following command to install all dependencies:

```bash
pip install -r requirements.txt
```
## project plan
Here's a structured approach:

1. Monitor File Operations:

File Access Patterns: Track processes that open numerous files in a short period, as ransomware often encrypts multiple files rapidly.
File Modifications: Detect unexpected file modifications, such as changes in file extensions or content encryption.
File Creation and Deletion: Identify the creation of ransom notes or the deletion of shadow copies, which are common ransomware behaviors.

2. Analyze System Behavior:

Process Monitoring: Observe processes for abnormal activities, like unauthorized access to sensitive directories or the execution of unknown binaries.
Registry Changes: Detect unauthorized modifications to the system registry, which may indicate attempts to establish persistence.
Service and Driver Installation: Monitor the installation of new services or drivers that could be malicious.

3. Identify Indicators of Compromise (IoCs):

Network Traffic Anomalies: Analyze outbound traffic for unusual patterns, such as communication with known malicious IP addresses or command-and-control servers.
Unauthorized Access Attempts: Detect repeated failed login attempts or access from unfamiliar locations.
System File Alterations: Monitor critical system files for unexpected changes, which could signify compromise.

4. Implement Detection Techniques:

Signature-Based Detection: Utilize known malware signatures to identify specific ransomware strains.
Behavior-Based Detection: Focus on identifying malicious behaviors, such as rapid file encryption or disabling security features.
Deception-Based Detection: Deploy honeypots or decoy files to lure ransomware and observe its behavior in a controlled environment.

5. Develop the Detection Tool:

Programming Language: Use a language like Python for its extensive libraries and community support.
File System Monitoring: Implement modules to monitor file system changes in real-time.
Process and Registry Monitoring: Use system APIs to track process activities and registry modifications.
Network Monitoring: Incorporate network analysis tools to inspect traffic for anomalies.

### for Windows

1. File System Monitoring:

Watchdog: A cross-platform library that monitors file system events, such as file creation, modification, and deletion, in real-time.

pip install watchdog

2. System Behavior Monitoring:

Psutil: A cross-platform library for retrieving information on running processes and system utilization (CPU, memory, disks, network, sensors).

pip install psutil

3. Registry Monitoring (Windows-specific):

winreg: A built-in Python module for accessing and modifying the Windows registry.

import winreg

4. Network Traffic Monitoring:

Scapy: A powerful Python library used for network traffic analysis and packet manipulation.

pip install scapy

5. Logging and Alerting:

##### Logging: Python's built-in logging module to record events for analysis.

import logging

##### smtplib: A built-in module for sending emails, useful for alerting.

import smtplib

### for linux

1. File System Monitoring:

PyInotify: A Python module for monitoring filesystem events on Linux systems, leveraging the inotify subsystem.

pip install pyinotify

2. System Behavior Monitoring:

Psutil: A cross-platform library for retrieving information on running processes and system utilization (CPU, memory, disks, network, sensors).

pip install psutil


3. Network Traffic Monitoring:

Scapy: A powerful Python library used for network traffic analysis and packet manipulation.

pip install scapy


4. Logging and Alerting:

Logging: Python's built-in logging module to record events for analysis.

import logging

smtplib: A built-in module for sending emails, useful for alerting.

import smtplib

### Running the Script on Linux:
Save the script as ransomware_detector.py.

Install dependencies:

```bash
pip install -r requirements.txt
```
Run the script:
```bash
python3 ransomware_detector.py
```

If you’re monitoring system directories, may need to use sudo:
```bash
sudo python3 ransomware_detector.py
```
