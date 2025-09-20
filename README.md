# Ghost Sentinel

A comprehensive host-based security monitoring framework that implements real-time threat detection through eBPF kernel monitoring, YARA pattern matching, network honeypots, and anti-evasion techniques.

## Overview

Ghost Sentinel provides multi-layer security monitoring for Linux systems by combining user-space and kernel-space detection mechanisms. The framework operates continuously to detect suspicious activities, malware, and evasion attempts while maintaining minimal system overhead.

## Features

- **eBPF Kernel Monitoring**: Real-time process execution tracking and system call analysis
- **YARA Malware Detection**: Pattern-based scanning for webshells, reverse shells, and crypto miners
- **Network Honeypots**: Automated deployment of listeners on commonly targeted ports
- **Anti-Evasion Detection**: Cross-validation techniques to identify hidden processes and connections
- **Threat Intelligence Integration**: Automated updates with IP reputation checking
- **Forensic Capabilities**: Detailed logging with integrity verification and quarantine functions
- **Alerts**: Real-time alerts for detected threats and suspicious activities via email, webhooks, Slack or Telegram

## Requirements

### System Requirements
- Linux kernel 4.9+ (for eBPF functionality)
- Bash 4.0+
- Root privileges (required for kernel monitoring and honeypots)

### Optional Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install yara bpftrace lsof python3 inotify-tools curl bpfcc-tools python-bpfcc unhide

# Fedora/RHEL
sudo dnf install yara inotify-tools bpftrace python3 curl

# Arch Linux
sudo pacman -S yara inotify-tools bpftrace python curl unhide
```

### Dependency Functions
- **yara**: Advanced malware detection rules
- **inotify-tools**: Real-time file system monitoring
- **bpfcc-tools**: eBPF kernel instrumentation
- **python3**: Network honeypot implementation and advanced monitoring features
- **curl**: Webhook notifications, suspicious IP list updates
- **unhide**: Extra checks for hidden processes

## Installation

### Quick Start
```bash
# Download
git clone https://github.com/ftk/ghost-sentinel.git
cd ghost-sentinel
chmod +x theprotector.sh

# Run basic scan
sudo ./theprotector.sh

# Install as systemd daemon
sudo ./theprotector.sh systemd
sudo systemctl enable --now ghost-sentinel
sudo journalctl -u ghost-sentinel -e
```

## Configuration

### Configuration File
Create `sentinel.conf` in the same directory as the script:

```bash
# Monitoring modules
MONITOR_NETWORK=true
MONITOR_PROCESSES=true
MONITOR_FILES=true
MONITOR_USERS=true
MONITOR_ROOTKITS=true
MONITOR_MEMORY=true

# Advanced features
ENABLE_ANTI_EVASION=true
ENABLE_EBPF=true
ENABLE_HONEYPOTS=true
ENABLE_YARA=true
ENABLE_THREAT_INTEL=true
ENABLE_UNHIDE=true

# Performance tuning
PERFORMANCE_MODE=false

# Notifications
SEND_EMAIL=false
EMAIL_RECIPIENT=""
WEBHOOK_URL=""
SLACK_WEBHOOK_URL=""
TELEGRAM_BOT_TOKEN=""
TELEGRAM_CHAT_ID=""

# Threat intelligence
THREAT_INTEL_UPDATE_HOURS=6

# Network settings
HONEYPOT_PORTS=("2222" "8080" "23" "21" "3389")

# Process whitelist (exact matching)
WHITELIST_PROCESSES=("socat")

# Quarantine suspicious files
QUARANTINE_ENABLE=true
```


## Output and Logging

### Log Location
`/var/log/ghost-sentinel/`

### Log Files
- `sentinel.log` - General activity log
- `alerts/YYYYMMDD.log` - Daily alert files
- `latest_scan.json` - Structured scan results
- `honeypot.log` - Network connection attempts
- `ebpf_events.log` - Kernel-level events
- `quarantine/` - Quarantined files with forensic data


### Debug Mode
```bash
# Enable verbose output
sudo ./theprotector.sh --verbose 
```

### Uninstall
```bash
sudo systemctl disable --now ghost-sentinel
sudo rm -rf /var/log/ghost-sentinel
sudo rm -rf /opt/ghost-sentinel
sudo rm /etc/systemd/system/ghost-sentinel.service
```

## License

This project is released under the GPLv3 license. See LICENSE file for details.
