# theProtector
Linux Bash Script for the Paranoid Admin on a Budget - real-time monitoring and active threat response

# TheProtector

**Linux security tool for the paranoid on a budget - not perfect but better than most**

TheProtector is comprehensive security monitoring for Linux systems. Built for DEfense Only

## What It Does

TheProtector monitors your Linux system in real-time and actively responds to threats:

**Real-time Monitoring:**
- Process execution and behavior analysis
- Network connections and traffic patterns  
- File system changes and integrity checking
- User activity and privilege escalation attempts
- System resource usage and anomalies
- Kernel-level activity via eBPF (when available)

**Active Threat Response:**
- Automatically blocks malicious IP addresses
- Terminates suspicious processes immediately
- Quarantines detected malware with forensic preservation
- Restores modified critical system files from backups
- Kills reverse shell connections and C2 communications

**Advanced Detection:**
- YARA rule scanning for malware signatures
- Behavioral baseline learning and anomaly detection
- Anti-evasion techniques to defeat rootkits and process hiding
- Honeypot services to detect reconnaissance attempts
- Threat intelligence integration with automatic updates

**Management Interface:**
- Web dashboard for real-time monitoring
- JSON output for SIEM integration
- Comprehensive logging with integrity verification
- Alert categorization by severity level
- Historical analysis and reporting

## Installation

### Quick Start

```bash
curl -O https://raw.githubusercontent.com/IHATEGIVINGAUSERNAME/theProtector/main/theprotector.sh
chmod +x theprotector.sh
sudo ./theprotector.sh test
```

### Full Installation

```bash
# Download the script
wget https://raw.githubusercontent.com/IHATEGIVINGAUSERNAME/theProtector/main/theprotector.sh

# Make executable
chmod +x theprotector.sh

# Run initial setup and test
sudo ./theprotector.sh test

# Install for automatic monitoring
sudo ./theprotector.sh install
```

## Dependencies

### Required (Standard on all Linux systems)
- bash (4.0 or higher)
- curl or wget
- awk, grep, sed
- netstat or ss
- iptables
- cron (for scheduled scans)

### Optional (Enables advanced features)
- **yara** - Malware signature scanning
- **jq** - JSON processing and pretty output
- **inotify-tools** - Real-time file monitoring
- **netcat** - Network honeypot services
- **bcc-tools** - eBPF kernel monitoring (requires root)

### Install Optional Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install yara jq inotify-tools netcat-openbsd
# For eBPF monitoring:
sudo apt install bcc-tools python3-bpfcc
```

**CentOS/RHEL/Fedora:**
```bash
sudo yum install epel-release
sudo yum install yara jq inotify-tools nmap-ncat
# For eBPF monitoring:
sudo yum install bcc-tools python3-bcc
```

**Arch Linux:**
```bash
sudo pacman -S yara jq inotify-tools gnu-netcat
# For eBPF monitoring:
sudo pacman -S bcc-tools python-bcc
```

## System Requirements

- Linux (any distribution)
- Root access (required for kernel monitoring and active response)
- Minimum 512MB RAM
- 100MB disk space for logs and quarantine
- Network access for threat intelligence updates

## Usage

### Basic Commands

```bash
# Run comprehensive security scan
sudo ./theprotector.sh enhanced

# Start web dashboard (http://localhost:8080)
sudo ./theprotector.sh dashboard

# View current alerts
sudo ./theprotector.sh alerts

# Check system status
sudo ./theprotector.sh status

# Run basic functionality test
sudo ./theprotector.sh test

# Clean up processes and reset
sudo ./theprotector.sh cleanup
```

### Advanced Usage

```bash
# Create security baseline
sudo ./theprotector.sh baseline

# Monitor with honeypots
sudo ./theprotector.sh honeypot

# eBPF kernel monitoring (requires BCC tools)
sudo ./theprotector.sh ebpf

# View JSON output for SIEM integration
sudo ./theprotector.sh json

# Edit configuration
sudo ./theprotector.sh config
```

### Automated Monitoring

```bash
# Install cron job for hourly scans
sudo ./theprotector.sh install

# View logs
sudo ./theprotector.sh logs

# Check what cron job was installed
sudo crontab -l | grep theprotector
```

## Configuration

TheProtector works immediately without configuration. To customize:

```bash
sudo ./theprotector.sh config
```

**Key Settings:**
- `MONITOR_NETWORK` - Enable network connection monitoring
- `ENABLE_HONEYPOTS` - Deploy honeypot services for attack detection
- `ENABLE_YARA` - Scan files with YARA malware rules
- `THREAT_INTEL_UPDATE` - Automatically update threat intelligence feeds
- `API_PORT` - Web dashboard port (default 8080)
- `LOG_RETENTION_DAYS` - How long to keep logs (default 30)

## File Locations

- **Script:** `./theprotector.sh`
- **Configuration:** `/etc/theprotector/theprotector.conf`
- **Logs:** `/var/log/theprotector/`
- **Alerts:** `/var/log/theprotector/alerts/`
- **Quarantine:** `/var/log/theprotector/quarantine/`
- **Baselines:** `/var/log/theprotector/baselines/`

## What It Detects

**Malware and Rootkits:**
- Cryptocurrency miners
- Webshells and backdoors
- Kernel rootkits
- Process injection attacks
- Fileless malware
- Memory-resident threats

**Network Attacks:**
- Port scanning and reconnaissance
- Brute force login attempts
- Command and control communications
- Data exfiltration attempts
- Lateral movement
- Reverse shell connections

**System Compromise:**
- Unauthorized privilege escalation
- New user account creation
- Critical file modifications
- Suspicious process execution
- Persistence mechanism installation
- Configuration tampering

## Performance

TheProtector is designed for continuous operation:
- **Memory usage:** Approximately 50MB RAM
- **CPU impact:** Less than 2% on modern systems
- **Disk usage:** Grows with log retention settings
- **Network impact:** Minimal, only threat intelligence updates

## Limitations

TheProtector provides a solid security foundation but has limitations:

- **Not a complete SIEM** - Lacks enterprise reporting and compliance features
- **Bash-based** - Some prefer compiled languages for security tools
- **Linux only** - Does not monitor Windows or macOS systems
- **Root required** - Needs elevated privileges for kernel monitoring
- **Community supported** - No vendor support or SLA

For most use cases, these limitations are not problems. For enterprise compliance requirements, additional tools may be needed.

## Troubleshooting

**Permission denied errors:**
```bash
# Ensure running as root
sudo ./theprotector.sh test
```

**Missing dependencies:**
```bash
# Check what's missing
./theprotector.sh test
# Install missing packages as shown above
```

**High resource usage:**
```bash
# Reduce monitoring frequency
sudo ./theprotector.sh config
# Set PERFORMANCE_MODE=true
```

**Web dashboard not accessible:**
```bash
# Check if port is blocked
sudo ufw allow 8080
# Or change port in configuration
```

## Contributing

This is a community project. Contributions are welcome:

- **Bug reports:** Open an issue with system details and error messages
- **Feature requests:** Describe your use case and requirements  
- **Code contributions:** Submit pull requests with clear descriptions
- **Documentation:** Help improve installation guides and examples
- **Testing:** Try on different distributions and report compatibility

## Support

- **Issues:** Use GitHub issue tracker
- **Questions:** Check existing issues and documentation first
- **Community:** GitHub discussions for general questions

This is free software provided as-is. No warranties or guarantees, but genuine effort to help the Linux security community.

## License

GNU General Public License v3.0

You are free to use, modify, and distribute this software. Any modifications must also be released under GPL v3.

## About

I built TheProtector over the past year in my free time because:

1. **Security should be accessible** - Not just for Fortune 500 companies
2. **Tools should work** - Detection without response is useless  
3. **Simplicity wins** - Complex tools break in production
4. **Open source is better** - Transparent security you can trust and modify
5. **Budget constraints drive innovation** - Good security doesn't require unlimited budgets

**Merry Christmas, Linux community.** 

This is my gift to you - a year of evenings and weekends building something that actually works. If you don't like it, cool. Make it better.

I maintain this in my spare time and give it away free because security tools shouldn't cost more than a car payment.

**Not perfect, but better than what you're paying for.**

---

Built by thelotus over a year of free time. Maintained by thelotus. Given away free because expensive security theater is stupid.
