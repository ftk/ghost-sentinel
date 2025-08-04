#!/usr/bin/env bash

# It is free and took me about a year so use it love it or leave it
# Production-hardened with eBPF, YARA, honeypots, and stealth detection

set -euo pipefail

# If --verbose is provided as argument, set -x
if [[ " $* " == *" --verbose "* ]]; then
    set -x
fi

# Configuration - Auto-detect user permissions and adjust paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
LOCK_FILE="/tmp/ghost-sentinel-$USER.lock"
PID_FILE="/tmp/ghost-sentinel-$USER.pid"

LOG_DIR="/var/log/ghost-sentinel"

CONFIG_FILE="$SCRIPT_DIR/sentinel.conf"
BASELINE_DIR="$LOG_DIR/baseline"
ALERTS_DIR="$LOG_DIR/alerts"
QUARANTINE_DIR="$LOG_DIR/quarantine"
THREAT_INTEL_DIR="$LOG_DIR/threat_intel"
YARA_RULES_DIR="$LOG_DIR/yara_rules"
SCRIPTS_DIR="$LOG_DIR/scripts"
HONEYPOT_LOG="$LOG_DIR/honeypot.log"
EBPF_LOG="$LOG_DIR/ebpf_events.log"

# Colors for output (straight quotes only)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Alert levels
CRITICAL=1
HIGH=2
MEDIUM=3
LOW=4

# Performance and security controls
THREAT_INTEL_UPDATE_HOURS=6
HONEYPOT_PORTS=("2222" "8080" "23" "21" "3389")

# Environment detection
IS_CONTAINER=false
IS_VM=false
IS_DEBIAN=false
IS_FEDORA=false
IS_NIXOS=false
HAS_INOTIFY=false
HAS_YARA=false
HAS_BCC=false

# Cleanup function for proper resource management
cleanup() {
    declare exit_code=$?

    # Stop honeypots
    stop_honeypots

    # Stop eBPF monitoring
    stop_ebpf_monitoring

    # Clean up locks
    rm -f "$LOCK_FILE" "$PID_FILE" 2>/dev/null || true

    exit $exit_code
}
trap cleanup EXIT INT TERM

# Enhanced lock management with stale lock detection
acquire_lock() {
    # Check for stale locks
    if [[ -f "$LOCK_FILE" ]]; then
        declare lock_pid=""
        if [[ -f "$PID_FILE" ]]; then
            lock_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        fi

        # If PID exists and process is running, exit
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            echo "Another instance is running (PID: $lock_pid). Exiting."
            exit 1
        else
            # Clean up stale lock
            rm -f "$LOCK_FILE" "$PID_FILE" 2>/dev/null || true
        fi
    fi

    # Use flock if available, otherwise manual locking
    if command -v flock >/dev/null 2>&1; then
        exec 200>"$LOCK_FILE"
        if ! flock -n 200; then
            echo "Failed to acquire lock. Another instance may be running."
            exit 1
        fi
    else
        echo $$ > "$LOCK_FILE"
    fi

    # Always write PID file
    echo $$ > "$PID_FILE"
}

# Enhanced dependency checking
check_dependencies() {
    # Check for inotify tools
    if command -v inotifywait >/dev/null 2>&1; then
        HAS_INOTIFY=true
    fi

    # Check for YARA
    if command -v yara >/dev/null 2>&1; then
        HAS_YARA=true
    fi

    # Check for eBPF/BCC tools
    if command -v bpftrace >/dev/null 2>&1 || [[ -d /usr/share/bcc/tools ]]; then
        HAS_BCC=true
    fi

    if [[ "$HAS_YARA" == false ]]; then
        log_info "YARA not found - malware scanning disabled"
    fi
    if [[ "$HAS_BCC" == false ]]; then
        log_info "eBPF tools not found - kernel monitoring disabled"
    fi
}

# Detect container/VM environment
detect_environment() {
    # Container detection
    if [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || grep -q "docker\|lxc\|containerd" /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER=true
    fi

    # VM detection
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        if systemd-detect-virt -q; then
            IS_VM=true
        fi
    elif command -v dmidecode >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
        declare vendor=$(dmidecode -s system-product-name 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if [[ "$vendor" =~ (vmware|virtualbox|qemu|kvm|xen) ]]; then
            IS_VM=true
        fi
    fi

    # Check if running on Debian-based system
    grep -qi "debian" /etc/os-release &>/dev/null && IS_DEBIAN=true

    # Check if running on Fedora-based system (works on RHEL, CentOS, etc.)
    grep -qi "fedora" /etc/os-release &>/dev/null && IS_FEDORA=true

    # NixOS detection
    grep -qi "nixos" /etc/os-release &>/dev/null && IS_NIXOS=true

    true # return true in case os is not recognised to prevent triggering set -e
}

# Initialize YARA rules for advanced malware detection
init_yara_rules() {
    if [[ "$HAS_YARA" != true ]]; then
        return
    fi

    mkdir -p "$YARA_RULES_DIR"

    # Create comprehensive YARA rules
    cat > "$YARA_RULES_DIR/malware_detection.yar" << 'EOF'
rule Suspicious_Base64_Payload {
    meta:
        description = "Detects suspicious base64 encoded payloads"
        severity = "high"
    strings:
        $b64_long = /[A-Za-z0-9+\/]{100,}={0,2}/ fullword
        $eval = "eval"
        $exec = "exec"
        $decode = "base64"
    condition:
        $b64_long and ($eval or $exec or $decode)
}

rule Reverse_Shell_Patterns {
    meta:
        description = "Detects reverse shell command patterns"
        severity = "critical"
    strings:
        $nc_bind = /nca?t? .*-l +-p +[0-9]+/
        $nc_connect = /nca?t? .*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .*[0-9]+/
        $bash_tcp = "/dev/tcp/"
        $python_socket = "socket.socket(socket.AF_INET"
        $perl_socket = "IO::Socket::INET"
        $socat_reverse = /socat.*tcp.*exec/
        $mknod_backpipe = /mknod.*backpipe.*p/
    condition:
        any of them
}

rule Webshell_Indicators {
    meta:
        description = "Detects common webshell patterns"
        severity = "high"
    strings:
        $php_eval = /eval\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_system = /system\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_passthru = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_shell_exec = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/
        $asp_eval = "eval(Request"
        $jsp_runtime = "Runtime.getRuntime().exec"
        $generic_backdoor = /\$_(GET|POST)\[.*\]\s*=.*exec/
    condition:
        any of them
}

rule Crypto_Miner_Indicators {
    meta:
        description = "Detects cryptocurrency mining malware"
        severity = "high"
    strings:
        $stratum1 = "stratum+tcp://"
        $stratum2 = "stratum+ssl://"
        $xmrig = "xmrig"
        $cpuminer = "cpuminer"
        $pool1 = "pool.supportxmr.com"
        $pool2 = "xmr-usa-east1.nanopool.org"
        $wallet = /[49][A-Za-z0-9]{94}/
        $mining_algo = /cryptonight|scrypt|sha256|x11/
    condition:
        any of them
}

rule Process_Injection_Techniques {
    meta:
        description = "Detects process injection indicators"
        severity = "medium"
    strings:
        $ptrace = "ptrace"
        $proc_mem = "/proc/*/mem"
        $ld_preload = "LD_PRELOAD"
        $dlopen = "dlopen"
        $mmap_exec = "PROT_EXEC"
        $shellcode = { 31 c0 50 68 }
    condition:
        any of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Detects persistence establishment attempts"
        severity = "medium"
    strings:
        $crontab = "crontab -e"
        $systemd_service = ".service"
        $bashrc = ".bashrc"
        $profile = ".profile"
        $ssh_keys = "authorized_keys"
        $startup = "/etc/init.d/"
        $rc_declare = "/etc/rc.local"
    condition:
        any of them
}
EOF

    # Create rules for specific threats
    cat > "$YARA_RULES_DIR/apt_indicators.yar" << 'EOF'
rule APT_Lateral_Movement {
    meta:
        description = "Detects APT lateral movement tools"
        severity = "critical"
    strings:
        $psexec = "psexec"
        $wmic = "wmic process call create"
        $schtasks = "schtasks /create"
        $powershell_encoded = "powershell -enc"
        $mimikatz = "sekurlsa::logonpasswords"
        $bloodhound = "SharpHound"
    condition:
        any of them
}

rule Data_Exfiltration {
    meta:
        description = "Detects data exfiltration attempts"
        severity = "high"
    strings:
        $curl_upload = /curl .*-T.*http/
        $wget_post = /wget .*--post-file/
        $nc_file = /nca?t? .*<.*\/.*\//
        $base64_pipe = /base64 .*\|.*curl/
        $tar_remote = /tar .*\|.*nc/
        $scp_remote = /scp .*@/
    condition:
        any of them
}
EOF

    log_info "YARA rules initialized for advanced malware detection"
}

# eBPF-based monitoring for kernel-level observability
start_ebpf_monitoring() {
    if [[ "$HAS_BCC" != true ]] || [[ $EUID -ne 0 ]]; then
        log_info "eBPF monitoring requires root and BCC tools - skipping"
        return
    fi

    log_info "Starting eBPF-based kernel monitoring..."

    # Monitor process execution
    cat > "$SCRIPTS_DIR/ghost_sentinel_execsnoop.py" << 'EOF'
#!/usr/bin/env python3
import sys
import time
from bcc import BPF

# eBPF program to monitor process execution
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    suspicious_patterns = [
        b"nc", b"netcat", b"socat", b"/dev/tcp", b"python -c", b"perl -e",
        b"bash -i", b"sh -i", b"wget", b"curl", b"base64"
    ]

    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')

    for pattern in suspicious_patterns:
        if pattern in filename.encode() or pattern in comm.encode():
            with open('/var/log/ghost-sentinel/ebpf_events.log', 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} SUSPICIOUS_EXEC: PID={event.pid} PPID={event.ppid} COMM={comm} FILE={filename}\n")
            break

try:
    b = BPF(text=bpf_text)
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

    b["events"].open_perf_buffer(print_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
except Exception as e:
    print(f"eBPF monitoring error: {e}")
    sys.exit(1)
EOF

    # Start eBPF monitoring in background
    if command -v python3 >/dev/null 2>&1; then
        python3 "$SCRIPTS_DIR/ghost_sentinel_execsnoop.py" &
        echo $! > "$LOG_DIR/ebpf_monitor.pid"
        log_info "eBPF process monitoring started"
    fi
}

stop_ebpf_monitoring() {
    if [[ -f "$LOG_DIR/ebpf_monitor.pid" ]]; then
        declare ebpf_pid=$(cat "$LOG_DIR/ebpf_monitor.pid" 2>/dev/null || echo "")
        if [[ -n "$ebpf_pid" ]] && kill -0 "$ebpf_pid" 2>/dev/null; then
            kill "$ebpf_pid" 2>/dev/null || true
        fi
        rm -f "$LOG_DIR/ebpf_monitor.pid"

        if [[ -s "$EBPF_LOG" ]]; then
            log_alert "$MEDIUM" "EBPF found $(wc -l < "$EBPF_LOG") suspicious execs: $(tail -n 1 "$EBPF_LOG")"
            mv "$EBPF_LOG" "$EBPF_LOG.$(date +%FT%T).txt"
        fi
    fi
    rm -f "$SCRIPTS_DIR/ghost_sentinel_execsnoop.py"
}

# Honeypot implementation for detecting scanning/attacks
start_honeypots() {
    if ! command -v python3 >/dev/null 2>&1; then
        log_info "python3 not available - honeypots disabled"
        return
    fi

    log_info "Starting honeypot listeners on well-known ports..."

    for port in "${HONEYPOT_PORTS[@]}"; do
        # Check if port is already in use
        if ss -tuln 2>/dev/null | grep -q ":$port "; then
            continue
        fi

        # Start honeypot listener
        (
            while true; do
                declare timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                declare connection_info=""

                connection_info="$(python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("'"${HONEYPOT_BINDADDR-127.0.0.1}"'", '"$port"')); s.listen(1); conn, addr = s.accept(); print(f"Connected: {addr}"); conn.settimeout(10); print(conn.recv(1024)); conn.close()' 2>&1)"

                if [[ -n "$connection_info" ]]; then
                    echo "[$timestamp] HONEYPOT_HIT: Port $port - $connection_info" >> "$HONEYPOT_LOG"
                    log_alert $HIGH "Honeypot triggered on port $port"
                fi

                sleep 1
            done
        ) &

        echo $! >> "$LOG_DIR/honeypot.pids"
    done

    log_info "Honeypots started on ports: ${HONEYPOT_PORTS[*]}"
}

stop_honeypots() {
    if [[ -f "$LOG_DIR/honeypot.pids" ]]; then
        while read pid; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done < "$LOG_DIR/honeypot.pids"
        rm -f "$LOG_DIR/honeypot.pids"
    fi
}

# Anti-evasion detection for advanced threats
detect_anti_evasion() {
    log_info "Running anti-evasion detection..."

    # Detect LD_PRELOAD hijacking
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        log_alert $HIGH "LD_PRELOAD environment variable detected: $LD_PRELOAD"
    fi

    # Check for processes with LD_PRELOAD in environment
    for pid in $(pgrep -f ".*" 2>/dev/null | head -20); do
        if [[ -r "/proc/$pid/environ" ]]; then
            declare environ_content=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null || echo "")
            if echo "$environ_content" | grep -q "LD_PRELOAD="; then
                declare proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                declare preload_libs=$(echo "$environ_content" | grep "LD_PRELOAD=" | cut -d= -f2)
                log_alert $HIGH "Process with LD_PRELOAD detected: $proc_name (PID: $pid, PRELOAD: $preload_libs)"
            fi
        fi
    done

    # Detect /proc inconsistencies (hidden processes)
    declare proc_dirs=$(find /proc -maxdepth 1 -type d -name '[0-9]*' 2>/dev/null | wc -l)
    declare ps_count=$(ps aux --no-headers 2>/dev/null | wc -l)
    declare ps_ef_count=$(ps -ef --no-headers 2>/dev/null | wc -l)

    # Check for significant discrepancies
    declare diff1=$((proc_dirs - ps_count))
    declare diff2=$((proc_dirs - ps_ef_count))

    if [[ $diff1 -gt 15 ]] || [[ $diff2 -gt 15 ]]; then
        log_alert $HIGH "Significant /proc inconsistency detected (proc_dirs: $proc_dirs, ps: $ps_count, ps_ef: $ps_ef_count)"
    fi

    # Detect modified system calls (if root)
    if [[ $EUID -eq 0 ]] && [[ -r /proc/kallsyms ]]; then
        declare suspicious_symbols=$(grep -E "(hijack|detour)" /proc/kallsyms 2>/dev/null | grep -vE '(setup_detour_execution$|arch_uretprobe_hijack_return_addr)' || echo "")
        if [[ -n "$suspicious_symbols" ]]; then
            log_alert $CRITICAL "Suspicious kernel symbols detected: $suspicious_symbols"
        fi
    fi

    # Check for common rootkit hiding techniques
    declare hiding_techniques=(
        "/usr/bin/..."
        "/usr/sbin/..."
        "/lib/.x"
        "/lib64/.x"
        "/tmp/.hidden"
        "/var/tmp/.X11-unix"
    )

    for technique in "${hiding_techniques[@]}"; do
        if [[ -e "$technique" ]]; then
            log_alert $CRITICAL "Rootkit hiding technique detected: $technique"
        fi
    done
}

# Enhanced network monitoring with anti-evasion
monitor_network_advanced() {
    if [[ "$MONITOR_NETWORK" != true ]]; then return; fi

    log_info "Advanced network monitoring with anti-evasion..."

    # Use multiple tools for cross-validation
    # Compare outputs to detect hiding
    local ss_ports="$(ss -Htulnp 2>/dev/null | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    local netstat_ports="$(netstat -tulnp 2>/dev/null | tail -n +3 | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    local lsof_ports="$(lsof -i -P -n 2>/dev/null | grep -vF -- '->' | grep -oE ":[0-9]+ " | sort -u | wc -l)"

    local diff_ss_netstat="$(( ss_ports - netstat_ports ))"
    local diff_ss_lsof="$(( lsof_ports - ss_ports ))"
    local max_diff=1
    if [[ ${diff_ss_netstat#-} -gt $max_diff || ${diff_ss_lsof#-} -gt $max_diff ]]; then
        log_alert $HIGH "Network tool output inconsistency detected (ss: $ss_ports, netstat: $netstat_ports, lsof: $lsof_ports)"
    fi

    # Check for suspicious RAW sockets
    if [[ -r /proc/net/raw ]]; then
        local raw_sockets="$(grep -v "sl" /proc/net/raw 2>/dev/null | wc -l)"
        if [[ $raw_sockets -gt 3 ]]; then
            log_alert $MEDIUM "Multiple RAW sockets detected: $raw_sockets"
        fi
    fi

    # Monitor for covert channels
    local icmp_traffic="$(grep "ICMP" /proc/net/snmp 2>/dev/null | tail -1 | awk '{print $3}' || echo 0)"
    if [[ $icmp_traffic -gt 1000 ]]; then
        log_alert $MEDIUM "High ICMP traffic detected: $icmp_traffic packets"
    fi

    # Check for connections to suspicious ip addresses
    if [[ -f "$THREAT_INTEL_DIR/malicious_ips.txt" ]]; then
        # grep ipv4 from netstat and filter out local and private ip ranges, then check if they are in the malicious ip cidr list
        local malicious_ips="$(netstat -np 2>/dev/null | \
        grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'| \
        sort -u | \
        grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|22[4-9]\.|23[0-9]\.)'  | \
        python3 -c "import sys, ipaddress; cidrs = [ipaddress.ip_network(l.strip()) for l in open('$THREAT_INTEL_DIR/malicious_ips.txt') if l.strip() and not '#' in l]; [print(f'{ip.strip()}') for ip in sys.stdin if ip.strip() and any(ipaddress.ip_address(ip.strip()) in cidr for cidr in cidrs)];")"

        if [[ -n $malicious_ips ]]; then
            log_alert $HIGH "Detected connections to malicious ips: $malicious_ips"
        fi
    fi
}

# YARA-enhanced file monitoring
monitor_files_with_yara() {
    if [[ "$MONITOR_FILES" != true ]]; then return; fi

    log_info "File monitoring with YARA malware detection..."

    # Scan suspicious locations with YARA
    declare scan_locations=("/tmp" "/var/tmp" "/dev/shm")

    for location in "${scan_locations[@]}"; do
        if [[ -d "$location" ]] && [[ -r "$location" ]]; then
            find "$location" -maxdepth 2 -type f -mtime -1 2>/dev/null | while read -r file; do
                # Skip very large files for performance
                declare file_size=$(stat -c%s "$file" 2>/dev/null || echo 0)
                if [[ $file_size -gt 1048576 ]]; then  # Skip files > 1MB
                    continue
                fi

                # Perform YARA scan if available
                if [[ "$HAS_YARA" == true ]]; then
                    declare yara_result=""
                    yara_result+=$(find "$YARA_RULES_DIR" -name '*.yar' -print0 | xargs -0 -I {} yara -s {} -r "$file" 2>/dev/null || echo "")
                    if [[ -n "$yara_result" ]]; then
                        log_alert $CRITICAL "YARA detection: $yara_result"
                        quarantine_file_forensic "$file"
                        continue
                    fi
                fi

                # Fallback pattern matching
                if [[ -r "$file" ]]; then
                    declare suspicious_content=$(grep -l -E "(eval.*base64|exec.*\\\$|/dev/tcp|socket\.socket.*connect)" "$file" 2>/dev/null || echo "")
                    if [[ -n "$suspicious_content" ]]; then
                        log_alert $HIGH "Suspicious script content: $file"
                        quarantine_file_forensic "$file"
                    fi
                fi
            done || true
        fi
    done

    # Perform online YARA monitoring
    if [[ "$HAS_YARA" == true ]] && [[ "$HAS_INOTIFY" == "true" ]] && [[ "$PERFORMANCE_MODE" == "false" ]]; then
    {
        inotifywait -q -m -e close_write -r --format '%w%f' --  "${scan_locations[@]}" | while read -r file; do
            declare file_size=$(stat -c%s "$file" 2>/dev/null || echo 0)
            if [[ $file_size -gt 1048576 ]]; then  # Skip files > 1MB
                continue
            fi

            declare yara_result=""
            yara_result=$(find "$YARA_RULES_DIR" -name '*.yar' -print0 | xargs -0 -I {} yara -s {} -r "$file" 2>/dev/null || echo "")
            if [[ -n "$yara_result" ]]; then
                log_alert $CRITICAL "YARA detection: $yara_result"
                quarantine_file_forensic "$file"
            fi
        done
    } &
fi

}

# Enhanced quarantine with YARA analysis and forensics
quarantine_file_forensic() {
    declare file="$1"
    declare timestamp=$(date +%s)
    declare quarantine_name="$(basename "$file")_$timestamp"

    if [[ -f "$file" ]] && [[ -w "$(dirname "$file")" ]]; then
        # Create forensic directory
        declare forensic_dir="$QUARANTINE_DIR/forensics"
        mkdir -p "$forensic_dir"

        # Preserve all metadata
        stat "$file" > "$forensic_dir/${quarantine_name}.stat" 2>/dev/null || true
        ls -la "$file" > "$forensic_dir/${quarantine_name}.ls" 2>/dev/null || true
        file "$file" > "$forensic_dir/${quarantine_name}.file" 2>/dev/null || true

        # Create hash for integrity
        sha256sum "$file" > "$forensic_dir/${quarantine_name}.sha256" 2>/dev/null || true

        # YARA analysis if available
        if [[ "$HAS_YARA" == true ]] && [[ -r "$file" ]]; then
            yara -s -r "$YARA_RULES_DIR" "$file" > "$forensic_dir/${quarantine_name}.yara" 2>/dev/null || true
        fi

        # String analysis
        if command -v strings >/dev/null 2>&1; then
            strings "$file" | head -100 > "$forensic_dir/${quarantine_name}.strings" 2>/dev/null || true
        fi

        if [[ "${QUARANTINE_ENABLE-true}" == "false" ]]; then
          return
        fi

        # Move to quarantine
        if mv "$file" "$QUARANTINE_DIR/$quarantine_name" 2>/dev/null; then
            log_info "File quarantined with forensics: $file -> $QUARANTINE_DIR/$quarantine_name"

            # Create safe placeholder
            touch "$file" 2>/dev/null || true
            chmod 000 "$file" 2>/dev/null || true
        else
            log_info "Failed to quarantine file: $file"
        fi
    fi
}

# Initialize enhanced directory structure
init_sentinel() {
    # Create directories FIRST
    for dir in "$LOG_DIR" "$BASELINE_DIR" "$ALERTS_DIR" "$QUARANTINE_DIR" "$THREAT_INTEL_DIR" "$YARA_RULES_DIR" "$SCRIPTS_DIR"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
            echo -e "${RED}[ERROR]${NC} Cannot create directory: $dir"
            echo "Please run as root or ensure write permissions"
            exit 1
        fi
    done
    chmod 700 "$SCRIPTS_DIR"

    # Load configuration BEFORE doing anything else
    load_config_safe

    # Check dependencies
    check_dependencies

    # Initialize components
    init_yara_rules

    log_info "Initializing Ghost Sentinel v2.3..."

    # Detect environment
    detect_environment
    if [[ "$IS_CONTAINER" == true ]]; then
        log_info "Container environment detected - adjusting monitoring"
    fi
    if [[ "$IS_VM" == true ]]; then
        log_info "Virtual machine environment detected"
    fi

    # Update threat intelligence
    update_threat_intelligence

    # Create/update baseline
    if [[ ! -f "$BASELINE_DIR/.initialized" ]] || [[ "${FORCE_BASELINE:-false}" == true ]]; then
        log_info "Creating security baseline..."
        create_baseline
        touch "$BASELINE_DIR/.initialized"
    fi
}

# Load configuration with enhanced validation
load_config_safe() {
    # Set secure defaults
    MONITOR_NETWORK=${MONITOR_NETWORK:-true}
    MONITOR_PROCESSES=${MONITOR_PROCESSES:-true}
    MONITOR_FILES=${MONITOR_FILES:-true}
    MONITOR_USERS=${MONITOR_USERS:-true}
    MONITOR_ROOTKITS=${MONITOR_ROOTKITS:-true}
    MONITOR_MEMORY=${MONITOR_MEMORY:-true}
    ENABLE_ANTI_EVASION=${ENABLE_ANTI_EVASION:-true}
    ENABLE_EBPF=${ENABLE_EBPF:-true}
    ENABLE_HONEYPOTS=${ENABLE_HONEYPOTS:-true}
    ENABLE_YARA=${ENABLE_YARA:-true}
    SEND_EMAIL=${SEND_EMAIL:-false}
    EMAIL_RECIPIENT=${EMAIL_RECIPIENT:-""}
    WEBHOOK_URL=${WEBHOOK_URL:-""}
    SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-""}
    ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY:-""}
    VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY:-""}
    SYSLOG_ENABLED=${SYSLOG_ENABLED:-true}
    PERFORMANCE_MODE=${PERFORMANCE_MODE:-false}
    ENABLE_THREAT_INTEL=${ENABLE_THREAT_INTEL:-true}

    # Secure whitelists with exact matching
    WHITELIST_PROCESSES=${WHITELIST_PROCESSES:-("firefox" "chrome" "nmap" "masscan" "nuclei" "gobuster" "ffuf" "subfinder" "httpx" "amass" "burpsuite" "wireshark" "metasploit" "sqlmap" "nikto" "dirb" "wpscan" "john" "docker" "containerd" "systemd" "kthreadd" "bash" "zsh" "ssh" "python3" "yara")}
    WHITELIST_CONNECTIONS=${WHITELIST_CONNECTIONS:-("127.0.0.1" "::1" "0.0.0.0" "8.8.8.8" "1.1.1.1" "208.67.222.222" "1.0.0.1" "9.9.9.9")}
    EXCLUDE_PATHS=${EXCLUDE_PATHS:-("/opt/metasploit-framework" "/usr/share/metasploit-framework" "/usr/share/wordlists" "/home/*/go/bin" "/tmp/nuclei-templates" "/var/lib/docker" "/var/lib/containerd" "/snap")}
    CRITICAL_PATHS=${CRITICAL_PATHS:-("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/hosts")}

    # Load and validate config file
    if [[ -f "$CONFIG_FILE" ]]; then
        if source "$CONFIG_FILE" 2>/dev/null; then
            log_info "Configuration loaded from $CONFIG_FILE"
        else
            log_info "Warning: Config file syntax error, using defaults"
        fi
    fi
}

# Enhanced logging with tamper resistance
log_alert() {
    declare level=$1
    declare message="$2"
    declare timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        $CRITICAL) echo -e "${RED}[CRITICAL]${NC} $message" ;;
        $HIGH)     echo -e "${YELLOW}[HIGH]${NC} $message" ;;
        $MEDIUM)   echo -e "${BLUE}[MEDIUM]${NC} $message" ;;
        $LOW)      echo -e "${GREEN}[LOW]${NC} $message" ;;
    esac

    # Write to alert file with integrity check
    if [[ -n "$ALERTS_DIR" ]]; then
        mkdir -p "$ALERTS_DIR" 2>/dev/null || true
        declare alert_file="$ALERTS_DIR/$(date +%Y%m%d).log"
        declare log_entry="[$timestamp] [LEVEL:$level] $message"
        echo "$log_entry" >> "$alert_file" 2>/dev/null || true

        # Add checksum for integrity
        echo "$(echo "$log_entry" | sha256sum | cut -d' ' -f1)" >> "$alert_file.hash" 2>/dev/null || true
    fi

    # Send to syslog with facility (only if SYSLOG_ENABLED is set)
    if [[ "${SYSLOG_ENABLED:-false}" == true ]] && command -v logger >/dev/null 2>&1; then
        logger -t "ghost-sentinel[$]" -p security.alert -i "$message" 2>/dev/null || true
    fi

    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        # Send to Telegram with bot token and chat ID
        curl --max-time 5 -s --fail -X POST --url "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" -d chat_id="${TELEGRAM_CHAT_ID}" -d text="$(hostname) ${level}: ${message}" >/dev/null || echo "Telegram alert failed"
    fi


    # Critical alerts trigger immediate response
    if [[ $level -eq $CRITICAL ]]; then
        send_critical_alert "$message"
    fi
}

log_info() {
    declare timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${CYAN}[INFO]${NC} $1"

    if [[ -n "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || true
        echo "[$timestamp] [INFO] $1" >> "$LOG_DIR/sentinel.log" 2>/dev/null || true
    fi
}

# Enhanced critical alert handling with fallbacks
send_critical_alert() {
    declare message="$1"

    # Email notification with fallback check
    if [[ "$SEND_EMAIL" == true ]] && [[ -n "$EMAIL_RECIPIENT" ]]; then
        if command -v mail >/dev/null 2>&1; then
            echo "CRITICAL SECURITY ALERT: $message" | mail -s "Ghost Sentinel Alert" "$EMAIL_RECIPIENT" 2>/dev/null || true
        elif command -v sendmail >/dev/null 2>&1; then
            echo -e "Subject: Ghost Sentinel Critical Alert\n\nCRITICAL SECURITY ALERT: $message" | sendmail "$EMAIL_RECIPIENT" 2>/dev/null || true
        fi
    fi

    # Webhook notification with improved error handling
    if [[ -n "$WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        curl -s --max-time 10 -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"alert\":\"CRITICAL\",\"message\":\"$message\",\"timestamp\":\"$(date -Iseconds)\",\"hostname\":\"$(hostname)\"}" 2>/dev/null || true
    fi

    # Slack webhook with rich formatting
    if [[ -n "$SLACK_WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        declare payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "danger",
            "title": "🚨 Ghost Sentinel v2.3 Critical Alert",
            "text": "$message",
            "fields": [
                {
                    "title": "Hostname",
                    "value": "$(hostname)",
                    "short": true
                },
                {
                    "title": "Timestamp",
                    "value": "$(date)",
                    "short": true
                }
            ],
            "footer": "Ghost Sentinel v2.3",
            "ts": $(date +%s)
        }
    ]
}
EOF
)
        curl -s --max-time 10 -X POST "$SLACK_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "$payload" 2>/dev/null || true
    fi
}

# Enhanced threat intelligence with caching
update_threat_intelligence() {
    if [[ "$ENABLE_THREAT_INTEL" != true ]]; then
        return
    fi

    log_info "Updating threat intelligence feeds..."

    declare intel_file="$THREAT_INTEL_DIR/malicious_ips.txt"
    declare intel_timestamp="$THREAT_INTEL_DIR/.last_update"

    # Check if update is needed (every 6 hours by default)
    declare update_needed=true
    if [[ -f "$intel_timestamp" ]]; then
        declare last_update=$(cat "$intel_timestamp" 2>/dev/null || echo 0)
        declare current_time=$(date +%s)
        declare age=$((current_time - last_update))
        declare max_age=$((THREAT_INTEL_UPDATE_HOURS * 3600))

        if [[ $age -lt $max_age ]]; then
            update_needed=false
        fi
    fi

    if [[ "$update_needed" == true ]]; then
        # Download threat feeds (with timeout and verification)
        declare temp_file=$(mktemp)

        # FireHOL Level 1 blocklist (reliable source)
        if command -v curl >/dev/null 2>&1; then
            if curl -s --max-time 30 -o "$temp_file" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" 2>/dev/null; then
                # Better validation - check for IP addresses and reasonable file size
                if [[ -s "$temp_file" ]] && [[ $(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$temp_file" | wc -l) -gt 100 ]]; then
                    mv "$temp_file" "$intel_file"
                    echo $(date +%s) > "$intel_timestamp"
                    log_info "Threat intelligence updated successfully ($(wc -l < "$intel_file" 2>/dev/null || echo 0) entries)"
                else
                    rm -f "$temp_file"
                    log_info "Threat intelligence update failed - validation failed"
                fi
            else
                rm -f "$temp_file"
                log_info "Threat intelligence update failed - network error"
            fi
        fi
    fi
}

# Enhanced helper functions with exact matching
is_whitelisted_process() {
    declare process="$1"
    declare proc_basename=$(basename "$process" 2>/dev/null || echo "$process")

    for whitelisted in "${WHITELIST_PROCESSES[@]}"; do
        if [[ "$proc_basename" == "$whitelisted" ]]; then
            return 0
        fi
    done
    return 1
}

is_whitelisted_connection() {
    declare addr="$1"
    for whitelisted in "${WHITELIST_CONNECTIONS[@]}"; do
        if [[ "$addr" == "$whitelisted" ]]; then
            return 0
        fi
    done
    return 1
}

is_private_address() {
    declare addr="$1"

    # RFC 1918 private networks + localhost + link-local
    if [[ "$addr" =~ ^10\. ]] || [[ "$addr" =~ ^192\.168\. ]] || [[ "$addr" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        return 0
    fi
    if [[ "$addr" =~ ^127\. ]] || [[ "$addr" =~ ^169\.254\. ]] || [[ "$addr" == "::1" ]] || [[ "$addr" =~ ^fe80: ]]; then
        return 0
    fi

    # Multicast and broadcast
    if [[ "$addr" =~ ^(224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.) ]]; then
        return 0
    fi

    return 1
}

# Enhanced threat intelligence checking
is_malicious_ip() {
    declare addr="$1"
    declare intel_file="$THREAT_INTEL_DIR/malicious_ips.txt"

    # Skip private addresses
    if is_private_address "$addr"; then
        return 1
    fi

    # Check declare threat intelligence
    if [[ -f "$intel_file" ]]; then
        if grep -q "^$addr" "$intel_file" 2>/dev/null; then
            return 0
        fi
    fi

    # Check against AbuseIPDB if API key is available
    if [[ -n "$ABUSEIPDB_API_KEY" ]] && command -v curl >/dev/null 2>&1; then
        declare cache_file="$THREAT_INTEL_DIR/abuseipdb_$addr"
        declare cache_age=3600  # 1 hour cache

        # Check cache first
        if [[ -f "$cache_file" ]]; then
            declare file_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
            if [[ $file_age -lt $cache_age ]]; then
                declare cached_result=$(cat "$cache_file" 2>/dev/null || echo "0")
                if [[ "$cached_result" -gt 75 ]]; then
                    return 0
                else
                    return 1
                fi
            fi
        fi

        # Query AbuseIPDB with rate limiting
        declare response=$(curl -s --max-time 5 -G https://api.abuseipdb.com/api/v2/check \
            --data-urlencode "ipAddress=$addr" \
            -H "Key: $ABUSEIPDB_API_KEY" \
            -H "Accept: application/json" 2>/dev/null || echo "")

        if [[ -n "$response" ]]; then
            declare confidence=0
            if command -v jq >/dev/null 2>&1; then
                confidence=$(echo "$response" | jq -r '.data.abuseConfidencePercentage // 0' 2>/dev/null || echo 0)
            else
                # Fallback parsing
                confidence=$(echo "$response" | grep -o '"abuseConfidencePercentage":[0-9]*' | cut -d: -f2 || echo 0)
            fi

            # Cache the result
            echo "$confidence" > "$cache_file"

            if [[ $confidence -gt 75 ]]; then
                return 0
            fi
        fi
    fi

    return 1
}

# Performance-optimized baseline creation
create_baseline() {
    log_info "Creating optimized security baseline..."

    # Network baseline
    if command -v ss >/dev/null 2>&1; then
        ss -tulnp --no-header > "$BASELINE_DIR/network_baseline.txt" 2>/dev/null || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp --numeric-hosts --numeric-ports > "$BASELINE_DIR/network_baseline.txt" 2>/dev/null || true
    fi

    # Process baseline (structured)
    ps -eo pid,ppid,user,comm,cmd --no-headers > "$BASELINE_DIR/process_baseline.txt" 2>/dev/null || true

    # Services baseline
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running --no-pager --no-legend --plain > "$BASELINE_DIR/services_baseline.txt" 2>/dev/null || true
    fi

    # Critical file baselines (performance optimized)
    for file in "${CRITICAL_PATHS[@]}"; do
        if [[ -e "$file" ]] && [[ -r "$file" ]] && [[ -f "$file" ]]; then
            sha256sum "$file" > "$BASELINE_DIR/$(basename "$file")_baseline.sha256" 2>/dev/null || true
        fi
    done

    # User baseline
    if [[ -r /etc/passwd ]]; then
        cut -d: -f1 /etc/passwd | sort > "$BASELINE_DIR/users_baseline.txt" 2>/dev/null || true
    fi

    # Login history (limited)
    if command -v last >/dev/null 2>&1; then
        last -n 10 --time-format=iso > "$BASELINE_DIR/last_baseline.txt" 2>/dev/null || true
    fi

    # Package state (hash only for performance)
    declare pkg_hash=""
    if [[ "$IS_DEBIAN" == true ]]; then
        pkg_hash=$(dpkg -l 2>/dev/null | sha256sum | cut -d' ' -f1)
        dpkg --get-selections | sort -u > "$BASELINE_DIR/packages_list.txt"
    elif [[ "$IS_FEDORA" == true ]]; then
        pkg_hash=$(rpm -qa --queryformat="%{NAME}-%{VERSION}-%{RELEASE}\n" 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    elif command -v pacman > /dev/null 2>/dev/null; then
        pacman -Qq | sort -u > "$BASELINE_DIR/packages_list.txt"
        pkg_hash=$(pacman -Q | sort | sha256sum | cut -d' ' -f1)
    fi

    if [[ "$IS_NIXOS" == true ]]; then
        pkg_hash=$(nix-store --query --requisites /run/current-system | cut -d- -f2- | sort | uniq)
    fi

    if [[ -n "$pkg_hash" ]]; then
        echo "$pkg_hash" > "$BASELINE_DIR/packages_hash.txt"
    fi

    # SUID/SGID baseline (limited scope)
    find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -perm /4000 -o -perm /2000 2>/dev/null | sort > "$BASELINE_DIR/suid_baseline.txt" || true

    log_info "Baseline created successfully"
}

# Production main function with all v2.3 features
main_enhanced() {
    declare start_time=$(date +%s)

    log_info "Ghost Sentinel v2.3 Enhanced - Starting advanced security scan..."

    # Initialize system
    init_sentinel

    # Start advanced monitoring features
    declare features_enabled=()

    if [[ "$ENABLE_EBPF" == true ]] && [[ "$HAS_BCC" == true ]] && [[ $EUID -eq 0 ]]; then
        start_ebpf_monitoring
        features_enabled+=("ebpf")
    fi

    if [[ "$ENABLE_HONEYPOTS" == true ]] && [[ $EUID -eq 0 ]]; then
        start_honeypots
        features_enabled+=("honeypots")
    fi

    if [[ "$ENABLE_API_SERVER" == true ]]; then
        start_api_server
        features_enabled+=("api")
    fi

    if [[ "$ENABLE_YARA" == true ]] && [[ "$HAS_YARA" == true ]]; then
        features_enabled+=("yara")
    fi

    # Run monitoring modules with timeout protection
    declare modules_run=()

    if [[ "$ENABLE_ANTI_EVASION" == true ]]; then
        log_info "Running anti-evasion detection..."
        if detect_anti_evasion; then
            modules_run+=("anti-evasion")
        fi
    fi

    log_info "Running network monitoring..."
    if monitor_network_advanced; then
        modules_run+=("network")
    fi

    if [[ "$HAS_YARA" == true ]]; then
        log_info "Running file monitoring with YARA..."
        if monitor_files_with_yara; then
            modules_run+=("files-yara")
        fi
    fi

    log_info "Running process monitoring..."
    if monitor_processes; then
        modules_run+=("processes")
    fi

    log_info "Running user monitoring..."
    if monitor_users; then
        modules_run+=("users")
    fi

    log_info "Running rootkit detection..."
    if monitor_rootkits; then
        modules_run+=("rootkits")
    fi

    log_info "Running memory monitoring..."
    if monitor_memory; then
        modules_run+=("memory")
    fi

    declare end_time=$(date +%s)
    declare duration=$((end_time - start_time))


    log_info "Advanced security scan completed in ${duration}s"

    if [[ ${#features_enabled[@]} -gt 0 ]]; then
        log_info "Advanced features active: ${features_enabled[*]}"
    fi
}


monitor_processes() {
    if [[ "$MONITOR_PROCESSES" != true ]]; then return; fi
    log_info "Basic process monitoring..."

    # Check for suspicious processes
    declare suspicious_procs=("^nc" "netcat" "socat" "ncat")
    for proc in "${suspicious_procs[@]}"; do
        if pgrep -f "$proc" >/dev/null 2>&1; then
            pgrep -f "$proc" 2>/dev/null | head -3 | while read pid; do
                declare proc_info=$(ps -p "$pid" -o user,comm,args --no-headers 2>/dev/null || echo "")
                if [[ -n "$proc_info" ]]; then
                    declare user=$(echo "$proc_info" | awk '{print $1}')
                    declare comm=$(echo "$proc_info" | awk '{print $2}')
                    declare args=$(echo "$proc_info" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}')

                    if ! is_whitelisted_process "$comm"; then
                        log_alert $MEDIUM "Potentially suspicious process: $comm (User: $user, PID: $pid)"
                    fi
                fi
            done
        fi
    done
}

monitor_files() {
    if [[ "$HAS_YARA" == true ]]; then
        monitor_files_with_yara
    fi
}

monitor_users() {
    if [[ "$MONITOR_USERS" != true ]]; then return; fi
    log_info "Basic user monitoring..."

    # Check for new users
    if [[ -r /etc/passwd ]] && [[ -f "$BASELINE_DIR/users_baseline.txt" ]]; then
        declare current_users=$(cut -d: -f1 /etc/passwd | sort)
        declare new_users=$(comm -13 "$BASELINE_DIR/users_baseline.txt" <(echo "$current_users") 2>/dev/null | head -3)

        if [[ -n "$new_users" ]]; then
            echo "$new_users" | while read user; do
                if getent passwd "$user" >/dev/null 2>&1; then
                    log_alert $HIGH "New user account detected: $user"
                fi
            done
        fi
    fi
}

monitor_rootkits() {
    if [[ "$MONITOR_ROOTKITS" != true ]]; then return; fi
    log_info "Basic rootkit detection..."

    # Check for common rootkit indicators
    declare rootkit_paths=("/tmp/.ICE-unix/.X11-unix" "/dev/shm/.hidden" "/tmp/.hidden" "/usr/bin/..." "/usr/sbin/...")

    for path in "${rootkit_paths[@]}"; do
        if [[ -e "$path" ]]; then
            log_alert $CRITICAL "Rootkit indicator found: $path"
        fi
    done
}

monitor_memory() {
    if [[ "$MONITOR_MEMORY" != true ]]; then return; fi
    log_info "Basic memory monitoring..."

    # Check for high memory usage
    ps aux --sort=-%mem --no-headers 2>/dev/null | head -3 | while read line; do
        declare mem_usage=$(echo "$line" | awk '{print $4}')
        declare proc_name=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null)
        declare pid=$(echo "$line" | awk '{print $2}')

        if ! is_whitelisted_process "$proc_name"; then
            if (( $(echo "$mem_usage > 80" | bc -l 2>/dev/null || echo 0) )); then
                log_alert $MEDIUM "High memory usage: $proc_name (PID: $pid, MEM: $mem_usage%)"
            fi
        fi
    done
}


# Create systemd service for enhanced integration
create_systemd_service() {
    declare service_file="/etc/systemd/system/ghost-sentinel.service"

    cat > "$service_file" << EOF
[Unit]
Description=Ghost Sentinel v2.3 Security Monitor
After=network.target

[Service]
Type=notify
# Run for an hour, then restart
ExecStart=$SCRIPT_PATH daemon 3600
ExecStopPost=/bin/sh -c "[ \$SERVICE_RESULT != 'success' ] && $SCRIPT_PATH alert \"Ghost sentinel systemd unit failed: \$EXIT_CODE \$EXIT_STATUS\"; exit 0"
User=root
StandardOutput=journal
StandardError=journal
Restart=on-success
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ghost-sentinel
    #systemctl start ghost-sentinel # TODO: lock file problem

    log_info "Systemd service and timer installed"
}

# === MAIN EXECUTION ===

# Acquire exclusive lock with stale lock detection
acquire_lock

# Command line interface with new v2.3 options
case "${1:-run}" in
"baseline")
    FORCE_BASELINE=true
    init_sentinel
    ;;
"config")
    ${EDITOR:-nano} "$CONFIG_FILE"
    ;;
"logs")
    init_sentinel
    if [[ -f "$LOG_DIR/sentinel.log" ]]; then
        tail -f "$LOG_DIR/sentinel.log"
    else
        echo "No log file found. Run a scan first."
    fi
    ;;
"alerts")
    init_sentinel
    declare today=$(date +%Y%m%d)
    if [[ -f "$ALERTS_DIR/$today.log" ]]; then
        cat "$ALERTS_DIR/$today.log"
    else
        echo "No alerts for today"
    fi
    ;;
"daemon")
    main_enhanced
    sleep "$2" &
    systemd-notify --ready --status=Up
    wait -n # wait until any of the processes exit (honeypots, ebpf or sleep)
    systemd-notify --stopping --status=Stopping 2>/dev/null || true # --stopping is not supported on some systems
    ;;
"systemd")
    if [[ $EUID -eq 0 ]]; then
        create_systemd_service
    else
        echo "systemd integration requires root privileges"
    fi
    ;;
"honeypot")
    if [[ "$EUID" -eq 0 ]]; then
        init_sentinel
        start_honeypots
        echo "Honeypots started. Press Ctrl+C to stop."
        read -r
        stop_honeypots
    else
        echo "Honeypots require root privileges"
    fi
    ;;
"yara")
    init_sentinel
    if [[ "$HAS_YARA" == true ]]; then
        monitor_files_with_yara
    else
        echo "YARA not available - install yara package"
    fi
    ;;
"ebpf")
    init_sentinel
    if [[ "$HAS_BCC" == true ]] && [[ $EUID -eq 0 ]]; then
        start_ebpf_monitoring
        echo "eBPF monitoring started. Press Ctrl+C to stop."
        read -r
        stop_ebpf_monitoring
    else
        echo "eBPF monitoring requires root privileges and BCC tools"
    fi
    ;;
"alert")
    load_config_safe
    log_alert "$HIGH" "$2"
    ;;
*)
    main_enhanced
    ;;
esac
