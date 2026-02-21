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

LOG_DIR="/var/log/ghost-sentinel"
CONFIG_FILE="$SCRIPT_DIR/sentinel.conf"
BASELINE_DIR="$LOG_DIR/baseline"
QUARANTINE_DIR="$LOG_DIR/quarantine"
THREAT_INTEL_DIR="$LOG_DIR/threat_intel"
YARA_RULES_DIR="$LOG_DIR/yara_rules"
SCRIPTS_DIR="$LOG_DIR/scripts"
HONEYPOT_LOG="$LOG_DIR/honeypot.log"
EBPF_LOG="$LOG_DIR/ebpf_events.log"

# Alert levels, consistent with journald
CRITICAL=2
HIGH=3
MEDIUM=4

# Performance and security controls
THREAT_INTEL_UPDATE_HOURS=6
HONEYPOT_PORTS=("2222" "8080" "23" "21" "3389")


trap stop_ebpf_monitoring EXIT INT TERM

# Environment detection
HAS_INOTIFY=false
HAS_YARA=false
HAS_BCC=false
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

# Initialize YARA rules for advanced malware detection
init_yara_rules() {
    if [[ "$HAS_YARA" != true ]]; then
        return
    fi

    mkdir -p "$YARA_RULES_DIR"

    # Create comprehensive YARA rules
    cat > "$YARA_RULES_DIR/malware_detection.yar" << 'EOF'

import "pe"
import "elf"
import "hash"

rule Enterprise_Malware_Detection {
    meta:
        description = "Enterprise-grade malware detection with multiple indicators"
        author = "Ghost Sentinel"
        severity = "high"
        category = "malware"
        tags = "enterprise,malware,detection"
        minimum_yara = "3.8.0"
        reference = "https://example.com/threat-report"  // Add real reference
        date = "2024-01-08"
    strings:
        $obfuscation1 = { 58 6F 62 66 75 73 63 61 74 65 } // :obfuscate - exact hex match
        $obfuscation2 = /\b(eval|base64_decode|gzinflate|str_rot13)\s*\(/ nocase  // Non-capturing, word-bound
        $obfuscation3 = { 5B 27 5D 2E 5B 27 5D } // [''].[''] pattern
        $shellcode1 = { B8 ?? ?? ?? ?? C1 C8 08 C1 C8 08 C1 C8 08 C1 C8 08 } // mov eax, imm32; ror eax, 8 (4x)
        $shellcode2 = { 31 C0 50 68 } // xor eax,eax; push eax; push imm32
        $shellcode3 = { 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 89 C1 89 C2 CD 80 } // Linux execve shell
        $memory1 = { 64 A1 30 00 00 00 } // mov eax, fs:[0x30] (PEB access)
        $memory2 = { 8B 40 0C 8B 40 1C 8B 00 8B 00 8B 40 08 } // PEB->Ldr->InLoadOrderModuleList traversal
        $anti_analysis1 = { 0F 31 } // rdtsc
        $anti_analysis2 = { 0F A2 } // cpuid
        $anti_analysis3 = /\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)\b/ nocase fullword
    condition:
        filesize < 50MB and (  // Increased size limit for better coverage
            (3 of ($obfuscation*)) or  // Stricter threshold
            (any of ($shellcode*)) or
            (2 of ($memory*)) or
            (2 of ($anti_analysis*)) or
            (pe.is_pe and pe.sections[0].name == ".text" and pe.sections[0].raw_data_size > 100KB) or
            (elf.type == elf.ET_EXEC and elf.entry_point < 0x1000)  // Added ELF check
        )
}
rule Advanced_Persistence_Mechanisms {
    meta:
        description = "Advanced persistence mechanism detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "persistence"
        tags = "enterprise,persistence,apt"
        reference = "https://attack.mitre.org/techniques/T1547/"
        date = "2026-01-08"
    strings:
        $reg1 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase fullword
        $reg2 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce/ nocase fullword
        $reg3 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run/ nocase fullword
        $service1 = /\b(sc\.exe|net\.exe|powershell)\s+(create|start)/ nocase
        $service2 = /New-Service\s+-/ nocase
        $task1 = /\b(schtasks|schtasks\.exe)\s+/ nocase
        $task2 = /at\.exe\s+/ nocase
        $startup1 = /AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/ nocase
        $startup2 = /ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp/ nocase
        $dll1 = /KnownDLLs/ nocase fullword
        $dll2 = /AppInit_DLLs/ nocase fullword
        $wmi1 = /winmgmts:\\root\\subscription/ nocase
        $wmi2 = /ActiveScriptEventConsumer/ nocase fullword
        $cron = /crontab\s+-l/ nocase  // Linux cron
        $systemd = /systemctl\s+enable/ nocase  // Linux systemd
    condition:
        filesize < 10MB and pe.is_pe and (any of them)
}
rule Enterprise_Crypto_Mining {
    meta:
        description = "Enterprise crypto mining detection with wallet patterns"
        author = "Ghost Sentinel"
        severity = "high"
        category = "cryptomining"
        tags = "enterprise,miner,crypto"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-01-08"
    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = /\.mining\.pool/ nocase
        $pool4 = /pool\.[a-z0-9]+\.com/ nocase  // More specific
        $miner1 = "xmrig" nocase fullword
        $miner2 = "cpuminer" nocase fullword
        $miner3 = "ethminer" nocase fullword
        $miner4 = "cgminer" nocase fullword
        $miner5 = "bfgminer" nocase fullword
        $wallet_btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $wallet_xmr = /[48][0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}/
        $wallet_eth = /0x[a-fA-F0-9]{40}/
        $wallet_sol = /So[0-9A-Za-z]{32,44}/  // Solana wallet
        $algo1 = /\b(cryptonight|randomx|kawpow|ethash)\b/ nocase
        $algo2 = /\b(scrypt|sha256|x11|equihash)\b/ nocase
        $cmd1 = /--cpu-priority/ nocase
        $cmd2 = /--threads/ nocase
        $cmd3 = /--gpu/ nocase
    condition:
        filesize < 10MB and (
            (any of ($miner*)) or
            (2 of ($pool*)) or
            (any of ($wallet*)) or
            (2 of ($algo*)) or
            (3 of ($cmd*))
        )
}
rule APT_Lateral_Movement_Advanced {
    meta:
        description = "Advanced APT lateral movement detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "apt"
        tags = "enterprise,apt,lateral_movement"
        reference = "https://attack.mitre.org/tactics/TA0008/"
        date = "2026-01-08"
    strings:
        $tool1 = "mimikatz" nocase fullword
        $tool2 = "bloodhound" nocase fullword
        $tool3 = "sharphound" nocase
        $tool4 = "cobaltstrike" nocase
        $tool5 = "empire" nocase
        $tool6 = "metasploit" nocase fullword
        $tool7 = "sliver" nocase fullword
        $tool8 = "havoc" nocase fullword
        $ps1 = /\bIEX\s*\(/ nocase
        $ps2 = /New-Object\s+Net\.WebClient/ nocase
        $ps3 = /DownloadString\s*\(/ nocase
        $ps4 = /Invoke-Expression/ nocase
        $lotl1 = /bitsadmin\s+/ nocase
        $lotl2 = /certutil\s+-urlcache/ nocase
        $lotl3 = /mshta\s+/ nocase
        $lotl4 = /rundll32\s+/ nocase
        $recon1 = /nmap\s+/ nocase
        $recon2 = /masscan\s+/ nocase
        $recon3 = /zmap\s+/ nocase
        $exfil1 = /rclone\s+/ nocase
        $exfil2 = /megatools\s+/ nocase
        $exfil3 = /scp\s+/ nocase
    condition:
        filesize < 10MB and pe.is_pe and (
            (any of ($tool*)) or
            (3 of ($ps*)) or
            (2 of ($lotl*)) or
            (any of ($recon*)) or
            (2 of ($exfil*))
        )
}

rule Enterprise_Ransomware_Indicators {
    meta:
        description = "Enterprise ransomware detection patterns"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "ransomware"
        tags = "enterprise,ransomware,encryption"
    strings:
        $encrypt1 = /vssadmin\s+delete\s+shadows/ nocase
        $encrypt2 = /wbadmin\s+delete\s+backup/ nocase
        $encrypt3 = /bcdedit\s+\/set\s+{default}\s+recoveryenabled\s+no/ nocase
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ext4 = ".crypt" nocase
        $ext5 = ".readme" nocase
        $note1 = "your files have been encrypted" nocase
        $note2 = "pay bitcoin" nocase
        $note3 = "decrypt your files" nocase
        $note4 = "bitcoin wallet" nocase
        $note5 = "contact us" nocase
        $note6 = "ransom" nocase
        $note7 = "payment" nocase
        $note8 = "private key" nocase
        $family1 = "wannacry" nocase
        $family2 = "ryuk" nocase
        $family3 = "conti" nocase
        $family4 = "lockbit" nocase
        $crypto1 = /AES\s*256/ nocase
        $crypto2 = /RSA\s*2048/ nocase
    condition:
        (2 of ($encrypt*)) or
        (3 of ($ext*)) or
        (2 of ($note*)) or
        (any of ($family*)) or
        (2 of ($crypto*))
}

rule Enterprise_Webshell_Detection {
    meta:
        description = "Advanced webshell detection for enterprise environments"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "webshell"
        tags = "enterprise,webshell,backdoor"
    strings:
        $php1 = /(\$_(GET|POST|REQUEST)\s*\[.*\]\s*\(\s*\$_(GET|POST|REQUEST)\s*\[.*\]\s*\))/ nocase
        $php2 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $php3 = /system\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php4 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php5 = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php6 = /exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $asp1 = /eval\s*\(\s*request/ nocase
        $asp2 = /execute\s*\(\s*request/ nocase
        $asp3 = /response\.write\s*\(\s*server\.createobject/ nocase
        $jsp1 = /Runtime\.getRuntime\(\)\.exec/ nocase
        $jsp2 = /ProcessBuilder/ nocase
        $generic1 = /password\s*=\s*['"]*admin['"]*/ nocase
        $generic2 = /cmd\s*=\s*['"]*shell['"]*/ nocase
        $generic3 = /upload\s*=\s*['"]*file['"]*/ nocase
        $obfuscated1 = /\\x65\\x76\\x61\\x6c/ nocase // \x65\x76\x61\x6c = eval
        $obfuscated2 = /\\x73\\x79\\x73\\x74\\x65\\x6d/ nocase // \x73\x79\x73\x74\x65\x6d = system
    condition:
        (3 of ($php*)) or
        (2 of ($asp*)) or
        (any of ($jsp*)) or
        (3 of ($generic*)) or
        (2 of ($obfuscated*))
}
rule Enterprise_Rootkit_Detection {
    meta:
        description = "Enterprise rootkit and kernel malware detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "rootkit"
        tags = "enterprise,rootkit,kernel"
    strings:
        $kernel1 = /insmod\s+/ nocase
        $kernel2 = /rmmod\s+/ nocase
        $kernel3 = /modprobe\s+/ nocase
        $syscall1 = "sys_call_table" nocase
        $syscall2 = "syscall_hook" nocase
        $syscall3 = "ftrace" nocase
        $hide1 = "hide_process" nocase
        $hide2 = "rootkit" nocase
        $hide3 = "rk_" nocase
        $dkom1 = "EPROCESS" nocase
        $dkom2 = "KTHREAD" nocase
        $dkom3 = "ActiveProcessLinks" nocase
        $known1 = "suckit" nocase
        $known2 = "phalanx" nocase
        $known3 = "knark" nocase
        $known4 = "adore" nocase
        $known5 = "azazel" nocase
        $known6 = "rkit" nocase
        $known7 = "lrk" nocase
        $known8 = "fu" nocase
        $known9 = "suterusu" nocase
        $known10 = "ghostkit" nocase
        $known11 = "tuxkit" nocase
        $known12 = "blackshades" nocase
    condition:
        (2 of ($kernel*)) or
        (2 of ($syscall*)) or
        (2 of ($hide*)) or
        (2 of ($dkom*)) or
        (any of ($known*))
}
rule Enterprise_Data_Exfiltration {
    meta:
        description = "Advanced data exfiltration detection"
        author = "Ghost Sentinel"
        severity = "high"
        category = "exfiltration"
        tags = "enterprise,exfiltration,data_theft"
    strings:
        $cloud1 = /aws\s+s3\s+cp/ nocase
        $cloud2 = /azcopy\s+/ nocase
        $cloud3 = /gsutil\s+cp/ nocase
        $cloud4 = /rclone\s+/ nocase
        $dns1 = /nslookup\s+/ nocase
        $dns2 = /dig\s+/ nocase
        $dns3 = /dns2tcp/ nocase
        $icmp1 = /ping\s+-p/ nocase
        $icmp2 = /hping3/ nocase
        $http1 = /curl\s+-F/ nocase
        $http2 = /wget\s+--post-file/ nocase
        $http3 = /python.*requests/ nocase
        $ftp1 = /ftp\s+/ nocase
        $ftp2 = /lftp\s+/ nocase
        $ftp3 = /ncftp/ nocase
        $email1 = /sendmail/ nocase
        $email2 = /mail\s+/ nocase
        $email3 = /mutt\s+/ nocase
        $large1 = /dd\s+if=.*bs=.*count/ nocase
        $large2 = /tar\s+.*\|\s+(nc|netcat)/ nocase
    condition:
        (any of ($cloud*)) or
        (2 of ($dns*)) or
        (any of ($icmp*)) or
        (2 of ($http*)) or
        (2 of ($ftp*)) or
        (2 of ($email*)) or
        (any of ($large*))
}
rule Enterprise_Credential_Theft {
    meta:
        description = "Enterprise credential theft and access detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "credentials"
        tags = "enterprise,credentials,access"
    strings:
        $pwd1 = "mimikatz" nocase
        $pwd2 = "sekurlsa::logonpasswords" nocase
        $pwd3 = "lsadump::sam" nocase
        $pwd4 = "lsadump::secrets" nocase
        $keylog1 = "keylogger" nocase
        $keylog2 = "GetAsyncKeyState" nocase
        $keylog3 = "SetWindowsHookEx" nocase
        $browser1 = "Chrome" nocase
        $browser2 = "Login Data" nocase
        $browser3 = "cookies.sqlite" nocase
        $ssh1 = "id_rsa" nocase
        $ssh2 = "authorized_keys" nocase
        $ssh3 = ".ssh" nocase
        $rdp1 = "rdp" nocase
        $rdp2 = "mstsc" nocase
        $rdp3 = "termsrv" nocase
        $db1 = "mysql" nocase
        $db2 = "postgresql" nocase
        $db3 = "oracle" nocase
        $db4 = "config" nocase
    condition:
        (2 of ($pwd*)) or
        (2 of ($keylog*)) or
        (3 of ($browser*)) or
        (2 of ($ssh*)) or
        (2 of ($rdp*)) or
        (3 of ($db*))
}
EOF
    cat > "$YARA_RULES_DIR/apt_indicators.yar" << 'EOF'
rule APT_Lateral_Movement_Enterprise {
    meta:
        description = "Enterprise APT lateral movement detection with advanced patterns"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "apt"
        tags = "enterprise,apt,lateral_movement,advanced"
        minimum_yara = "3.8.0"
    strings:
        $apt_tool1 = "mimikatz" nocase
        $apt_tool2 = "bloodhound" nocase
        $apt_tool3 = "sharphound" nocase
        $apt_tool4 = "cobaltstrike" nocase
        $apt_tool5 = "empire" nocase
        $apt_tool6 = "metasploit" nocase
        $apt_tool7 = "powersploit" nocase
        $apt_tool8 = "nishang" nocase
        $empire1 = /\bIEX\s*\(\s*New-Object\s+Net\.WebClient/ nocase
        $empire2 = /DownloadString\s*\(\s*['"]http/ nocase
        $empire3 = /Invoke-Expression\s*\(\s*\$/ nocase
        $beacon3 = /%2f%2f%2b%2f/ nocase // //+/ encoded
        $lotl1 = /bitsadmin\s+\/transfer/ nocase
        $lotl2 = /certutil\s+-urlcache\s+-split\s+-f/ nocase
        $lotl3 = /mshta\s+javascript:/ nocase
        $lotl4 = /rundll32\s+javascript:/ nocase
        $lotl5 = /regsvr32\s+\/s\s+\/n\s+\/u\s+/ nocase
        $recon1 = /nmap\s+-sS\s+-p-/ nocase
        $recon2 = /masscan\s+/ nocase
        $recon3 = /zmap\s+/ nocase
        $recon4 = /nuclei\s+/ nocase
        $fileless1 = /powershell\s+-nop\s+-exec\s+bypass/ nocase
        $fileless2 = /wmic\s+process\s+call\s+create/ nocase
        $fileless3 = /msbuild\s+\/nologo/ nocase
        $memory1 = /reflective\s+loader/ nocase
        $memory2 = /process\s+hollowing/ nocase
        $memory3 = /atom\s+bombing/ nocase
    condition:
        (any of ($apt_tool*)) or
        (2 of ($empire*)) or
        (any of ($beacon*)) or
        (2 of ($lotl*)) or
        (any of ($recon*)) or
        (2 of ($fileless*)) or
        (any of ($memory*))
}
rule Enterprise_Command_and_Control {
    meta:
        description = "Enterprise C2 communication detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "c2"
        tags = "enterprise,c2,command_control"
    strings:
        $dns1 = /dnscat/ nocase
        $dns2 = /iodine/ nocase
        $dns3 = /dns2tcp/ nocase
        $http1 = /User-Agent:\s*Mozilla\/5\.0\s+\(compatible;\s*MSIE\s+9\.0/ nocase
        $http2 = /Content-Type:\s*application\/octet-stream/ nocase
        $http3 = /X-Requested-With:\s*XMLHttpRequest/ nocase
        $https1 = /sslstrip/ nocase
        $https2 = /bettercap/ nocase
        $icmp1 = /icmptunnel/ nocase
        $icmp2 = /hans/ nocase
        $custom1 = /custom\s+protocol/ nocase
        $custom2 = /protocol\s+obfuscation/ nocase
        $framework1 = "covenant" nocase
        $framework2 = "brute ratel" nocase
        $framework3 = "sliver" nocase
        $framework4 = "havoc" nocase
    condition:
        (any of ($dns*)) or
        (3 of ($http*)) or
        (any of ($https*)) or
        (any of ($icmp*)) or
        (any of ($custom*)) or
        (any of ($framework*))
}
rule Enterprise_Zero_Day_Exploits {
    meta:
        description = "Zero-day and N-day exploit detection patterns"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "exploit"
        tags = "enterprise,exploit,zero_day"
    strings:
        $cve1 = /eternalblue/i nocase
        $cve2 = /wannacry/i nocase
        $cve3 = /notpetya/i nocase
        $cve4 = /badrabbit/i nocase
        $framework1 = /metasploit/i nocase
        $framework2 = /exploit-db/i nocase
        $framework3 = /rapid7/i nocase
        $shellcode1 = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 31 D2 B0 0B CD 80 } // Linux x86 execve
        $shellcode2 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D 01 C7 E2 F0 52 57 8B 52 10 8B 42 3C 01 D0 8B 40 78 85 C0 74 4A 01 D0 50 8B 48 18 8B 58 20 01 D3 E3 3C 49 8B 34 8B 01 D6 31 FF 31 C0 AC C1 CF 0D 01 C7 38 E0 75 F4 03 7D F8 3B 7D 24 75 E2 58 8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3 8B 04 8B 01 D0 89 44 24 24 5B 5B 61 59 5A 51 FF E0 58 5F 5A 8B 12 EB 86 }
        $heapspray1 = { 0C 0C 0C 0C } // NOP sled
        $heapspray2 = { 90 90 90 90 } // NOP sled
        $rop1 = { C3 } // ret
        $rop2 = { C2 ?? ?? } // ret n
        $rop3 = { FF E4 } // jmp esp
    condition:
        (any of ($cve*)) or
        (any of ($framework*)) or
        (any of ($shellcode*)) or
        (2 of ($heapspray*)) or
        (3 of ($rop*))
}
rule Enterprise_Insider_Threat {
    meta:
        description = "Insider threat and data theft detection"
        author = "Ghost Sentinel"
        severity = "high"
        category = "insider"
        tags = "enterprise,insider,data_theft"
    strings:
        $exfil1 = /rclone\s+/ nocase
        $exfil2 = /megatools\s+/ nocase
        $exfil3 = /rsync\s+/ nocase
        $exfil4 = /scp\s+/ nocase
        $archive1 = /tar\s+czf\s+/ nocase
        $archive2 = /zip\s+-r\s+/ nocase
        $archive3 = /7z\s+a\s+/ nocase
        $large1 = /dd\s+if=.*of=.*bs=/ nocase
        $large2 = /cp\s+.*\/dev\/null/ nocase
        $usb1 = /\/dev\/sd[a-z]/ nocase
        $usb2 = /\/media\// nocase
        $usb3 = /\/mnt\// nocase
        $cloud1 = /aws\s+s3\s+sync/ nocase
        $cloud2 = /az\s+storage\s+blob\s+upload/ nocase
        $cloud3 = /gsutil\s+rsync/ nocase
        $email1 = /mutt\s+-a/ nocase
        $email2 = /mail\s+-a/ nocase
    condition:
        (2 of ($exfil*)) or
        (2 of ($archive*)) or
        (any of ($large*)) or
        (2 of ($usb*)) or
        (any of ($cloud*)) or
        (any of ($email*))
}
rule Enterprise_Container_Escape {
    meta:
        description = "Container escape and privilege escalation detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "container"
        tags = "enterprise,container,escape,privilege"
    strings:
        $docker1 = /docker\.sock/ nocase
        $docker2 = /var\/run\/docker\.sock/ nocase
        $docker3 = /docker\s+run\s+--privileged/ nocase
        $k8s1 = /kubectl\s+exec/ nocase
        $k8s2 = /kubelet/ nocase
        $k8s3 = /serviceaccount/ nocase
        $mount1 = /\/proc\/1\/ns/ nocase
        $mount2 = /setns/ nocase
        $mount3 = /unshare/ nocase
        $cap1 = /CAP_SYS_ADMIN/ nocase
        $cap2 = /CAP_SYS_PTRACE/ nocase
        $cap3 = /CAP_DAC_OVERRIDE/ nocase
        $device1 = /\/dev\/mem/ nocase
        $device2 = /\/dev\/kmem/ nocase
        $device3 = /\/proc\/kcore/ nocase
    condition:
        (2 of ($docker*)) or
        (2 of ($k8s*)) or
        (2 of ($mount*)) or
        (2 of ($cap*)) or
        (any of ($device*))
}
rule Enterprise_Supply_Chain_Attack {
    meta:
        description = "Supply chain attack detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "supply_chain"
        tags = "enterprise,supply_chain,dependency"
    strings:
        $package1 = /solarwinds/i nocase
        $package2 = /ccleaner/i nocase
        $package3 = /notepad\+\+.*installer/i nocase
        $dep1 = /npm\s+install\s+.*@/ nocase
        $dep2 = /pip\s+install\s+.*==/ nocase
        $dep3 = /gem\s+install\s+.*-/ nocase
        $registry1 = /registry\.yarnpkg\.com/ nocase
        $registry2 = /registry\.npmjs\.org/ nocase
        $registry3 = /pypi\.org/ nocase
        $inject1 = /postinstall.*script/ nocase
        $inject2 = /preinstall.*script/ nocase
        $typo1 = /cross-env/i nocase
        $typo2 = /crossenv/i nocase
        $typo3 = /request/i nocase
        $typo4 = /reques/i nocase
    condition:
        (any of ($package*)) or
        (2 of ($dep*)) or
        (2 of ($registry*)) or
        (any of ($inject*)) or
        (2 of ($typo*))
}
EOF

    # Compile rules into a single file
    yarac --no-warnings "$YARA_RULES_DIR"/*.yar "$YARA_RULES_DIR/rules.yarac"

    log_info "YARA rules initialized for advanced malware detection"
}

# eBPF-based monitoring for kernel-level observability
start_ebpf_monitoring() {
    if [[ "$HAS_BCC" != true ]] || [[ $EUID -ne 0 ]] || ! command -v python3 >/dev/null 2>&1; then
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

ebpf_log = sys.argv[1]
whitelist = sys.argv[2:]

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
        b"ncat", b"/nc", b"netcat", b"socat", b"/dev/tcp", b"python -c", b"perl -e",
        b"bash -i", b"sh -i", b"wget", b"curl", b"base64"
    ]

    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')

    for pattern in suspicious_patterns:
        if pattern in filename.encode() or pattern in comm.encode():
            if not comm.encode() in whitelist:
                with open(ebpf_log, 'a') as f:
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
    python3 "$SCRIPTS_DIR/ghost_sentinel_execsnoop.py" "$EBPF_LOG" "${WHITELIST_PROCESSES[@]}" &
    log_info "eBPF process monitoring started"
}

stop_ebpf_monitoring() {
    if [[ -s "$EBPF_LOG" ]]; then
        log_alert "$MEDIUM" "EBPF found $(wc -l < "$EBPF_LOG") suspicious execs: $(tail -n 1 "$EBPF_LOG")"
        mv "$EBPF_LOG" "$EBPF_LOG.$(date +%FT%T).txt"
    fi
    rm -f "$SCRIPTS_DIR/ghost_sentinel_execsnoop.py" || true
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
    done

    log_info "Honeypots started on ports: ${HONEYPOT_PORTS[*]}"
}

# Anti-evasion detection for advanced threats
detect_anti_evasion() {

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

    # Use multiple tools for cross-validation
    # Compare outputs to detect hiding
    local ss_ports="$(ss -Htulnp 2>/dev/null | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    local netstat_ports="$(netstat -tulnp 2>/dev/null | tail -n +3 | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    local lsof_ports="$({ lsof -i -P -n 2>/dev/null | grep -vF -- '->' | grep -oE ":[0-9]+ "; rpcinfo -p 2> /dev/null | awk 'NR>1{print ":"$4" "}' || true ; } | sort -u | wc -l)"

    local diff_ss_netstat="$(( ss_ports - netstat_ports ))"
    local diff_ss_lsof="$(( lsof_ports - ss_ports ))"
    local max_diff=3
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
        local malicious_ips="$(ss -Hn4ap 2>/dev/null | \
        grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'| \
        sort -u | \
        grep -vE '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|22[4-9]\.|23[0-9]\.|0\.0\.0\.0)'  | \
        python3 -c "import sys, ipaddress; cidrs = [ipaddress.ip_network(l.strip()) for l in open('$THREAT_INTEL_DIR/malicious_ips.txt') if l.strip() and not '#' in l]; [print(f'{ip.strip()}') for ip in sys.stdin if ip.strip() and any(ipaddress.ip_address(ip.strip()) in cidr for cidr in cidrs)];" \
        || true)"

        if [[ -n $malicious_ips ]]; then
            log_alert $HIGH "Detected connections to malicious ips: $malicious_ips"
            ss -Hn4ap > "$LOG_DIR/netstat.$(date +%FT%T).txt" 2>&1 || true
        fi
    fi
}

# YARA-enhanced file monitoring
monitor_files_with_yara() {
    if [[ "$MONITOR_FILES" != true ]]; then return; fi

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
                    yara_result+=$(yara --no-warnings --fast-scan --print-strings --recursive --compiled-rules "$YARA_RULES_DIR/rules.yarac" "$file" 2>/dev/null || echo "")
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
            yara_result=$(yara --no-warnings --fast-scan --print-strings --recursive --compiled-rules --timeout=1 --skip-larger=1048576 "$YARA_RULES_DIR/rules.yarac" "$file" 2>/dev/null || echo "")
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
    for dir in "$LOG_DIR" "$BASELINE_DIR" "$QUARANTINE_DIR" "$THREAT_INTEL_DIR" "$YARA_RULES_DIR" "$SCRIPTS_DIR"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
            echo "<3>Cannot create directory: $dir" >&2
            echo "<3>Please run as root or ensure write permissions" >&2
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

    log_info "Initializing Ghost Sentinel v3..."

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
    PERFORMANCE_MODE=${PERFORMANCE_MODE:-false}
    ENABLE_THREAT_INTEL=${ENABLE_THREAT_INTEL:-true}

    # Secure whitelists with exact matching
    [[ -v WHITELIST_PROCESSES ]] || WHITELIST_PROCESSES=("firefox" "chrome" "nmap" "masscan" "nuclei" "gobuster" "ffuf" "subfinder" "httpx" "amass" "burpsuite" "wireshark" "metasploit" "sqlmap" "nikto" "dirb" "wpscan" "john" "docker" "containerd" "systemd" "kthreadd" "bash" "zsh" "ssh" "python3" "yara")
    [[ -v CRITICAL_PATHS ]] || CRITICAL_PATHS=("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/hosts")

    # Load and validate config file
    if [[ -f "$CONFIG_FILE" ]]; then
        if source "$CONFIG_FILE" 2>/dev/null; then
            log_info "Configuration loaded from $CONFIG_FILE"
        else
            log_info "Warning: Config file syntax error, using defaults"
        fi
    fi
}

log_info() {
    echo "$1"
}

log_alert() {
    declare level=$1
    declare message="$2"

    echo "<${level}>${message}" >&2

    # Send alerts
    if [[ -n "$TELEGRAM_BOT_TOKEN" ]] && [[ -n "$TELEGRAM_CHAT_ID" ]]; then
        # Send to Telegram with bot token and chat ID
        curl --max-time 10 --silent --show-error --fail -X POST --url "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" --data-urlencode chat_id="${TELEGRAM_CHAT_ID}" --data-urlencode text="$(hostname) ${level}: ${message}" >/dev/null || echo "<$ERROR>Telegram alert failed" >&2
    fi

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
            "title": "Ghost Sentinel Alert",
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
            "footer": "Ghost Sentinel",
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
    declare whitelisted

    for whitelisted in "${WHITELIST_PROCESSES[@]}"; do
        if [[ "$proc_basename" == "$whitelisted" ]]; then
            return 0
        fi
    done
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
    if grep -qi "debian" /etc/os-release &>/dev/null; then
        pkg_hash=$(dpkg -l 2>/dev/null | sha256sum | cut -d' ' -f1)
        dpkg --get-selections | sort -u > "$BASELINE_DIR/packages_list.txt"
    elif grep -qi "fedora" /etc/os-release &>/dev/null; then
        pkg_hash=$(rpm -qa --queryformat="%{NAME}-%{VERSION}-%{RELEASE}\n" 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    elif command -v pacman > /dev/null 2>/dev/null; then
        pacman -Qq | sort -u > "$BASELINE_DIR/packages_list.txt"
        pkg_hash=$(pacman -Q | sort | sha256sum | cut -d' ' -f1)
    fi

    if grep -qi "nixos" /etc/os-release &>/dev/null; then
        pkg_hash=$(nix-store --query --requisites /run/current-system | cut -d- -f2- | sort | uniq)
    fi

    if [[ -n "$pkg_hash" ]]; then
        echo "$pkg_hash" > "$BASELINE_DIR/packages_hash.txt"
    fi

    # SUID/SGID baseline (limited scope)
    find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -perm /4000 -o -perm /2000 2>/dev/null | sort > "$BASELINE_DIR/suid_baseline.txt" || true

    log_info "Baseline created successfully"
}

run_unhide() {
    if ! unhide-linux -v quick reverse procall sys 2>&1 | tee "$1"
    then
        log_alert $HIGH "Unhide-linux failed: $(cat "$1")"
    fi
    if ! unhide-tcp -flv 2>&1 | tee -a "$1"
    then
        log_alert $HIGH "Unhide-tcp failed: $(cat "$1")"
    fi
}

main_enhanced() {
    declare start_time=$(date +%s)
    log_info "Ghost Sentinel v3 - Starting advanced security scan..."

    # Initialize system
    init_sentinel

    # Start advanced monitoring features
    if [[ "$ENABLE_EBPF" == true ]] && [[ "$HAS_BCC" == true ]] && [[ $EUID -eq 0 ]]; then
        start_ebpf_monitoring
    fi

    if [[ "$ENABLE_HONEYPOTS" == true ]] && [[ $EUID -eq 0 ]]; then
        start_honeypots
    fi

    if [[ "$ENABLE_ANTI_EVASION" == true ]]; then
        log_info "Running anti-evasion detection..."
        detect_anti_evasion
    fi

    log_info "Running network monitoring..."
    monitor_network_advanced

    if [[ "$HAS_YARA" == true ]] && [[ "$ENABLE_YARA" == true ]]; then
        log_info "Running file monitoring with YARA..."
        monitor_files_with_yara
    fi

    log_info "Running process monitoring..."
    monitor_processes

    log_info "Running user monitoring..."
    monitor_users

    log_info "Running rootkit detection..."
    monitor_rootkits

    log_info "Running memory monitoring..."
    monitor_memory

    if command -v unhide-linux > /dev/null 2>&1 && [[ "${ENABLE_UNHIDE-true}" == "true" ]]
    then
        declare unhide_log_file
        unhide_log_file="$LOG_DIR/unhide-$(date +%F).log"
        if [[ ! -s $unhide_log_file ]]
        then
            log_info "Running daily unhide check..."
            run_unhide "$unhide_log_file"
        fi
    fi

    declare end_time=$(date +%s)
    declare duration=$((end_time - start_time))

    log_info "Advanced security scan completed in ${duration}s"
}


monitor_processes() {
    if [[ "$MONITOR_PROCESSES" != true ]]; then return; fi

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

    # Check for high memory usage
    ps aux --sort=-%mem --no-headers 2>/dev/null | head -3 | while read line; do
        declare mem_usage=$(echo "$line" | awk '{print $4}' | grep -o '^[0-9]*')
        declare proc_name=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null)
        declare pid=$(echo "$line" | awk '{print $2}')

        if ! is_whitelisted_process "$proc_name"; then
            if (( mem_usage > 80 )); then
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
Description=Ghost Sentinel Security Monitor
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
# Unhide checks might take a while
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ghost-sentinel
    #systemctl start ghost-sentinel # TODO: lock file problem

    log_info "Systemd service and timer installed"
}

# === MAIN EXECUTION ===

case "${1:-run}" in
"baseline")
    FORCE_BASELINE=true
    init_sentinel
    ;;
"config")
    ${EDITOR:-nano} "$CONFIG_FILE"
    ;;
"daemon")
    main_enhanced
    sleep "${2-60}" &
    systemd-notify --ready --status=Up
    wait -n # wait until any of the processes exit (honeypots, ebpf or sleep)
    systemd-notify --stopping --status=Stopping 2>/dev/null || true # --stopping is not supported on some systems
    ;;
"systemd")
    if [[ $EUID -eq 0 ]]; then
        create_systemd_service
    else
        echo "systemd integration requires root privileges"
        exit 1
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
