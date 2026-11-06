# CVE-2026-123158 PoC

Proof of Concept (PoC) exploit for **CVE-2026-123158**.

Based on the research and original repository by [oz9un/sshole](https://github.com/oz9un/sshole/tree/main).

Reference: [Alpine Linux Security Advisory](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/)

---

## ⚠ Am I vulnerable?

```bash
curl -sO https://raw.githubusercontent.com/oz9un/sshole/main/check.sh
sudo sh check.sh
```

## 💥 How to make myself vulnerable?
```bash
vi /etc/ssh/sshd_config
rc-service sshd restart
rc-update add sshd
adduser -D ssholeuser
echo 'ssholeuser:*' | chpasswd -e
```

## ⚙️ Prerequisites

Make sure you have Python 3.x installed on your system. This tool requires the `paramiko` library for handling SSH connections.

## 📥 Installation

You can install the required dependency by running:

```bash
pip install paramiko
```

## 🚀 Usage

Run the script by specifying the target user, host, and port:

```bash
python sshole.py [user]@[host] -p [PORT]
```

### Example:

```bash
python sshole.py admin@192.168.1.100 -p 22
```

---

## ⚠️ Disclaimer

*This software and the information contained in this repository have been created exclusively for educational purposes and security research. Using this tool against systems without explicit authorization is illegal. The authors assume no liability for any misuse or damage caused by this material.*
