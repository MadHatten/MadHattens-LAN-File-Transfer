#!/usr/bin/env python3      I have this all here incase you want to modify anything, do what you want with it. 
"""
MadHatten's LAN File Transfer
Created by Austin Hatten. MIT License (see LICENSE).

Two-way file and folder transfer between computers on the same home network.

  * Pair a device once with a PIN, tick "Remember this device", and after that
    transfers go straight through with just a progress bar.
  * Every file is checked with SHA-256 so you know the copy is bit-perfect.
  * Works on Windows and Linux (Ubuntu/Mint/Edubuntu, Fedora, CachyOS).
    macOS should work but is untested.

Run:  python MadHattens_lan_filetransfer.py
"""

APP_NAME = "MadHattens LAN File Transfer"
APP_VERSION = "1.0"
PROTOCOL_VERSION = 2

#  Installs the dependencies (PyQt5) ---
import subprocess
import sys


def ensure_pyqt5():
    try:
        import PyQt5  # noqa: F401
        return
    except ImportError:
        pass
    print("Package 'PyQt5' not found. Installing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyQt5"])
        return
    except Exception:
        pass
    # Many Linux distros block pip installs into the system Python
    print(
        "\nCould not install PyQt5 automatically.\n"
        "Install it with your system package manager"
        "  Ubuntu / Mint / Edubuntu:  sudo apt install python3-pyqt5\n"
        "  Fedora:                    sudo dnf install python3-qt5\n"
        "  CachyOS / Arch:            sudo pacman -S python-pyqt5\n"
        "  Windows / macOS:           python -m pip install PyQt5\n"
    )
    sys.exit(1)


ensure_pyqt5()

# the imports that start this off
import argparse
import hashlib
import hmac
import itertools
import json
import os
import re
import secrets
import shutil
import socket
import threading
import time
import uuid
from datetime import datetime

from PyQt5.QtCore import QObject, Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QPalette, QIntValidator
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QListWidget, QListWidgetItem, QProgressBar,
    QMessageBox, QFileDialog, QTabWidget, QComboBox, QFrame, QScrollArea,
    QTableWidget, QTableWidgetItem, QHeaderView, QDialog, QCheckBox,
    QAbstractItemView, QSizePolicy,
)

#  Config
DEFAULT_PORT = 12345
CHUNK_SIZE = 256 * 1024            # bytes per read/send
MAX_MSG_SIZE = 16 * 1024 * 1024    # largest control message we accept
NET_TIMEOUT = 30                   # seconds of silence before giving up
HUMAN_TIMEOUT = 180                # seconds to wait for Allow / PIN entry
SPACE_MARGIN = 200 * 1024 * 1024   # keep this much disk free after a transfer
PART_EXT = ".lanpart"              # temporary name while a file is arriving
HISTORY_LIMIT = 500


#  Helpers

def human_size(n):
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024


def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no packets are actually sent
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def default_config_dir():
    if os.name == "nt":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "MadHattensLANTransfer")


def default_download_dir():
    return os.path.join(os.path.expanduser("~"), "Downloads", "LAN_Transfers")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def parse_target(text, default_port):
    """'192.168.1.5', '192.168.1.5:12345' or '192.168.1.5  (name)' -> (ip, port)."""
    text = text.strip().split()[0] if text.strip() else ""
    if not text:
        return None, None
    if text.count(":") == 1:
        host, port = text.split(":")
        try:
            return host, int(port)
        except ValueError:
            return None, None
    return text, default_port



#  Wire protocol
#  Every control message = 4-byte length + JSON.  File data is sent raw

class ProtocolError(Exception):
    pass


class TransferCancelled(Exception):
    pass


class RemoteRejected(Exception):
    pass


def recv_exact(sock, n):
    """Read exactly n bytes (a single recv() can legally return fewer)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), CHUNK_SIZE))
        if not chunk:
            raise ConnectionError("Connection closed by the other device")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_msg(sock):
    n = int.from_bytes(recv_exact(sock, 4), "big")
    if n > MAX_MSG_SIZE:
        raise ProtocolError("Message too large")
    try:
        obj = json.loads(recv_exact(sock, n).decode("utf-8"))
    except ValueError:
        raise ProtocolError("Garbled message")
    if not isinstance(obj, dict) or "type" not in obj:
        raise ProtocolError("Bad message")
    return obj


def expect(msg, *types):
    if msg.get("type") not in types:
        raise ProtocolError(f"Unexpected message '{msg.get('type')}'")


_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')


def safe_parts(relpath):
    """Turn an incoming relative path into safe path parts (no '..', no absolute paths)."""
    if not isinstance(relpath, str) or not relpath:
        raise ProtocolError("Missing file path")
    relpath = relpath.replace("\\", "/")
    if relpath.startswith("/"):
        raise ProtocolError("Unsafe file path")
    clean = []
    for part in relpath.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ProtocolError("Unsafe file path")
        
        # Characters Windows cant store it also strip trailing dots and spaces
        part = _BAD_CHARS.sub("_", part).rstrip(" .") or "_"
        clean.append(part)
    if not clean:
        raise ProtocolError("Empty file path")
    return clean


def unique_name(directory, name, is_dir):
    """'photo.jpg' -> 'photo (1).jpg' if it already exists. Never overwrite."""
    if is_dir:
        base, ext = name, ""
    else:
        base, ext = os.path.splitext(name)
    candidate, i = name, 1
    while (os.path.exists(os.path.join(directory, candidate))
           or os.path.exists(os.path.join(directory, candidate + PART_EXT))):
        candidate = f"{base} ({i}){ext}"
        i += 1
    return candidate


def build_send_items(paths):
    """Expand dropped files/folders into (abs_path, relpath, size, is_dir) items."""
    items, used_tops, skipped = [], set(), []

    def dedupe_top(name, is_dir):
        if name not in used_tops:
            used_tops.add(name)
            return name
        base, ext = (name, "") if is_dir else os.path.splitext(name)
        i = 1
        while f"{base} ({i}){ext}" in used_tops:
            i += 1
        new = f"{base} ({i}){ext}"
        used_tops.add(new)
        return new

    for p in paths:
        p = os.path.abspath(p)
        name = os.path.basename(p.rstrip("/\\")) or "item"
        if os.path.isdir(p):
            top = dedupe_top(name, True)
            items.append((None, top, 0, True))
            for root, dirs, files in os.walk(p):
                dirs.sort()
                files.sort()
                rel_root = os.path.relpath(root, p)
                for d in dirs:
                    rel = d if rel_root == "." else os.path.join(rel_root, d)
                    items.append((None, top + "/" + rel.replace(os.sep, "/"), 0, True))
                for f in files:
                    full = os.path.join(root, f)
                    rel = f if rel_root == "." else os.path.join(rel_root, f)
                    try:
                        if not os.path.isfile(full):
                            continue
                        size = os.path.getsize(full)
                    except OSError:
                        skipped.append(full)
                        continue
                    items.append((full, top + "/" + rel.replace(os.sep, "/"), size, False))
        elif os.path.isfile(p):
            top = dedupe_top(name, False)
            items.append((p, top, os.path.getsize(p), False))
        else:
            skipped.append(p)
    return items, skipped


#  Storage: this device's identity, remembered devices, history etc.

class Identity:
    def __init__(self, config_dir):
        path = os.path.join(config_dir, "identity.json")
        data = load_json(path, {})
        if not data.get("device_id"):
            data = {"device_id": uuid.uuid4().hex, "name": socket.gethostname() or "Unknown PC"}
            save_json(path, data)
        self.device_id = data["device_id"]
        self.name = data.get("name") or socket.gethostname()


class DeviceStore:
    """Remembered (paired) devices, keyed by device ID - not IP - so IP changes don't matter."""

    def __init__(self, config_dir, on_change=None):
        self.path = os.path.join(config_dir, "devices.json")
        self.lock = threading.Lock()
        self.devices = load_json(self.path, {})
        self.on_change = on_change

    def _notify(self):
        # Called AFTER the lock is released, so the GUI can read the list
        if self.on_change:
            self.on_change()

    def get(self, device_id):
        with self.lock:
            d = self.devices.get(device_id)
            return dict(d) if d else None

    def remember(self, device_id, name, ip, secret):
        with self.lock:
            self.devices[device_id] = {
                "name": name, "ip": ip, "secret": secret,
                "paired": now_str(), "last_seen": now_str(),
            }
            save_json(self.path, self.devices)
        self._notify()

    def update_seen(self, device_id, name, ip):
        with self.lock:
            d = self.devices.get(device_id)
            if not d:
                return
            d.update({"name": name, "ip": ip, "last_seen": now_str()})
            save_json(self.path, self.devices)
        self._notify()

    def forget(self, device_id):
        with self.lock:
            if self.devices.pop(device_id, None) is None:
                return
            save_json(self.path, self.devices)
        self._notify()

    def list(self):
        with self.lock:
            return sorted(
                ((k, dict(v)) for k, v in self.devices.items()),
                key=lambda kv: kv[1].get("name", "").lower(),
            )


class HistoryStore:
    def __init__(self, config_dir, on_change=None):
        self.path = os.path.join(config_dir, "history.json")
        self.lock = threading.Lock()
        self.entries = load_json(self.path, [])
        self.on_change = on_change

    def add(self, **entry):
        entry.setdefault("time", now_str())
        with self.lock:
            self.entries.insert(0, entry)
            del self.entries[HISTORY_LIMIT:]
            save_json(self.path, self.entries)
        if self.on_change:
            self.on_change()

    def list(self):
        with self.lock:
            return list(self.entries)

    def clear(self):
        with self.lock:
            self.entries = []
            save_json(self.path, self.entries)
        if self.on_change:
            self.on_change()



#  requests need you to allow


class PairingRequest:
    """Receiver side: someone new wants to send. Shows PIN + Allow/Cancel."""

    def __init__(self, tid, peer_name, peer_ip, pin, count, total, conn, my_name):
        self.tid, self.peer_name, self.peer_ip = tid, peer_name, peer_ip
        self.pin, self.count, self.total = pin, count, total
        self.conn, self.my_name = conn, my_name
        self.event = threading.Event()
        self.allowed = False
        self.remember = False

    def decide(self, allowed, remember=False):
        if self.event.is_set():
            return
        self.allowed, self.remember = allowed, remember
        self.event.set()
        if not allowed:
            try:
                send_msg(self.conn, {"type": "reject", "reason": f"Declined on {self.my_name}"})
            except Exception:
                pass
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


class PinRequest:
    """Sender side: ask the user for the PIN shown on the other device."""

    def __init__(self, tid, peer_name, peer_ip):
        self.tid, self.peer_name, self.peer_ip = tid, peer_name, peer_ip
        self.event = threading.Event()
        self.pin = ""
        self.remember = False
        self.cancelled = False

    def submit(self, pin, remember):
        if not self.event.is_set():
            self.pin, self.remember = pin, remember
            self.event.set()

    def cancel(self):
        if not self.event.is_set():
            self.cancelled = True
            self.event.set()


class TransferHandle:
    def __init__(self, tid):
        self.tid = tid
        self.cancelled = threading.Event()
        self.sock = None
        self.pin_request = None

    def cancel(self):
        self.cancelled.set()
        if self.pin_request:
            self.pin_request.cancel()
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


#  Transfer engine nothing her eis the gui and the transfer has to be before the start of the handles

class TransferEngine:
    """
    `ui` must provide:
        log(text), server_status(text),
        transfer_started(tid, direction, name, ip, total, count),
        transfer_status(tid, text), transfer_peer(tid, name),
        transfer_progress(tid, done, total, current),
        transfer_finished(tid, text, ok),
        show_pairing(PairingRequest), close_pairing(PairingRequest),
        ask_pin(PinRequest)
    """

    def __init__(self, identity, devices, history, ui, port, download_dir):
        self.identity, self.devices, self.history, self.ui = identity, devices, history, ui
        self.port = port
        self.download_dir = download_dir
        self.handles = {}
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self.running = False
        self._server_thread = None

    #the cycle
    def start(self):
        os.makedirs(self.download_dir, exist_ok=True)
        self.running = True
        self._server_thread = threading.Thread(target=self._serve, daemon=True)
        self._server_thread.start()

    def stop(self):
        self.running = False
        for h in list(self.handles.values()):
            h.cancel()
        if self._server_thread:
            self._server_thread.join(timeout=3)

    def cancel(self, tid):
        h = self.handles.get(tid)
        if h:
            h.cancel()

    def _new_handle(self):
        with self._lock:
            tid = next(self._ids)
            h = TransferHandle(tid)
            self.handles[tid] = h
            return h

    def _drop_handle(self, tid):
        with self._lock:
            self.handles.pop(tid, None)

    def _serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", self.port))
            srv.listen(8)
            srv.settimeout(1.0)  # checks before it timeout
        except OSError as e:
            self.ui.server_status(f"Can't listen on port {self.port}: {e} (is the app already open?)")
            self.ui.log(f"Server error: {e}")
            srv.close()
            return

        self.ui.server_status(f"Ready - {self.identity.name} at {get_lan_ip()}:{self.port}")
        self.ui.log(f"Listening on port {self.port}")
        while self.running:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.running:
                    break
                continue
            threading.Thread(target=self._handle_incoming, args=(conn, addr), daemon=True).start()
        srv.close()

    # receiving 
    def _handle_incoming(self, conn, addr):
        ip = addr[0]
        handle = self._new_handle()
        handle.sock = conn
        tid = handle.tid
        peer_name, count, total = ip, 0, 0
        started = False
        pairing = None
        result, ok, received = "Failed", False, 0
        try:
            conn.settimeout(NET_TIMEOUT)
            hello = recv_msg(conn)
            expect(hello, "hello")
            if hello.get("protocol") != PROTOCOL_VERSION:
                send_msg(conn, {"type": "reject", "reason": "Different app version - update both PCs"})
                raise ProtocolError("Sender uses a different app version")
            peer_id = str(hello.get("device_id", ""))[:64]
            peer_name = str(hello.get("name") or ip)[:64]
            offer = hello.get("offer") or {}
            count, total = int(offer.get("count", 0)), int(offer.get("total_bytes", 0))
            if count < 0 or total < 0:
                raise ProtocolError("Bad offer")

            # Free-space check
            free = shutil.disk_usage(self.download_dir).free
            if total + SPACE_MARGIN > free:
                reason = (f"Not enough free space on {self.identity.name} "
                          f"(needs {human_size(total)}, has {human_size(free)})")
                send_msg(conn, {"type": "reject", "reason": reason})
                result = "Rejected - not enough space"
                return

            me = {"device_id": self.identity.device_id, "name": self.identity.name}

            # Remembered device
            trusted = False
            known = self.devices.get(peer_id)
            if known:
                nonce = secrets.token_hex(16)
                send_msg(conn, {"type": "challenge", "nonce": nonce, **me})
                auth = recv_msg(conn)
                expect(auth, "auth")
                expected = hmac.new(bytes.fromhex(known["secret"]), nonce.encode(), hashlib.sha256).hexdigest()
                mac = auth.get("mac")
                trusted = isinstance(mac, str) and hmac.compare_digest(mac, expected)

            if trusted:
                self.devices.update_seen(peer_id, peer_name, ip)
                send_msg(conn, {"type": "accept", **me})
            else:
                # New device: PIN 
                pin = f"{secrets.randbelow(10**6):06d}"
                send_msg(conn, {"type": "pin_required", **me})
                pairing = PairingRequest(tid, peer_name, ip, pin, count, total, conn, self.identity.name)
                self.ui.show_pairing(pairing)
                conn.settimeout(HUMAN_TIMEOUT)
                try:
                    pin_msg = recv_msg(conn)
                    expect(pin_msg, "pin")
                except (OSError, ConnectionError):
                    if pairing.event.is_set() and not pairing.allowed:
                        result = "Declined"
                        return
                    result = "Cancelled by sender"
                    return
                if not pairing.event.wait(HUMAN_TIMEOUT):
                    send_msg(conn, {"type": "reject", "reason": "Nobody clicked Allow in time"})
                    result = "Timed out"
                    return
                if not pairing.allowed:
                    result = "Declined"
                    return
                if not hmac.compare_digest(str(pin_msg.get("pin", "")), pin):
                    send_msg(conn, {"type": "reject", "reason": "Wrong PIN"})
                    result = "Rejected - wrong PIN"
                    return
                secret = secrets.token_hex(32)
                if pairing.remember:
                    self.devices.remember(peer_id, peer_name, ip, secret)
                send_msg(conn, {"type": "accept", "secret": secret, **me})
                conn.settimeout(NET_TIMEOUT)

            if pairing:
                self.ui.close_pairing(pairing)
            started = True
            self.ui.transfer_started(tid, "in", peer_name, ip, total, count)
            files_ok, files_bad, received = self._receive_items(conn, handle, total, count)
            if files_bad:
                result = f"{len(files_bad)} file(s) FAILED checksum, {files_ok} verified"
            else:
                result = f"Completed - {files_ok} file(s) verified"
                ok = True
        except TransferCancelled:
            result = "Cancelled"
        except Exception as e:
            if handle.cancelled.is_set():
                result = "Cancelled"
            elif started and isinstance(e, (ConnectionError, OSError)):
                result = "Stopped - the sender cancelled or the connection dropped"
            elif started:
                result = f"Failed - {e}"
            else:
                result = f"Failed - {e}" if not isinstance(e, (ConnectionError, OSError)) else "Connection dropped"
        finally:
            if pairing:
                self.ui.close_pairing(pairing)
            try:
                conn.close()
            except Exception:
                pass
            self._drop_handle(tid)
            if started:
                self.ui.transfer_finished(tid, result, ok)
            else:
                self.ui.log(f"Incoming from {peer_name} ({ip}): {result}")
            self.history.add(direction="Received", device=peer_name, ip=ip,
                             items=count, size=received if started else total, result=result)

    def _receive_items(self, conn, handle, declared_total, declared_count):
        dest = os.path.abspath(self.download_dir)
        os.makedirs(dest, exist_ok=True)
        top_map = {}
        received, items, files_ok, files_bad = 0, 0, 0, []
        last_emit = 0.0
        while True:
            if handle.cancelled.is_set():
                raise TransferCancelled()
            msg = recv_msg(conn)
            if msg["type"] == "done":
                break
            expect(msg, "file")
            items += 1
            if items > declared_count:
                raise ProtocolError("More items than announced")
            parts = safe_parts(msg.get("path"))
            is_dir = bool(msg.get("is_dir"))
            size = int(msg.get("size", 0))
            if size < 0:
                raise ProtocolError("Bad file size")

            top = parts[0]
            if top not in top_map:
                top_map[top] = unique_name(dest, top, is_dir or len(parts) > 1)
            parts[0] = top_map[top]
            target = os.path.abspath(os.path.join(dest, *parts))
            if not target.startswith(dest + os.sep):
                raise ProtocolError("Unsafe file path")
            display = "/".join(parts)

            if is_dir:
                os.makedirs(target, exist_ok=True)
                continue
            if received + size > declared_total:
                raise ProtocolError("More data than announced")

            os.makedirs(os.path.dirname(target), exist_ok=True)
            tmp = target + PART_EXT
            h = hashlib.sha256()
            remaining = size
            try:
                with open(tmp, "wb") as f:
                    while remaining > 0:
                        if handle.cancelled.is_set():
                            raise TransferCancelled()
                        chunk = conn.recv(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise ConnectionError("Connection lost")
                        f.write(chunk)
                        h.update(chunk)
                        remaining -= len(chunk)
                        received += len(chunk)
                        t = time.monotonic()
                        if t - last_emit > 0.1:
                            self.ui.transfer_progress(handle.tid, received, declared_total, display)
                            last_emit = t
                end = recv_msg(conn)
                expect(end, "file_end")
                if hmac.compare_digest(str(end.get("sha256", "")), h.hexdigest()):
                    os.replace(tmp, target)
                    files_ok += 1
                    send_msg(conn, {"type": "file_ok"})
                else:
                    os.remove(tmp)
                    files_bad.append(display)
                    self.ui.log(f"Checksum FAILED for {display} - file deleted")
                    send_msg(conn, {"type": "file_bad", "reason": "Checksum mismatch"})
            except BaseException:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
            self.ui.transfer_progress(handle.tid, received, declared_total, display)
        return files_ok, files_bad, received

    # sending
    def send(self, target_ip, paths, port=None):
        handle = self._new_handle()
        threading.Thread(target=self._send_worker,
                         args=(handle, target_ip, port or self.port, list(paths)),
                         daemon=True).start()
        return handle.tid

    def _send_worker(self, handle, target_ip, port, paths):
        tid = handle.tid
        peer_name = target_ip
        result, ok, sent, count = "Failed", False, 0, 0
        try:
            items, skipped = build_send_items(paths)
            for s in skipped:
                self.ui.log(f"Skipped (can't read): {s}")
            count = len(items)
            total = sum(i[2] for i in items)
            self.ui.transfer_started(tid, "out", target_ip, target_ip, total, count)
            if not items:
                raise ProtocolError("Nothing to send")
            self.ui.transfer_status(tid, "Connecting...")
            try:
                sock = socket.create_connection((target_ip, port), timeout=10)
            except (socket.timeout, ConnectionRefusedError, OSError):
                raise ConnectionError(f"Couldn't connect - is the app open on {target_ip}?")
            handle.sock = sock
            if handle.cancelled.is_set():
                raise TransferCancelled()
            sock.settimeout(HUMAN_TIMEOUT + 30)

            send_msg(sock, {
                "type": "hello", "protocol": PROTOCOL_VERSION,
                "device_id": self.identity.device_id, "name": self.identity.name,
                "offer": {"count": count, "total_bytes": total},
            })

            remember, peer_id = False, None
            while True:
                msg = recv_msg(sock)
                t = msg["type"]
                if t == "challenge":
                    peer_id = msg.get("device_id")
                    peer_name = msg.get("name") or target_ip
                    known = self.devices.get(peer_id)
                    mac = None
                    if known:
                        mac = hmac.new(bytes.fromhex(known["secret"]), str(msg.get("nonce", "")).encode(),
                                       hashlib.sha256).hexdigest()
                    send_msg(sock, {"type": "auth", "mac": mac})
                elif t == "pin_required":
                    peer_id = msg.get("device_id")
                    peer_name = msg.get("name") or target_ip
                    self.ui.transfer_peer(tid, peer_name)
                    self.ui.transfer_status(tid, f"Enter the PIN shown on {peer_name}")
                    req = PinRequest(tid, peer_name, target_ip)
                    handle.pin_request = req
                    self.ui.ask_pin(req)
                    if not req.event.wait(HUMAN_TIMEOUT) or req.cancelled:
                        raise TransferCancelled()
                    remember = req.remember
                    send_msg(sock, {"type": "pin", "pin": req.pin})
                    self.ui.transfer_status(tid, f"Waiting for Allow on {peer_name}...")
                elif t == "accept":
                    peer_id = msg.get("device_id") or peer_id
                    peer_name = msg.get("name") or peer_name
                    if msg.get("secret") and remember:
                        self.devices.remember(peer_id, peer_name, target_ip, msg["secret"])
                    elif peer_id and self.devices.get(peer_id):
                        self.devices.update_seen(peer_id, peer_name, target_ip)
                    break
                elif t == "reject":
                    raise RemoteRejected(msg.get("reason", "Rejected"))
                else:
                    raise ProtocolError(f"Unexpected message '{t}'")

            self.ui.transfer_peer(tid, peer_name)
            self.ui.transfer_status(tid, "Sending...")
            sock.settimeout(NET_TIMEOUT)
            files_ok, files_bad = 0, []
            last_emit = 0.0
            for abs_path, rel, size, is_dir in items:
                if handle.cancelled.is_set():
                    raise TransferCancelled()
                send_msg(sock, {"type": "file", "path": rel, "size": size, "is_dir": is_dir})
                if is_dir:
                    continue
                h = hashlib.sha256()
                remaining = size
                with open(abs_path, "rb") as f:
                    while remaining > 0:
                        if handle.cancelled.is_set():
                            raise TransferCancelled()
                        chunk = f.read(min(CHUNK_SIZE, remaining))
                        if not chunk:
                            raise IOError(f"File changed while sending: {rel}")
                        sock.sendall(chunk)
                        h.update(chunk)
                        remaining -= len(chunk)
                        sent += len(chunk)
                        t = time.monotonic()
                        if t - last_emit > 0.1:
                            self.ui.transfer_progress(tid, sent, total, rel)
                            last_emit = t
                send_msg(sock, {"type": "file_end", "sha256": h.hexdigest()})
                reply = recv_msg(sock)
                if reply["type"] == "file_ok":
                    files_ok += 1
                elif reply["type"] == "file_bad":
                    files_bad.append(rel)
                else:
                    raise ProtocolError(f"Unexpected message '{reply['type']}'")
                self.ui.transfer_progress(tid, sent, total, rel)
            send_msg(sock, {"type": "done"})
            if files_bad:
                result = f"{len(files_bad)} file(s) FAILED checksum, {files_ok} verified"
            else:
                result = f"Completed - {files_ok} file(s) verified"
                ok = True
        except TransferCancelled:
            result = "Cancelled"
        except RemoteRejected as e:
            result = f"Rejected - {e}"
        except Exception as e:
            if handle.cancelled.is_set():
                result = "Cancelled"
            elif isinstance(e, ConnectionError) and str(e).startswith("Couldn't connect"):
                result = str(e)
            elif isinstance(e, (ConnectionError, OSError)):
                result = "Stopped - the other device cancelled or the connection dropped"
            else:
                result = f"Failed - {e}"
        finally:
            if handle.sock:
                try:
                    handle.sock.close()
                except Exception:
                    pass
            self._drop_handle(tid)
            self.ui.transfer_finished(tid, result, ok)
            self.history.add(direction="Sent", device=peer_name, ip=target_ip,
                             items=count, size=sent, result=result)



# the sadness in my life. The GUI


DARK_STYLE = """
QWidget { font-size: 13px; }
QTabWidget::pane { border: 1px solid #33343c; border-radius: 6px; top: -1px; }
QTabBar::tab { background: #26272d; color: #b8bac4; padding: 8px 18px; border: 1px solid #33343c;
               border-bottom: none; border-top-left-radius: 6px; border-top-right-radius: 6px; margin-right: 2px; }
QTabBar::tab:selected { background: #1e1f24; color: #ffffff; }
QPushButton { background: #2f3139; border: 1px solid #40424c; border-radius: 6px; padding: 7px 14px; color: #e6e6eb; }
QPushButton:hover { background: #393b45; }
QPushButton:disabled { color: #6f717a; }
QPushButton#primary { background: #2f6fde; border: 1px solid #3c7cf0; color: white; font-weight: bold; }
QPushButton#primary:hover { background: #3a7cf0; }
QPushButton#danger { background: #4a2a2e; border: 1px solid #6a3a40; }
QLineEdit, QComboBox { background: #17181c; border: 1px solid #3a3c45; border-radius: 6px; padding: 6px; }
QListWidget, QTableWidget { background: #17181c; border: 1px solid #33343c; border-radius: 6px; }
QHeaderView::section { background: #26272d; color: #b8bac4; border: none; padding: 6px; }
QProgressBar { background: #17181c; border: 1px solid #3a3c45; border-radius: 5px; height: 14px; text-align: center; }
QProgressBar::chunk { background: #2f6fde; border-radius: 4px; }
QFrame#row { background: #24252b; border: 1px solid #33343c; border-radius: 8px; }
QLabel#dropzone { border: 2px dashed #4a4c57; border-radius: 10px; background: #1a1b20; color: #9a9ca6; font-size: 15px; }
QLabel#dropzone[hover="true"] { border-color: #2f6fde; color: #ffffff; }
QLabel#pin { font-size: 34px; font-weight: bold; letter-spacing: 6px; color: #ffffff; }
QLabel#heading { font-size: 15px; font-weight: bold; color: #ffffff; }
QLabel#muted { color: #8d8f99; }
"""


def apply_dark_theme(app):
    app.setStyle("Fusion")
    p = QPalette()
    p.setColor(QPalette.Window, QColor(30, 31, 36))
    p.setColor(QPalette.WindowText, QColor(230, 230, 235))
    p.setColor(QPalette.Base, QColor(23, 24, 28))
    p.setColor(QPalette.AlternateBase, QColor(36, 37, 43))
    p.setColor(QPalette.ToolTipBase, QColor(23, 24, 28))
    p.setColor(QPalette.ToolTipText, QColor(230, 230, 235))
    p.setColor(QPalette.Text, QColor(230, 230, 235))
    p.setColor(QPalette.Button, QColor(47, 49, 57))
    p.setColor(QPalette.ButtonText, QColor(230, 230, 235))
    p.setColor(QPalette.BrightText, QColor(255, 90, 90))
    p.setColor(QPalette.Highlight, QColor(47, 111, 222))
    p.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    p.setColor(QPalette.Link, QColor(90, 150, 255))
    for role in (QPalette.Text, QPalette.WindowText, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor(110, 112, 120))
    app.setPalette(p)
    app.setStyleSheet(DARK_STYLE)


class UIBridge(QObject):
    """Engine threads call these methods; signals carry the work safely to the GUI thread."""
    log_sig = pyqtSignal(str)
    server_sig = pyqtSignal(str)
    started_sig = pyqtSignal(int, str, str, str, object, int)
    status_sig = pyqtSignal(int, str)
    peer_sig = pyqtSignal(int, str)
    progress_sig = pyqtSignal(int, object, object, str)
    finished_sig = pyqtSignal(int, str, bool)
    pairing_sig = pyqtSignal(object)
    pairing_close_sig = pyqtSignal(object)
    pin_sig = pyqtSignal(object)
    devices_sig = pyqtSignal()
    history_sig = pyqtSignal()

    def log(self, text): self.log_sig.emit(text)
    def server_status(self, text): self.server_sig.emit(text)
    def transfer_started(self, tid, d, name, ip, total, count): self.started_sig.emit(tid, d, name, ip, total, count)
    def transfer_status(self, tid, text): self.status_sig.emit(tid, text)
    def transfer_peer(self, tid, name): self.peer_sig.emit(tid, name)
    def transfer_progress(self, tid, done, total, cur): self.progress_sig.emit(tid, done, total, cur)
    def transfer_finished(self, tid, text, ok): self.finished_sig.emit(tid, text, ok)
    def show_pairing(self, req): self.pairing_sig.emit(req)
    def close_pairing(self, req): self.pairing_close_sig.emit(req)
    def ask_pin(self, req): self.pin_sig.emit(req)


class DropZone(QLabel):
    dropped = pyqtSignal(list)

    def __init__(self):
        super().__init__("Drag and drop files or folders here")
        self.setObjectName("dropzone")
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(110)
        self.setAcceptDrops(True)

    def _hover(self, on):
        self.setProperty("hover", "true" if on else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._hover(True)

    def dragLeaveEvent(self, e):
        self._hover(False)

    def dropEvent(self, e):
        self._hover(False)
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.toLocalFile()]
        if paths:
            self.dropped.emit(paths)


class TransferRow(QFrame):
    cancel_clicked = pyqtSignal(int)

    def __init__(self, tid, direction, name, ip, total, count):
        super().__init__()
        self.setObjectName("row")
        self.tid, self.direction, self.ip = tid, direction, ip
        self.total = total
        self.finished = False
        self._start = time.monotonic()

        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 10, 12, 10)
        top = QHBoxLayout()
        self.title = QLabel()
        self.title.setObjectName("heading")
        top.addWidget(self.title, 1)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setObjectName("danger")
        self.cancel_btn.clicked.connect(lambda: self.cancel_clicked.emit(self.tid))
        top.addWidget(self.cancel_btn)
        lay.addLayout(top)

        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setTextVisible(False)
        lay.addWidget(self.bar)
        self.detail = QLabel(f"{count} item(s), {human_size(total)}")
        self.detail.setObjectName("muted")
        lay.addWidget(self.detail)
        self.set_peer(name)

    def set_peer(self, name):
        arrow, verb = ("↑", "Sending to") if self.direction == "out" else ("↓", "Receiving from")
        label = name if name == self.ip else f"{name} ({self.ip})"
        self.title.setText(f"{arrow}  {verb} {label}")

    def set_status(self, text):
        if not self.finished:
            self.detail.setText(text)

    def set_progress(self, done, total, current):
        if self.finished:
            return
        total = total or 1
        self.bar.setValue(int(done * 1000 / total))
        elapsed = max(time.monotonic() - self._start, 0.001)
        speed = human_size(done / elapsed) + "/s"
        name = current if len(current) < 60 else "..." + current[-57:]
        self.detail.setText(f"{done * 100 // total}%  -  {human_size(done)} of {human_size(total)}  -  {speed}  -  {name}")

    def finish(self, text, ok):
        self.finished = True
        self.cancel_btn.hide()
        if ok:
            self.bar.setValue(1000)
            self.detail.setText("✔  " + text)
            self.detail.setStyleSheet("color: #5fd38a;")
        else:
            self.detail.setText("✖  " + text)
            self.detail.setStyleSheet("color: #ff7b7b;")


class PairingDialog(QDialog):
    """Receiver: first time a device sends - PIN + Allow/Cancel."""

    def __init__(self, req, parent):
        super().__init__(parent)
        self.req = req
        self.setWindowTitle("Incoming transfer request")
        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        self.setModal(False)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        head = QLabel(f"<b>{req.peer_name}</b> ({req.peer_ip}) wants to send you<br>"
                      f"{req.count} item(s), {human_size(req.total)}")
        head.setObjectName("heading")
        lay.addWidget(head)
        lay.addWidget(QLabel("Enter this PIN on the sending computer:"))
        pin = QLabel(req.pin)
        pin.setObjectName("pin")
        pin.setAlignment(Qt.AlignCenter)
        pin.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(pin)
        self.remember = QCheckBox("Remember this device")
        lay.addWidget(self.remember)
        note = QLabel("Remembered devices can send without a PIN next time.")
        note.setObjectName("muted")
        lay.addWidget(note)
        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self._cancel)
        allow = QPushButton("Allow")
        allow.setObjectName("primary")
        allow.clicked.connect(self._allow)
        btns.addWidget(cancel)
        btns.addWidget(allow)
        lay.addLayout(btns)

    def _allow(self):
        self.req.decide(True, self.remember.isChecked())
        self.accept()

    def _cancel(self):
        self.req.decide(False)
        self.reject()

    def closeEvent(self, e):
        self.req.decide(False)
        super().closeEvent(e)


class PinDialog(QDialog):
    """Sender: type the PIN shown on the other computer."""

    def __init__(self, req, parent):
        super().__init__(parent)
        self.req = req
        self.setWindowTitle("Pair with device")
        self.setWindowFlag(Qt.WindowStaysOnTopHint, True)
        lay = QVBoxLayout(self)
        lay.setSpacing(10)
        head = QLabel(f"<b>{req.peer_name}</b> ({req.peer_ip}) hasn't been paired yet.")
        head.setObjectName("heading")
        lay.addWidget(head)
        lay.addWidget(QLabel("Type the 6-digit PIN shown on that computer:"))
        self.pin = QLineEdit()
        self.pin.setValidator(QIntValidator(0, 999999))
        self.pin.setMaxLength(6)
        self.pin.setAlignment(Qt.AlignCenter)
        self.pin.setStyleSheet("font-size: 24px; letter-spacing: 6px;")
        lay.addWidget(self.pin)
        self.remember = QCheckBox("Remember this device")
        lay.addWidget(self.remember)
        btns = QHBoxLayout()
        btns.addStretch(1)
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self._cancel)
        ok = QPushButton("Pair && Send")
        ok.setObjectName("primary")
        ok.setDefault(True)
        ok.clicked.connect(self._ok)
        btns.addWidget(cancel)
        btns.addWidget(ok)
        lay.addLayout(btns)

    def _ok(self):
        if len(self.pin.text()) != 6:
            QMessageBox.warning(self, "PIN", "The PIN is 6 digits.")
            return
        self.req.submit(self.pin.text(), self.remember.isChecked())
        self.accept()

    def _cancel(self):
        self.req.cancel()
        self.reject()

    def closeEvent(self, e):
        self.req.cancel()
        super().closeEvent(e)


class MainWindow(QMainWindow):
    def __init__(self, args):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.resize(820, 680)
        self.bridge = UIBridge()
        self.rows = {}
        self.pairing_dialogs = {}
        self.queue = []

        config_dir = args.config_dir or default_config_dir()
        self.download_dir = args.download_dir or default_download_dir()
        self.identity = Identity(config_dir)
        self.devices = DeviceStore(config_dir, on_change=self.bridge.devices_sig.emit)
        self.history = HistoryStore(config_dir, on_change=self.bridge.history_sig.emit)
        self.engine = TransferEngine(self.identity, self.devices, self.history,
                                     self.bridge, args.port, self.download_dir)

        tabs = QTabWidget()
        tabs.addTab(self._build_transfer_tab(), "Transfer")
        tabs.addTab(self._build_devices_tab(), "Devices")
        tabs.addTab(self._build_history_tab(), "History")
        self.setCentralWidget(tabs)
        self.statusBar().showMessage("Starting...")

        b = self.bridge
        b.log_sig.connect(self._log)
        b.server_sig.connect(self.statusBar().showMessage)
        b.started_sig.connect(self._on_started)
        b.status_sig.connect(lambda tid, t: self.rows[tid].set_status(t) if tid in self.rows else None)
        b.peer_sig.connect(lambda tid, n: self.rows[tid].set_peer(n) if tid in self.rows else None)
        b.progress_sig.connect(lambda tid, d, t, c: self.rows[tid].set_progress(d, t, c) if tid in self.rows else None)
        b.finished_sig.connect(self._on_finished)
        b.pairing_sig.connect(self._on_pairing)
        b.pairing_close_sig.connect(self._on_pairing_close)
        b.pin_sig.connect(self._on_pin)
        b.devices_sig.connect(self._refresh_devices)
        b.history_sig.connect(self._refresh_history)

        self._refresh_devices()
        self._refresh_history()
        self.engine.start()

    # building the transfer tab
    def _build_transfer_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setSpacing(10)

        self.dropzone = DropZone()
        self.dropzone.dropped.connect(self._add_paths)
        lay.addWidget(self.dropzone)

        row = QHBoxLayout()
        add_files = QPushButton("Add Files")
        add_files.clicked.connect(self._browse_files)
        add_folder = QPushButton("Add Folder")
        add_folder.clicked.connect(self._browse_folder)
        clear = QPushButton("Clear List")
        clear.clicked.connect(self._clear_queue)
        row.addWidget(add_files)
        row.addWidget(add_folder)
        row.addStretch(1)
        row.addWidget(clear)
        lay.addLayout(row)

        self.queue_list = QListWidget()
        self.queue_list.setMaximumHeight(110)
        lay.addWidget(self.queue_list)

        send_row = QHBoxLayout()
        send_row.addWidget(QLabel("Send to:"))
        self.target = QComboBox()
        self.target.setEditable(True)
        self.target.lineEdit().setPlaceholderText("IP address, e.g. 1.1.1.1")
        self.target.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        send_row.addWidget(self.target, 1)
        self.send_btn = QPushButton("Send")
        self.send_btn.setObjectName("primary")
        self.send_btn.clicked.connect(self._send)
        send_row.addWidget(self.send_btn)
        lay.addLayout(send_row)

        head = QHBoxLayout()
        h = QLabel("Transfers")
        h.setObjectName("heading")
        head.addWidget(h)
        head.addStretch(1)
        open_btn = QPushButton("Open Received Folder")
        open_btn.clicked.connect(self._open_download_dir)
        clear_done = QPushButton("Clear Finished")
        clear_done.clicked.connect(self._clear_finished)
        head.addWidget(open_btn)
        head.addWidget(clear_done)
        lay.addLayout(head)

        self.rows_box = QVBoxLayout()
        self.rows_box.setSpacing(8)
        self.rows_box.addStretch(1)
        holder = QWidget()
        holder.setLayout(self.rows_box)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(holder)
        lay.addWidget(scroll, 1)
        return w

    def _add_paths(self, paths):
        for p in paths:
            if p in self.queue or not os.path.exists(p):
                continue
            self.queue.append(p)
            if os.path.isdir(p):
                folder_name = os.path.basename(p.rstrip("/\\")) or p
                label = f"\U0001F4C1  {folder_name}   (folder)"
            else:
                label = f"\U0001F4C4  {os.path.basename(p)}   ({human_size(os.path.getsize(p))})"
            item = QListWidgetItem(label)
            item.setToolTip(p)
            self.queue_list.addItem(item)

    def _browse_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to send")
        self._add_paths(files)

    def _browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select a folder to send")
        if folder:
            self._add_paths([folder])

    def _clear_queue(self):
        self.queue = []
        self.queue_list.clear()

    def _send(self):
        if not self.queue:
            QMessageBox.warning(self, "Nothing to send", "Add some files or folders first.")
            return
        ip, port = parse_target(self.target.currentText(), self.engine.port)
        if not ip or not port:
            QMessageBox.warning(self, "No target", "Enter the IP address of the other computer.")
            return
        self.engine.send(ip, self.queue, port)
        self._clear_queue()

    def _on_started(self, tid, direction, name, ip, total, count):
        row = TransferRow(tid, direction, name, ip, total, count)
        row.cancel_clicked.connect(self.engine.cancel)
        self.rows[tid] = row
        self.rows_box.insertWidget(0, row)
        if direction == "in" and not self.isActiveWindow():
            QApplication.alert(self)

    def _on_finished(self, tid, text, ok):
        if tid in self.rows:
            self.rows[tid].finish(text, ok)
        self._log(f"Transfer #{tid}: {text}")

    def _clear_finished(self):
        for tid, row in list(self.rows.items()):
            if row.finished:
                row.setParent(None)
                row.deleteLater()
                del self.rows[tid]

    def _open_download_dir(self):
        os.makedirs(self.download_dir, exist_ok=True)
        try:
            if os.name == "nt":
                os.startfile(self.download_dir)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", self.download_dir])
            else:
                subprocess.Popen(["xdg-open", self.download_dir])
        except Exception as e:
            QMessageBox.information(self, "Received folder", f"{self.download_dir}\n\n({e})")

    # pairing
    def _on_pairing(self, req):
        dlg = PairingDialog(req, self)
        self.pairing_dialogs[id(req)] = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()
        QApplication.alert(self)

    def _on_pairing_close(self, req):
        dlg = self.pairing_dialogs.pop(id(req), None)
        if dlg:
            dlg.blockSignals(True)
            dlg.hide()
            dlg.deleteLater()

    def _on_pin(self, req):
        dlg = PinDialog(req, self)
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    #devices tab
    def _build_devices_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        h = QLabel("This computer")
        h.setObjectName("heading")
        lay.addWidget(h)
        self.me_label = QLabel(
            f"Name: {self.identity.name}\n"
            f"Address: {get_lan_ip()}:{self.engine.port}\n"
            f"Saves to: {self.download_dir}"
        )
        self.me_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.me_label)

        h2 = QLabel("Remembered devices")
        h2.setObjectName("heading")
        lay.addWidget(h2)
        self.devices_list = QListWidget()
        lay.addWidget(self.devices_list, 1)
        row = QHBoxLayout()
        row.addStretch(1)
        forget = QPushButton("Forget Selected")
        forget.setObjectName("danger")
        forget.clicked.connect(self._forget_device)
        row.addWidget(forget)
        lay.addLayout(row)
        return w

    def _refresh_devices(self):
        self.devices_list.clear()
        current = self.target.currentText()
        self.target.clear()
        for dev_id, d in self.devices.list():
            item = QListWidgetItem(f"{d.get('ip', '?'):<16}   {d.get('name', '?')}   -   last seen {d.get('last_seen', '?')}")
            item.setData(Qt.UserRole, dev_id)
            self.devices_list.addItem(item)
            self.target.addItem(f"{d.get('ip')}   ({d.get('name')})")
        self.target.setEditText(current)

    def _forget_device(self):
        item = self.devices_list.currentItem()
        if not item:
            return
        if QMessageBox.question(self, "Forget device",
                                "Forget this device? It will need a PIN again next time.") == QMessageBox.Yes:
            self.devices.forget(item.data(Qt.UserRole))

    # the history
    def _build_history_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        self.history_table = QTableWidget(0, 7)
        self.history_table.setHorizontalHeaderLabels(["Time", "Direction", "Device", "IP", "Items", "Size", "Result"])
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.history_table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.history_table, 1)

        h = QLabel("Activity log")
        h.setObjectName("heading")
        lay.addWidget(h)
        self.log_list = QListWidget()
        self.log_list.setMaximumHeight(120)
        lay.addWidget(self.log_list)

        row = QHBoxLayout()
        row.addStretch(1)
        clear = QPushButton("Clear History")
        clear.clicked.connect(lambda: self.history.clear())
        row.addWidget(clear)
        lay.addLayout(row)
        return w

    def _refresh_history(self):
        entries = self.history.list()
        self.history_table.setRowCount(len(entries))
        for r, e in enumerate(entries):
            vals = [e.get("time", ""), e.get("direction", ""), e.get("device", ""), e.get("ip", ""),
                    str(e.get("items", "")), human_size(e.get("size", 0) or 0), e.get("result", "")]
            for c, v in enumerate(vals):
                self.history_table.setItem(r, c, QTableWidgetItem(v))

    def _log(self, text):
        self.log_list.insertItem(0, f"{datetime.now().strftime('%H:%M:%S')}  {text}")
        while self.log_list.count() > 300:
            self.log_list.takeItem(self.log_list.count() - 1)

    # should it shutdown
    def closeEvent(self, event):
        active = [r for r in self.rows.values() if not r.finished]
        if active and QMessageBox.question(
                self, "Transfers running",
                "Transfers are still running. Quit and cancel them?") != QMessageBox.Yes:
            event.ignore()
            return
        self.engine.stop()
        event.accept()


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="port to listen on (default 12345)")
    parser.add_argument("--download-dir", help="where received files go (default ~/Downloads/LAN_Transfers)")
    parser.add_argument("--config-dir", help="where settings/paired devices are kept")
    args = parser.parse_args()

    app = QApplication(sys.argv)
    apply_dark_theme(app)
    window = MainWindow(args)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
