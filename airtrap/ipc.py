"""Tiny UNIX-datagram IPC so dnsmasq/hostapd hook scripts can report into the daemon."""
import json
import os
import socket
import threading

from . import logger

DEFAULT_SOCK = "/run/airtrap/airtrap.sock"


def serve(path, stop):
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.settimeout(1)

    def loop():
        while not stop.is_set():
            try:
                data = s.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data)
                logger.emit(msg.pop("event"), msg.pop("severity", "info"), **msg)
            except Exception:
                pass
        s.close()

    t = threading.Thread(target=loop, daemon=True, name="ipc")
    t.start()
    return t


def send(payload, path=None):
    path = path or os.environ.get("AIRTRAP_SOCK", DEFAULT_SOCK)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.sendto(json.dumps(payload).encode(), path)
    finally:
        s.close()
