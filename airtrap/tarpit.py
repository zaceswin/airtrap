"""Async tarpit for the honeypot network: accepts anything, replies painfully slowly, logs everything."""
import asyncio
import os
import random
import socket
import struct
import threading
import time

from . import logger
from .utils import arp_lookup

SO_ORIGINAL_DST = 80


def _orig_dst(sock):
    try:
        data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port, ip = struct.unpack_from("!2xH4s", data)
        return socket.inet_ntoa(ip), port
    except OSError:
        return None, None


async def _read(reader, n, timeout):
    try:
        return await asyncio.wait_for(reader.read(n), timeout)
    except asyncio.TimeoutError:
        return b""


async def _drip(writer, delay, max_dur, start, make):
    while time.time() - start < max_dur:
        writer.write(make())
        await writer.drain()
        await asyncio.sleep(delay)


def _parse_http(raw, limit, with_body):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    first = lines[0].split(" ") if lines else []
    hdrs = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdrs[k.strip().lower()] = v.strip()
    info = {"method": first[0] if first else None, "path": (first[1] if len(first) > 1 else None),
            "host": hdrs.get("host"), "user_agent": hdrs.get("user-agent")}
    if with_body and body:
        info["body"] = body[:limit].decode(errors="replace")
    return {k: (v[:limit] if isinstance(v, str) else v) for k, v in info.items()}


async def _handle(reader, writer, cfg):
    h = cfg["honeypot"]
    ip = writer.get_extra_info("peername")[0]
    sock = writer.get_extra_info("socket")
    _, dport = _orig_dst(sock) if sock else (None, None)
    dport = dport or h["tarpit_port"]
    mac, start = arp_lookup(ip), time.time()
    delay, maxd, lim = h["tarpit_delay"], h["max_duration"], h["payload_bytes"]
    logger.emit("tarpit_connection", "warning", attacker_ip=ip, attacker_mac=mac, dest_port=dport)
    try:
        if dport in (80, 8080, 8000):
            raw = await _read(reader, lim * 8, 10)
            logger.emit("tarpit_http", "warning", attacker_ip=ip, attacker_mac=mac, dest_port=dport,
                        **_parse_http(raw, lim, h["log_http_body"]))
            writer.write(b"HTTP/1.1 200 OK\r\n")
            await _drip(writer, delay, maxd, start, lambda: b"X-Pad: " + os.urandom(3).hex().encode() + b"\r\n")
        elif dport == 23:
            writer.write(b"\xff\xfb\x01login: ")
            creds = await _read(reader, lim, 20)
            logger.emit("tarpit_login", "warning", attacker_ip=ip, attacker_mac=mac, dest_port=dport,
                        typed=creds.decode(errors="replace")[:lim] if h["log_http_body"] else None)
            await _drip(writer, delay, maxd, start, lambda: b"Password: ")
        else:
            raw = await _read(reader, lim, 3)
            if raw:
                logger.emit("tarpit_payload", "warning", attacker_ip=ip, attacker_mac=mac,
                            dest_port=dport, first_bytes_hex=raw[:lim].hex())
            # endlessh-style: endless pre-banner lines keep scanners/brute-forcers stuck
            await _drip(writer, delay, maxd, start, lambda: b"%x\r\n" % random.getrandbits(32))
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass
        logger.emit("tarpit_closed", "info", attacker_ip=ip, attacker_mac=mac, dest_port=dport,
                    duration_s=round(time.time() - start, 1))


async def serve(cfg, stop):
    h = cfg["honeypot"]
    state = {"active": 0}

    async def cb(r, w):
        if state["active"] >= h["max_connections"]:
            w.close()
            return
        state["active"] += 1
        try:
            await _handle(r, w, cfg)
        finally:
            state["active"] -= 1

    server = await asyncio.start_server(cb, h["gateway"], h["tarpit_port"])
    logger.emit("tarpit_listening", "info", address=h["gateway"], port=h["tarpit_port"])
    while not stop.is_set():
        await asyncio.sleep(0.5)
    server.close()


def start_thread(cfg, stop):
    t = threading.Thread(target=lambda: asyncio.run(serve(cfg, stop)), daemon=True, name="tarpit")
    t.start()
    return t
