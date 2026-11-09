"""Structured JSON-lines event logging (one JSON object per line, SIEM friendly)."""
import json
import logging
import logging.handlers
import socket
import sys
import time
from pathlib import Path

HOSTNAME = socket.gethostname()
_log = logging.getLogger("airtrap.events")
_subscribers = []


def setup(path, stdout=True, max_bytes=10_485_760, backups=5):
    _log.setLevel(logging.INFO)
    _log.propagate = False
    _log.handlers.clear()
    fmt = logging.Formatter("%(message)s")
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backups)
        fh.setFormatter(fmt)
        _log.addHandler(fh)
    if stdout:
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        _log.addHandler(sh)


def subscribe(fn):
    """Register a callback that receives every emitted record (dict)."""
    _subscribers.append(fn)


def emit(event, severity="info", **fields):
    now = time.time()
    record = {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now * 1000) % 1000:03d}Z",
        "sensor": HOSTNAME,
        "event": event,
        "severity": severity,
    }
    record.update({k: v for k, v in fields.items() if v is not None})
    _log.info(json.dumps(record, separators=(",", ":"), default=str))
    for fn in _subscribers:
        try:
            fn(record)
        except Exception as exc:  # a broken subscriber must never kill the sensor
            _log.info(json.dumps({"event": "subscriber_error", "severity": "high", "error": str(exc)}))
    return record
