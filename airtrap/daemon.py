import os
import signal
import sys
import threading
from pathlib import Path

from . import ipc, logger, monitor, tarpit
from .detectors import Detector
from .honeypot import Honeypot
from .responder import Responder
from .sensor import Sensor
from .utils import iface_mac


def run(cfg):
    if os.geteuid() != 0:
        sys.exit("airtrap must run as root (monitor mode, hostapd, nftables).")
    lg = cfg["logging"]
    logger.setup(lg["file"], lg["stdout"], lg["max_bytes"], lg["backups"])
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())

    rt = Path(cfg["runtime_dir"])
    rt.mkdir(parents=True, exist_ok=True)
    s, hp_cfg = cfg["sensor"], cfg["honeypot"]
    iface = s["interface"]
    if not Path(f"/sys/class/net/{iface}").exists():
        sys.exit(f"Sensor interface {iface} not found. Run `iw dev` and edit sensor.interface.")
    if hp_cfg["enabled"] and not Path(f"/sys/class/net/{hp_cfg['interface']}").exists():
        sys.exit(f"Honeypot interface {hp_cfg['interface']} not found (or set honeypot.enabled: false).")
    hp = Honeypot(cfg) if hp_cfg["enabled"] else None
    own = [iface_mac(iface), iface_mac(hp_cfg["interface"])]
    responder = Responder(cfg, own_macs=own, hp_iface=hp_cfg["interface"] if hp else None)
    logger.subscribe(responder.handle)
    ipc.serve(str(rt / "airtrap.sock"), stop)

    hopper = None
    try:
        if s["manage_monitor_mode"]:
            monitor.enable(iface)
        hopper = monitor.ChannelHopper(iface, s["channels"], s["hop_interval"], stop)
        hopper.start()
        if hp:
            hp.start()
            tarpit.start_thread(cfg, stop)
        logger.emit("sensor_started", "info", interface=iface, channels=s["channels"],
                    honeypot=bool(hp), response_mode=cfg["response"]["mode"],
                    protected_ssids=sorted(cfg["detection"]["protected_networks"]))
        det = Detector(cfg, hp.bssid if hp else None, hp_cfg["ssid"] if hp else None,
                       channel_fn=lambda: hopper.current)
        Sensor(iface, det, stop).run()
    finally:
        stop.set()
        if hp:
            hp.stop()
        responder.cleanup()
        if s["manage_monitor_mode"]:
            monitor.disable(iface)
        logger.emit("sensor_stopped", "info")
