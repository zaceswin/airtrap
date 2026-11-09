import itertools
import shutil
import subprocess
import threading


def _run(cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def enable(iface):
    if shutil.which("nmcli"):
        _run(["nmcli", "dev", "set", iface, "managed", "no"], check=False)
    _run(["ip", "link", "set", iface, "down"])
    _run(["iw", "dev", iface, "set", "type", "monitor"])
    _run(["ip", "link", "set", iface, "up"])


def disable(iface):
    _run(["ip", "link", "set", iface, "down"], check=False)
    _run(["iw", "dev", iface, "set", "type", "managed"], check=False)
    _run(["ip", "link", "set", iface, "up"], check=False)
    if shutil.which("nmcli"):
        _run(["nmcli", "dev", "set", iface, "managed", "yes"], check=False)


def set_channel(iface, ch):
    _run(["iw", "dev", iface, "set", "channel", str(ch)], check=False)


class ChannelHopper(threading.Thread):
    def __init__(self, iface, channels, interval, stop):
        super().__init__(daemon=True, name="hopper")
        self.iface, self.channels, self.interval, self.stop = iface, list(channels), interval, stop
        self.current = None

    def run(self):
        if len(self.channels) == 1:
            self.current = self.channels[0]
            set_channel(self.iface, self.current)
            return
        for ch in itertools.cycle(self.channels):
            if self.stop.is_set():
                break
            set_channel(self.iface, ch)
            self.current = ch
            self.stop.wait(self.interval)
