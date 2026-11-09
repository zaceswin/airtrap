from scapy.all import sniff

from . import logger


class Sensor:
    def __init__(self, iface, detector, stop):
        self.iface, self.detector, self.stop = iface, detector, stop

    def _on(self, pkt):
        try:
            for kind, sev, fields in self.detector.process(pkt):
                logger.emit(kind, sev, **fields)
        except Exception as exc:  # malformed frames must never crash the sensor
            logger.emit("frame_parse_error", "info", error=str(exc))

    def run(self):
        while not self.stop.is_set():
            try:
                sniff(iface=self.iface, prn=self._on, store=False, timeout=2)
            except Exception as exc:
                logger.emit("sensor_error", "high", error=str(exc))
                self.stop.wait(3)
