"""Single-consumer, bounded passive detection state. Times are monotonic."""
from collections import Counter, OrderedDict, deque
from datetime import datetime, timezone
import time

from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP


def _put_bounded(table, key, value, limit):
    table[key] = value
    table.move_to_end(key)
    while len(table) > limit:
        table.popitem(last=False)


class Detector:
    def __init__(self, config, clock=time.monotonic):
        self.config = config
        self.clock = clock
        self.bindings = OrderedDict()  # IP -> (MAC, last observed)
        self.requests = OrderedDict()  # (requested IP, requester IP) -> time
        self.syns = OrderedDict()     # source IP -> (deque[(time, port)], Counter[port])
        self.gratuitous = OrderedDict()  # source IP -> deque[time]
        self.last_prune = clock()

    def _alert(self, signature, severity, ip, mac, **details):
        return {'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                'signature': signature, 'severity': severity, 'attacker_ip': ip,
                'source_mac': mac, 'interface': self.config.interface, **details}

    def _prune(self, now):
        # Periodic global expiry avoids retaining idle keys forever, without an O(n) walk per packet.
        if now - self.last_prune < 1:
            return
        self.last_prune = now
        for table, ttl in ((self.bindings, self.config.arp_entry_ttl),
                           (self.requests, self.config.arp_request_timeout)):
            for key, value in list(table.items()):
                timestamp = value[1] if table is self.bindings else value
                if now - timestamp > ttl:
                    del table[key]
        for key, (events, ports) in list(self.syns.items()):
            self._expire_syn(events, ports, now)
            if not events:
                del self.syns[key]
        for key, events in list(self.gratuitous.items()):
            while events and now - events[0] > self.config.arp_window:
                events.popleft()
            if not events:
                del self.gratuitous[key]

    def _expire_syn(self, events, ports, now):
        while events and now - events[0][0] > self.config.window:
            _, port = events.popleft()
            ports[port] -= 1
            if not ports[port]:
                del ports[port]

    def process(self, packet):
        now = self.clock()
        self._prune(now)
        alerts = []
        if ARP in packet:
            arp = packet[ARP]
            ip, mac, target = str(arp.psrc), str(arp.hwsrc).lower(), str(arp.pdst)
            eth_mac = str(packet[Ether].src).lower() if Ether in packet else mac
            # Ignore probes (0.0.0.0); they do not assert an IP binding.
            if int(arp.op) == 1 and ip != '0.0.0.0' and ip != target:
                _put_bounded(self.requests, (target, ip), now, self.config.max_sources)
            if ip != '0.0.0.0' and int(arp.op) in (1, 2):
                previous = self.bindings.get(ip)
                if previous and now - previous[1] > self.config.arp_entry_ttl:
                    del self.bindings[ip]
                    previous = None
                if previous and previous[0] != mac:
                    alerts.append(self._alert('arp_binding_conflict', 'high', ip, eth_mac,
                                              claimed_mac=mac, previous_mac=previous[0]))
                    # Do not let a conflicting packet replace or refresh the trusted observation.
                else:
                    _put_bounded(self.bindings, ip, (mac, now), self.config.max_sources)
            if int(arp.op) == 2:
                request_time = self.requests.pop((ip, target), None)
                if request_time is None or now - request_time > self.config.arp_request_timeout:
                    alerts.append(self._alert('unsolicited_arp_reply', 'medium', ip, eth_mac, claimed_mac=mac))
            if (ip != '0.0.0.0' and ip == target and Ether in packet and
                    str(packet[Ether].dst).lower() == 'ff:ff:ff:ff:ff:ff'):
                events = self.gratuitous.get(ip, deque(maxlen=self.config.max_events))
                while events and now - events[0] > self.config.arp_window:
                    events.popleft()
                events.append(now)
                _put_bounded(self.gratuitous, ip, events, self.config.max_sources)
                if len(events) >= self.config.gratuitous_threshold:
                    alerts.append(self._alert('gratuitous_arp_burst', 'high', ip, eth_mac, count=len(events)))
        if IP in packet and TCP in packet:
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if flags & 0x02 and not flags & 0x10:  # SYN without ACK
                ip = str(packet[IP].src)
                mac = str(packet[Ether].src).lower() if Ether in packet else ''
                events, counts = self.syns.get(ip, (deque(), Counter()))
                self._expire_syn(events, counts, now)
                if len(events) == self.config.max_events:
                    _, oldest = events.popleft()
                    counts[oldest] -= 1
                    if not counts[oldest]:
                        del counts[oldest]
                port = int(tcp.dport)
                events.append((now, port))
                counts[port] += 1
                _put_bounded(self.syns, ip, (events, counts), self.config.max_sources)
                ports = len(counts)
                if ports >= self.config.scan_ports:
                    alerts.append(self._alert('tcp_port_scan', 'high', ip, mac, distinct_ports=ports, syn_count=len(events)))
                if len(events) >= self.config.syn_threshold:
                    alerts.append(self._alert('tcp_syn_flood', 'high', ip, mac, syn_count=len(events), distinct_ports=ports))
        return alerts
