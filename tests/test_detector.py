from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from config import Config
from core.detector import Detector


class Clock:
    def __init__(self): self.now = 0
    def __call__(self): return self.now


def signatures(alerts):
    return {a['signature'] for a in alerts}


def arp(op=2, ip='10.0.0.1', target='10.0.0.2', mac='00:11:22:33:44:55', dst='ff:ff:ff:ff:ff:ff'):
    return Ether(src=mac, dst=dst)/ARP(op=op, psrc=ip, pdst=target, hwsrc=mac)


def syn(port, flags='S', src='10.0.0.9'):
    return Ether(src='aa:bb:cc:dd:ee:ff')/IP(src=src, dst='10.0.0.10')/TCP(dport=port, flags=flags)


def test_request_reply_correlation_and_expiry():
    clock = Clock()
    d = Detector(Config('test', arp_request_timeout=2), clock)
    d.process(arp(op=1, ip='10.0.0.2', target='10.0.0.1'))
    assert 'unsolicited_arp_reply' not in signatures(d.process(arp()))
    assert 'unsolicited_arp_reply' in signatures(d.process(arp()))
    d.process(arp(op=1, ip='10.0.0.2', target='10.0.0.1'))
    clock.now = 3
    assert 'unsolicited_arp_reply' in signatures(d.process(arp()))


def test_binding_conflict_does_not_replace_first_and_expires():
    clock = Clock()
    d = Detector(Config('test', arp_entry_ttl=10), clock)
    d.process(arp())
    result = d.process(arp(mac='aa:bb:cc:dd:ee:ff'))
    conflict = next(a for a in result if a['signature'] == 'arp_binding_conflict')
    assert conflict['previous_mac'] == '00:11:22:33:44:55'
    assert conflict['source_mac'] == 'aa:bb:cc:dd:ee:ff'
    assert d.bindings['10.0.0.1'][0] == '00:11:22:33:44:55'
    clock.now = 11
    assert 'arp_binding_conflict' not in signatures(d.process(arp(mac='aa:bb:cc:dd:ee:ff')))


def test_gratuitous_broadcast_window_and_probe():
    clock = Clock()
    d = Detector(Config('test', gratuitous_threshold=2, arp_window=3), clock)
    g = arp(op=1, ip='10.0.0.1', target='10.0.0.1')
    assert not d.process(g)
    assert 'gratuitous_arp_burst' in signatures(d.process(g))
    clock.now = 4
    assert 'gratuitous_arp_burst' not in signatures(d.process(g))
    d.process(arp(op=1, ip='0.0.0.0'))
    assert '0.0.0.0' not in d.bindings
    assert 'gratuitous_arp_burst' not in signatures(d.process(arp(op=1, ip='10.0.0.2', target='10.0.0.2', dst='00:11:22:33:44:55')))


def test_syn_scan_flood_and_window():
    clock = Clock()
    d = Detector(Config('test', scan_ports=3, syn_threshold=4, window=3), clock)
    assert not d.process(syn(1))
    assert not d.process(syn(2, 'SA'))
    assert not d.process(syn(2))
    assert 'tcp_port_scan' in signatures(d.process(syn(3)))
    assert signatures(d.process(syn(3))) == {'tcp_port_scan', 'tcp_syn_flood'}
    clock.now = 4
    assert not d.process(syn(4))
    assert not d.process(syn(1, src='10.0.0.8'))


def test_state_is_bounded_and_idle_entries_expire():
    clock = Clock()
    d = Detector(Config('test', max_sources=2, max_events=2, scan_ports=2, syn_threshold=2), clock)
    for i in range(5):
        d.process(syn(i, src=f'10.0.0.{i+1}'))
    assert len(d.syns) == 2
    for i in range(10):
        d.process(syn(i))
    assert len(d.syns['10.0.0.9'][0]) == 2
    clock.now = 10
    d.process(syn(99, src='10.1.1.1'))
    assert list(d.syns) == ['10.1.1.1']
