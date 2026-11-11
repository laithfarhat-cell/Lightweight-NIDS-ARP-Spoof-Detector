import asyncio
import io
import json
from types import SimpleNamespace

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from config import Config, parse_args
from main import Pipeline
from notifiers.webhook import Cooldown, send, validate_discord_url


def test_pipeline_writes_json_and_drains():
    output = io.StringIO()
    p = Pipeline(Config('test', scan_ports=1, syn_threshold=2), output)
    p.start()
    p.capture(Ether()/IP(src='10.0.0.1')/TCP(dport=123, flags='S'))
    p.stop()
    alert = json.loads(output.getvalue())
    assert alert['signature'] == 'tcp_port_scan'
    assert alert['timestamp'].endswith('Z')
    assert alert['attacker_ip'] == '10.0.0.1'


def test_cooldown_by_source_and_signature():
    now = [0]
    c = Cooldown(10, 2, lambda: now[0])
    a = {'signature': 'scan', 'attacker_ip': '1'}
    assert c.allow(a)
    assert not c.allow(a)
    assert c.allow({'signature': 'flood', 'attacker_ip': '1'})
    now[0] = 10
    assert c.allow(a)
    c.allow({'signature': 'scan', 'attacker_ip': '2'})
    assert len(c.last) == 2


def test_webhooks_payloads_and_isolated_failure():
    requests = []
    class Response:
        status = 204
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
    class Session:
        def post(self, url, **kwargs):
            requests.append((url, kwargs))
            return Response()
    config = Config('test', discord_url='https://discord.com/api/webhooks/id/token', telegram_token='secret', telegram_chat_id='42')
    alert = {'signature': 'scan', 'severity': 'high', 'timestamp': 'now', 'attacker_ip': '1.2.3.4', 'source_mac': 'aa:bb'}
    asyncio.run(send(Session(), config, alert))
    assert len(requests) == 2
    discord, telegram = requests
    assert discord[1]['json']['allowed_mentions'] == {'parse': []}
    assert all(value in discord[1]['json']['content'] for value in alert.values())
    assert telegram[1]['json']['parse_mode'] == 'HTML'
    assert all(value in telegram[1]['json']['text'] for value in alert.values())
    assert not discord[1]['allow_redirects']


def test_configuration_validation(monkeypatch):
    monkeypatch.delenv('TELEGRAM_BOT_TOKEN', raising=False)
    monkeypatch.delenv('TELEGRAM_CHAT_ID', raising=False)
    assert parse_args(['-i', 'eth0']).scan_ports == 20
    for args in (['--window', 'nan'], ['--window', '0'], ['--max-events', '2']):
        with pytest.raises(SystemExit): parse_args(['-i', 'eth0', *args])
    monkeypatch.setenv('TELEGRAM_BOT_TOKEN', 'secret')
    with pytest.raises(SystemExit): parse_args(['-i', 'eth0'])
    validate_discord_url('https://discord.com/api/webhooks/1/token')
    with pytest.raises(ValueError): validate_discord_url('https://discord.com.evil.test/api/webhooks/1/token')


def test_queue_overflow_is_nonblocking_and_counted():
    p = Pipeline(Config('test', queue_size=1), io.StringIO())
    p.capture('first')
    p.capture('second')
    assert p.packets.qsize() == 1
    assert p.drops['packets'] == 1


def test_log_error_signals_failure():
    class BrokenOutput:
        def write(self, data):
            raise OSError('disk full')
    p = Pipeline(Config('test'), BrokenOutput())
    p.start()
    p.offer('alerts', {'signature': 'test', 'attacker_ip': '1'})
    assert p.failed.wait(2)
    p.stop()
