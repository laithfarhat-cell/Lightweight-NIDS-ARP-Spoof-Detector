#!/usr/bin/env python3
"""Capture is isolated from bounded detection, logging, and notification workers."""
import asyncio
import json
import logging
import queue
import signal
import threading
import time

import aiohttp
from scapy.all import AsyncSniffer

from config import parse_args
from core.detector import Detector
from notifiers.webhook import Cooldown, send, validate_discord_url

LOG = logging.getLogger('nids')
STOP = object()


class Pipeline:
    def __init__(self, config, output):
        self.config, self.output = config, output
        self.packets = queue.Queue(config.queue_size)
        self.alerts = queue.Queue(config.queue_size)
        self.notifications = queue.Queue(config.queue_size)
        self.failed = threading.Event()
        self.drops = {'packets': 0, 'alerts': 0, 'notifications': 0}
        self.detector = Detector(config)
        self.threads = []

    def offer(self, name, item):
        try:
            getattr(self, name).put_nowait(item)
        except queue.Full:
            self.drops[name] += 1

    def capture(self, packet):
        self.offer('packets', packet)

    def detect(self):
        try:
            while True:
                packet = self.packets.get()
                if packet is STOP:
                    break
                try:
                    for alert in self.detector.process(packet):
                        self.offer('alerts', alert)
                except Exception:
                    LOG.exception('Failed to process packet')
        except Exception:
            LOG.exception('Detection worker failed')
            self.failed.set()

    def log_alerts(self):
        cooldown = Cooldown(self.config.cooldown, self.config.max_sources)
        try:
            while True:
                alert = self.alerts.get()
                if alert is STOP:
                    break
                self.output.write(json.dumps(alert, ensure_ascii=True, allow_nan=False) + '\n')
                self.output.flush()
                if (self.config.discord_url or self.config.telegram_token) and cooldown.allow(alert):
                    self.offer('notifications', alert)
        except Exception:
            LOG.exception('Alert logging failed; stopping capture')
            self.failed.set()

    def notify(self):
        async def run():
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                while True:
                    alert = await asyncio.to_thread(self.notifications.get)
                    if alert is STOP:
                        break
                    await send(session, self.config, alert)
        try:
            asyncio.run(run())
        except Exception:
            LOG.exception('Notification worker failed')
            self.failed.set()

    def start(self):
        for name, target in (('detector', self.detect), ('alert-logger', self.log_alerts), ('notifier', self.notify)):
            thread = threading.Thread(name=name, target=target, daemon=True)
            thread.start()
            self.threads.append(thread)

    def stop(self):
        # Stop upstream first, then drain accepted packets and alerts in order.
        # Timeouts prevent a dead worker from hanging shutdown indefinitely.
        def finish(q, thread):
            try:
                q.put(STOP, timeout=5)
            except queue.Full:
                LOG.error('Could not stop %s: queue is full', thread.name)
                return
            thread.join(timeout=10)
            if thread.is_alive():
                LOG.error('%s did not stop in time', thread.name)
        finish(self.packets, self.threads[0])
        finish(self.alerts, self.threads[1])
        # Webhooks are best-effort: do not wait for a potentially large backlog.
        while True:
            try:
                self.notifications.get_nowait()
                self.drops['notifications'] += 1
            except queue.Empty:
                break
        finish(self.notifications, self.threads[2])
        LOG.info('Dropped items: %s', self.drops)


def main(argv=None):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    config = parse_args(argv)
    try:
        if config.discord_url:
            validate_discord_url(config.discord_url)
        output = open(config.log_file, 'a', encoding='utf-8', buffering=1)
    except (OSError, ValueError) as exc:
        LOG.error('Configuration error: %s', exc)
        return 1

    stopping = threading.Event()
    def request_stop(signum, _frame):
        LOG.info('Received signal %s; shutting down', signum)
        stopping.set()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, request_stop)

    pipeline = Pipeline(config, output)
    pipeline.start()
    started = threading.Event()
    sniffer = AsyncSniffer(iface=config.interface, filter='arp or tcp', store=False,
                           prn=pipeline.capture, started_callback=started.set)
    status = 0
    try:
        sniffer.start()
        # AsyncSniffer reports socket/filter errors on its thread, not from start().
        deadline = time.monotonic() + 10
        while not started.wait(0.1):
            if not sniffer.thread.is_alive() or time.monotonic() >= deadline or stopping.is_set():
                if not stopping.is_set():
                    LOG.error('Capture failed to start: %s', getattr(sniffer, 'exception', None) or 'startup timeout')
                    status = 1
                break
        if started.is_set():
            LOG.info('Monitoring interface %s; alerts appended to %s', config.interface, config.log_file)
            reported_drops = dict(pipeline.drops)
            next_report = time.monotonic() + 60
            while not stopping.wait(1):
                if time.monotonic() >= next_report:
                    if pipeline.drops != reported_drops:
                        reported_drops = dict(pipeline.drops)
                        LOG.warning('Cumulative dropped items: %s', reported_drops)
                    next_report = time.monotonic() + 60
                if pipeline.failed.is_set() or not sniffer.thread.is_alive():
                    LOG.error('A worker or capture stopped unexpectedly: %s', getattr(sniffer, 'exception', None))
                    status = 1
                    break
    except Exception:
        LOG.exception('Capture error')
        status = 1
    finally:
        if started.is_set() and sniffer.thread.is_alive():
            try:
                sniffer.stop()
            except Exception:
                LOG.exception('Could not stop capture')
                status = 1
        pipeline.stop()
        output.close()
        if pipeline.failed.is_set():
            status = 1
    return status


if __name__ == '__main__':
    raise SystemExit(main())
