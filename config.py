"""Command-line and environment configuration."""
import argparse
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    interface: str
    log_file: str = 'alerts.json'
    window: float = 3.0
    scan_ports: int = 20
    syn_threshold: int = 100
    arp_window: float = 3.0
    gratuitous_threshold: int = 5
    arp_request_timeout: float = 10.0
    arp_entry_ttl: float = 3600.0
    cooldown: float = 60.0
    queue_size: int = 4096
    max_sources: int = 4096
    max_events: int = 4096
    discord_url: str = ''
    telegram_token: str = ''
    telegram_chat_id: str = ''


def positive_float(value):
    try:
        number = float(value)
        if not 0 < number < float('inf'):
            raise ValueError
        return number
    except ValueError:
        raise argparse.ArgumentTypeError('must be a finite positive number')


def positive_int(value):
    try:
        number = int(value)
        if number <= 0:
            raise ValueError
        return number
    except ValueError:
        raise argparse.ArgumentTypeError('must be a positive integer')


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Passive ARP spoof and TCP SYN monitor')
    parser.add_argument('-i', '--interface', required=True, help='network interface to monitor')
    parser.add_argument('--log-file', default='alerts.json', help='JSON Lines alert file (default: alerts.json)')
    parser.add_argument('--window', type=positive_float, default=3.0, help='TCP SYN sliding window in seconds')
    parser.add_argument('--scan-ports', type=positive_int, default=20, help='distinct destination ports per source')
    parser.add_argument('--syn-threshold', type=positive_int, default=100, help='SYN packets per source per window')
    parser.add_argument('--arp-window', type=positive_float, default=3.0, help='gratuitous ARP window in seconds')
    parser.add_argument('--gratuitous-threshold', type=positive_int, default=5, help='gratuitous broadcasts per IP per window')
    parser.add_argument('--arp-request-timeout', type=positive_float, default=10.0, help='seconds to correlate ARP requests and replies')
    parser.add_argument('--arp-entry-ttl', type=positive_float, default=3600.0, help='seconds before an inactive ARP binding expires')
    parser.add_argument('--cooldown', type=positive_float, default=60.0, help='webhook cooldown per signature and source in seconds')
    parser.add_argument('--queue-size', type=positive_int, default=4096, help='maximum items per pipeline queue')
    parser.add_argument('--max-sources', type=positive_int, default=4096, help='maximum tracked keys per detector table')
    parser.add_argument('--max-events', type=positive_int, default=4096, help='maximum events retained per tracked key')
    args = parser.parse_args(argv)
    if max(args.scan_ports, args.syn_threshold, args.gratuitous_threshold) > args.max_events:
        parser.error('thresholds must not exceed --max-events')
    token = os.getenv('TELEGRAM_BOT_TOKEN', '')
    chat_id = os.getenv('TELEGRAM_CHAT_ID', '')
    if bool(token) != bool(chat_id):
        parser.error('TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must both be set')
    return Config(**vars(args), discord_url=os.getenv('DISCORD_WEBHOOK_URL', ''),
                  telegram_token=token, telegram_chat_id=chat_id)
