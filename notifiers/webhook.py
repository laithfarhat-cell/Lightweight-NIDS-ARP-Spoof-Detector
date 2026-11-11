"""Best-effort asynchronous notification delivery; no secrets are logged."""
import asyncio
import logging
import time
from collections import OrderedDict
from urllib.parse import urlparse

import aiohttp

LOG = logging.getLogger(__name__)


class Cooldown:
    def __init__(self, seconds, limit, clock=time.monotonic):
        self.seconds, self.limit, self.clock = seconds, limit, clock
        self.last = OrderedDict()

    def allow(self, alert):
        now = self.clock()
        key = (alert['signature'], alert['attacker_ip'])
        previous = self.last.get(key)
        if previous is not None and now - previous < self.seconds:
            return False
        self.last[key] = now
        self.last.move_to_end(key)
        while len(self.last) > self.limit:
            self.last.popitem(last=False)
        return True


def _safe(value):
    # Code spans prevent markdown injection from interface or packet-derived fields.
    return str(value).replace('`', "'").replace('\n', ' ').replace('\r', ' ')[:256]


def format_message(alert):
    return (f"**NIDS alert: {_safe(alert['signature'])}**\n"
            f"Severity: `{_safe(alert['severity'])}`\nTimestamp: `{_safe(alert['timestamp'])}`\n"
            f"Attacker IP: `{_safe(alert['attacker_ip'])}`\nSource MAC: `{_safe(alert['source_mac'])}`")


def validate_discord_url(url):
    # Avoid accidentally sending alerts or credentials to arbitrary hosts.
    parsed = urlparse(url)
    if (parsed.scheme != 'https' or parsed.hostname not in {'discord.com', 'discordapp.com'}
            or parsed.username or parsed.password or parsed.port not in (None, 443)
            or not parsed.path.startswith('/api/webhooks/')):
        raise ValueError('DISCORD_WEBHOOK_URL must be an HTTPS Discord webhook URL')


async def send(session, config, alert):
    message = format_message(alert)
    jobs = []
    if config.discord_url:
        jobs.append(('Discord', config.discord_url, {'content': message, 'allowed_mentions': {'parse': []}}))
    if config.telegram_token and config.telegram_chat_id:
        # Telegram HTML supports a smaller, predictable escaping surface than MarkdownV2.
        from html import escape
        text = (f"<b>NIDS alert: {escape(str(alert['signature']))}</b>\n"
                f"Severity: <code>{escape(str(alert['severity']))}</code>\n"
                f"Timestamp: <code>{escape(str(alert['timestamp']))}</code>\n"
                f"Attacker IP: <code>{escape(str(alert['attacker_ip']))}</code>\n"
                f"Source MAC: <code>{escape(str(alert['source_mac']))}</code>")
        jobs.append(('Telegram', f'https://api.telegram.org/bot{config.telegram_token}/sendMessage',
                     {'chat_id': config.telegram_chat_id, 'text': text, 'parse_mode': 'HTML'}))

    async def post(name, url, payload):
        try:
            async with session.post(url, json=payload, allow_redirects=False) as response:
                if response.status >= 300:
                    LOG.warning('%s webhook failed with HTTP %s', name, response.status)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            # Exception text may contain a webhook URL or bot token.
            LOG.warning('%s webhook request failed', name)
    await asyncio.gather(*(post(*job) for job in jobs))
