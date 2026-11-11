# Lightweight NIDS & ARP Spoof Detector

A passive Python/Scapy sensor for IPv4 TCP SYN reconnaissance and suspicious ARP on a single interface. Capture, detection, JSON logging and best-effort webhook delivery are isolated by bounded queues. The capture callback only enqueues packets; Scapy performs its own decoding in the capture thread. This is a monitoring tool, **not** an inline firewall or a guarantee of detecting every attack.

```text
 Interface (ARP/TCP) -- Scapy capture --> [bounded packet queue]
                                             |
                                  detector worker (bounded state)
                                             |
                                      [bounded alert queue]
                                             |
                                   JSON Lines file / SIEM
                                             |
                              per-source/signature cooldown
                                             |
                                [bounded webhook queue]
                                             |
                                async Discord + Telegram
```

## Installation and usage

Requires Python 3.10+, libpcap, and permissions to capture on the chosen interface. On Linux, install `libpcap` (e.g. `sudo apt install libpcap0.8`), then:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
# Run with appropriate capture privileges; use the venv interpreter under sudo:
sudo .venv/bin/python main.py --interface eth0 --log-file alerts.json
```

Choose a real interface with `ip link` (Linux) or `ifconfig` (macOS). For notifications, provide `DISCORD_WEBHOOK_URL`, and/or both `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in the **process environment**. Pass them securely via your service manager or secret store; `sudo` often strips environment variables. The Discord URL must be an HTTPS `discord.com`/`discordapp.com` webhook URL. The application never logs webhook URLs or bot tokens. Protect the alert file and secrets with appropriate filesystem and service permissions.

### Docker Compose (Linux)

```sh
# Set NIDS_INTERFACE and optional webhook environment variables in your shell
export NIDS_INTERFACE=eth0
docker compose up -d --build
docker compose logs -f nids
docker compose down
```

The container uses host networking and only the `NET_RAW` and `NET_ADMIN` capabilities, and appends to `./data/alerts.json`. Host networking here is intended for a Linux Docker host; Docker Desktop runs the container in a VM and will not monitor the physical host interface. Set the interface to one visible in the host network namespace. Tune CLI arguments by modifying the Compose `command`. Restrict access to the mounted `data` directory. Provision disk monitoring and external log rotation; the process keeps the file open, so use a rotation strategy that copies/truncates the file or restart the service after renaming it. Root or capture capabilities expose sensitive traffic: deploy only on authorized networks.

## CLI

Run `python main.py --help` for defaults and descriptions. All numeric options must be positive; thresholds cannot exceed `--max-events`.

| Option | Default | Purpose |
|---|---:|---|
| `-i`, `--interface` | required | Interface to capture |
| `--log-file` | `alerts.json` | Append-only JSON Lines output |
| `--window` | 3 seconds | SYN sliding window |
| `--scan-ports` | 20 | Distinct destination ports per source in window |
| `--syn-threshold` | 100 | SYNs per source in window (flood signature) |
| `--arp-window` | 3 seconds | Gratuitous broadcast window |
| `--gratuitous-threshold` | 5 | Gratuitous broadcasts per IP in window |
| `--arp-request-timeout` | 10 seconds | ARP request/reply correlation lifetime |
| `--arp-entry-ttl` | 3600 seconds | Inactive binding lifetime |
| `--cooldown` | 60 seconds | Webhook cooldown per signature and source IP |
| `--queue-size` | 4096 | Capacity of each pipeline queue |
| `--max-sources` | 4096 | Maximum keys in each state/cooldown table |
| `--max-events` | 4096 | Maximum retained window events per key |

## Detection and alerts

* ARP requests and replies establish first-observed IP-to-MAC bindings (ARP probes with `0.0.0.0` do not). A different MAC claiming an existing IP triggers `arp_binding_conflict`; the original binding is retained until its TTL expires. This is trust-on-first-observation, **not** a trusted baseline. ARP replies without a recently observed matching request trigger `unsolicited_arp_reply`. Broadcast ARP announcements where sender and target IP match are counted for `gratuitous_arp_burst`.
* IPv4 TCP SYNs without ACK are counted per source across all observed destinations. `tcp_port_scan` counts distinct destination port numbers; `tcp_syn_flood` counts packets, including retransmissions. The sensor sees traffic available on the interface, including locally generated/outbound packets; it does not infer traffic direction. IPv6, UDP scans, and distributed floods are not detected.
* These are heuristics. Legitimate failover, DHCP changes, gratuitous announcements, asymmetrical visibility, starting mid-conversation, retransmissions, proxies and NAT can cause false positives or missed detections. Packet loss, spoofed source addresses, encryption/tunnels, switched-network visibility, finite state eviction and high traffic can also affect results. Test and tune for your network.
* Every triggered alert is appended as one flat JSON object per line (JSON Lines, not a JSON array or ECS). Cooldown suppresses **webhooks only**; repeated alerts remain in the file. Keys in the bounded cooldown table may be evicted under high cardinality. Notifications are best-effort, use a five-second timeout, are not retried, and do not follow redirects. Discord uses Markdown and Telegram uses HTML's equivalent rich formatting. A webhook failure does not stop logging.

Example (`alerts.json`):

```json
{"timestamp":"2026-11-11T10:00:00.000Z","signature":"tcp_port_scan","severity":"high","attacker_ip":"192.0.2.10","source_mac":"00:11:22:33:44:55","interface":"eth0","distinct_ports":20,"syn_count":20}
```

`attacker_ip` is the observed claimed source, not proof of an attacker. The timestamp is UTC detection time; for ARP conflicts `claimed_mac` and `previous_mac` provide the ARP payload and prior binding, while `source_mac` is the observed Ethernet source when present. Other signatures add relevant count fields.

## Operations and tests

The service handles SIGINT/SIGTERM by stopping capture and draining accepted packets and alerts, with bounded shutdown waits. Pending notifications may be discarded at shutdown. If a queue fills, new items are dropped rather than blocking capture; cumulative dropped counts are logged periodically when they change and on exit. Alert-file errors stop the sensor with a nonzero exit. Monitor process health, storage capacity, queue drops and capture permissions; no persistence or replay of state is provided. Memory is bounded by queue/table/event settings, although worst-case memory grows with `max-sources * max-events` per window tracker. In highly loaded environments, tune caps and consider using a dedicated capture sensor.

```sh
pip install pytest
python -m pytest -q
```
