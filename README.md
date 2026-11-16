# wifi-presence

Tiny LAN presence tracker. Scans the local subnet every 30 s, labels devices by
MAC, and exposes a local HTTP API consumed by the
[whatsapp-bot-with-ai](https://github.com/sirajju/whatsapp-bot-with-ai)
`!home` / `!devices` / `!label` skill.

- Pure Go, static binary, no cgo, no root, no system packages.
- Idle footprint: ~12 MB RSS.
- SQLite for state — survives restarts without re-firing stale "arrived" events.
- Designed to pair with wa-bot, but the HTTP API is generic.

## How it works

1. Every poll tick, short-timeout TCP dials to every host in the /24.
   The kernel has to ARP-resolve the destination to even try — ARP cache
   is populated as a side effect, without needing CAP_NET_RAW.
2. `/proc/net/arp` is read; each (MAC, IP) becomes a Sighting.
3. A debounced state machine tracks home/away per MAC:
   - seen within `PRESENCE_HOME_WINDOW` (default 90 s) = HOME
   - unseen past `PRESENCE_AWAY_WINDOW` (default 5 min) = AWAY
   - the gap is a hysteresis band so phones in power-save don't flap.
4. Transitions are appended to an events table; the wa-bot polls it.

No signal-strength / RSSI. The MediaTek ONT router this is designed for
doesn't expose per-station radio stats, and server-side sniffing requires
a monitor-mode adapter. See the project blog if you later add ESPresense.

## Install

```bash
git clone https://github.com/sirajju/wifi-presence.git
cd wifi-presence
cp .env.example .env
make build-linux
./bin/presence-linux-amd64              # test it; Ctrl-C to stop
```

### systemd (user unit, no root)

```bash
make install-systemd
systemctl --user enable --now presence
systemctl --user status presence
journalctl --user -u presence -f
```

## HTTP API

Default listen: `127.0.0.1:8765`. Everything is JSON.

| Method | Path | Purpose |
|---|---|---|
| GET  | `/healthz` | liveness probe |
| GET  | `/api/status` | current home/away split + counts |
| GET  | `/api/devices` | every known MAC with label, vendor, last-seen |
| GET  | `/api/events?since=<rfc3339\|unix>&limit=N` | event feed, oldest first |
| POST | `/api/label` | `{"mac":"aa:bb:...", "label":"Siraj phone", "owner":"Siraj"}` |

Event `kind` values: `arrived`, `departed`, `new_device`, `house_empty`, `house_occupied`.

## Configuration

Every setting is an env var, with defaults in `.env.example`. The most useful ones:

| Var | Default | Notes |
|---|---|---|
| `PRESENCE_LISTEN` | `127.0.0.1:8765` | Keep it loopback-only. |
| `PRESENCE_INTERFACE` | `auto` | Picks the first UP, non-loopback, RFC1918 interface (skips tailscale/docker). |
| `PRESENCE_SUBNET` | `auto` | Clamped to /24 even if your interface is on a larger prefix. |
| `PRESENCE_POLL_INTERVAL` | `30s` | |
| `PRESENCE_HOME_WINDOW` | `90s` | |
| `PRESENCE_AWAY_WINDOW` | `5m` | |

## wa-bot integration

The bot ships a `!home` / `!devices` / `!label` skill that only HTTP-calls this
service — no code duplication. Point the bot at `PRESENCE_API_URL=http://127.0.0.1:8765`
in its own `.env`.

## License

MIT.
