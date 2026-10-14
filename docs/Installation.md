# Installation

AirBL runs in Docker. During speedtests it brings up a WireGuard tunnel inside its own container and changes the container's routing, so it needs `NET_ADMIN` but no privileged mode, and it never touches the host's routing.

Images build natively for amd64, arm64 (e.g. Raspberry Pi 4/5 with 64-bit OS) and armhf.

## Docker Compose (recommended)

Use `docker/docker-compose.yml` from the repository. The essentials:

```yaml
services:
  airbl:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    container_name: airbl
    cap_add:
      - NET_ADMIN
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv4.ip_forward=1
      - net.ipv6.conf.all.disable_ipv6=1
    ports:
      - "5665:5665"
    volumes:
      - ./conf:/app/conf:ro            # your AirVPN WireGuard .conf files
      - ./data:/app/data               # database, settings, baseline (persistent)
      - ./gluetun:/app/gluetun         # Gluetun server lists (share with Gluetun)
      - ./wireguard:/app/wireguard     # generated WireGuard configs (contain your private key)
    environment:
      - PORT=5665
      - TZ=${TZ:-UTC}
      - AIRBL_CONFIG_DIR=/app/conf
      - AIRBL_CACHE_DIR=/app/data
      - AIRBL_CONFIG_FILE=/app/conf/airbl-config.json
      - DNS_SERVERS=1.1.1.1,8.8.8.8
    restart: unless-stopped
```

```bash
cd docker && docker compose up -d --build
```

Then open `http://<host>:5665/`.

Put one AirVPN WireGuard `.conf` per server you want scanned into `docker/conf/`. AirBL also reads your client identity from them, to generate extra configs for other ports and entries.

Alternatively, use a single region config (e.g. `AirVPN_Europe_UDP-1637-Entry3.conf`). Its name doesn't name a server, so AirBL uses its keys and port to generate a config for every server in AirVPN's server list (Entry 3, or Entry 1 if a server has none). Choose what to scan with Settings → Scan Regions and City Selection. If `docker/conf/` has any per-server configs, only those are scanned.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 5665 | Dashboard port. Also used by the healthcheck, the dashboard routing rule and the kill switch. |
| `TZ` | UTC | Time zone for schedules ("05:00") and timestamps. Put e.g. `TZ=Europe/London` in `docker/.env`. |
| `AIRBL_CONFIG_DIR` | /app/conf | WireGuard `.conf` files. |
| `AIRBL_CACHE_DIR` | /app/data | Database, settings, baseline. |
| `AIRBL_CONFIG_FILE` | `<config dir>/airbl-config.json` | Optional read-only base settings file (see `CONFIG-EXAMPLE.md`). |
| `DNS_SERVERS` | system resolver | Resolvers for DroneBL lookups. |
| `SCAN_INTERVAL` | (unset) | Minutes; when set, overrides the interval saved in Settings on every start. |
| `AUTO_SCAN` | (unset) | `true`/`false`; when set, overrides the saved auto-scan toggle on every start. |
| `AIRBL_KILL_SWITCH` | 1 | Set to `0` to disable the speedtest kill switch. |
| `HOST` | 0.0.0.0 | Bind address. |

## Notes

- **Network mode:** use the default bridge network. With `network_mode: host`, AirBL's routing rules would apply to the whole host, so the kill switch disables itself there and that mode is unsupported for VPN tests.
- **Persistence:** everything worth keeping is in `./data`: scan/speedtest history, settings (plus a `.bak` of the previous version) and the baseline speedtest. Recreating the container keeps it all.
- **Updates:** rebuild with `docker compose up -d --build`. Browsers pick up new dashboard code automatically (no force-refresh needed).
- **Init:** the image runs under `tini`, which reaps child processes (speedtests, pings) cleanly.
- **Other commands:** `docker compose run --rm airbl <command>` passes CLI commands through, e.g. `configs`, `check <ip>`, `ping <ip>`, `--help`.

## Without Docker (development)

```bash
pip install -r requirements.txt
AIRBL_CONFIG_DIR=./docker/conf AIRBL_CACHE_DIR=./data python -m airbl.web
```

VPN speedtests need root and Linux networking tools (`wg`, `ip`, `iptables`); scanning and the dashboard work without them.
