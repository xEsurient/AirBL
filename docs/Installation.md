# Installation

AirBL runs in Docker. During speedtests it brings up a WireGuard tunnel inside its own container and changes the container's routing, so it needs `NET_ADMIN` but no privileged mode, and it never touches the host's routing.

Images build natively for amd64 and arm64 (e.g. Raspberry Pi 4/5 with a 64-bit OS). 32-bit ARM (armhf) is not supported: a dependency (pydantic-core) has no prebuilt package for it and would need a Rust toolchain.

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

## Prebuilt image

Instead of building from source, you can pull `ghcr.io/xesurient/airbl` (amd64 and arm64).

**docker run.** No clone needed. Run it from the folder that holds your `conf/`; `data/`, `gluetun/` and `wireguard/` are created next to it:

```bash
docker run --detach \
    --name airbl \
    --cap-add NET_ADMIN \
    --sysctl net.ipv4.conf.all.src_valid_mark=1 \
    --sysctl net.ipv4.ip_forward=1 \
    --sysctl net.ipv6.conf.all.disable_ipv6=1 \
    --publish 5665:5665 \
    --env TZ=Europe/London \
    --volume "$PWD/conf:/app/conf:ro" \
    --volume "$PWD/data:/app/data" \
    --volume "$PWD/gluetun:/app/gluetun" \
    --volume "$PWD/wireguard:/app/wireguard" \
    --restart unless-stopped \
    ghcr.io/xesurient/airbl:latest
```

To update: `docker pull ghcr.io/xesurient/airbl:latest`, then `docker rm -f airbl` and run the same command again. Your data stays in `./data`.

**Compose.** `docker/docker-compose.ghcr.yml` swaps the build for the image and keeps everything else from the main compose file:

```bash
cd docker
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml pull
docker compose -f docker-compose.yml -f docker-compose.ghcr.yml up -d
```

The override needs Docker Compose v2.24 or newer (`docker compose version`). To avoid typing both files every time, add `COMPOSE_FILE=docker-compose.yml:docker-compose.ghcr.yml` to `docker/.env`. Then plain `docker compose pull && docker compose up -d` updates to the newest image.

Tags: `latest` follows the main branch, `1.2.3` / `1.2` are releases, and `sha-<commit>` pins an exact build. To pin one, edit the `image:` lines in `docker-compose.ghcr.yml`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | 5665 | Dashboard port. Also used by the healthcheck, the dashboard routing rule and the kill switch. With compose, set it in `docker/.env` so the published port follows. |
| `TZ` | UTC | Time zone for schedules ("05:00") and timestamps. Put e.g. `TZ=Europe/London` in `docker/.env`. |
| `AIRBL_CONFIG_DIR` | /app/conf | WireGuard `.conf` files. |
| `AIRBL_CACHE_DIR` | /app/data | Database, settings, baseline. |
| `AIRBL_DB_PATH` | `<cache dir>/airbl.db` | Database file, if it should live elsewhere. |
| `AIRBL_CONFIG_FILE` | `<config dir>/airbl-config.json` | Optional read-only base settings file (see `CONFIG-EXAMPLE.md`). |
| `DNS_SERVERS` | system resolver | Resolvers for DroneBL lookups. |
| `SCAN_INTERVAL` | (unset) | Minutes; when set, overrides the interval saved in Settings on every start. |
| `AUTO_SCAN` | (unset) | `true`/`false`; when set, overrides the saved auto-scan toggle on every start. |
| `AIRBL_KILL_SWITCH` | 1 | Set to `0` to disable the speedtest kill switch. |
| `HOST` | 0.0.0.0 | Bind address. |
| `AIRBL_ALLOWED_ORIGINS` | (unset) | Extra origins allowed to change settings, comma-separated (e.g. `https://airbl.example`). Only needed behind a reverse proxy that changes the host name and doesn't send `X-Forwarded-Host`. |

## Notes

- **Network mode:** use the default bridge network. With `network_mode: host`, AirBL's routing rules would apply to the whole host, so the kill switch disables itself there and that mode is unsupported for VPN tests.
- **Persistence:** everything worth keeping is in `./data`: scan/speedtest history, settings (plus a `.bak` of the previous version) and the baseline speedtest. Recreating the container keeps it all.
- **Updates:** rebuild with `docker compose up -d --build` (or `docker compose pull && docker compose up -d` with the prebuilt image). Browsers pick up new dashboard code automatically (no force-refresh needed).
- **Init:** the image runs under `tini`, which reaps child processes (speedtests, pings) cleanly.
- **Other commands:** `docker compose run --rm airbl <command>` passes CLI commands through, e.g. `configs`, `check <ip>`, `ping <ip>`, `--help`. `check` exits 0 (clean), 1 (listed) or 2 (unverified); `ping`, `speedtest`, `scan` and `status` exit non-zero on failure. Run speedtests from the dashboard while the web app is up: the CLI refuses, since both would use the same tunnel.

## Without Docker (development)

```bash
pip install -r requirements.txt
AIRBL_CONFIG_DIR=./docker/conf AIRBL_CACHE_DIR=./data python -m airbl.web
```

VPN speedtests need root and Linux networking tools (`wg`, `ip`, `iptables`); scanning and the dashboard work without them.
