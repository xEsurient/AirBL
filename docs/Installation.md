# Installation

AirBL runs in Docker. During speedtests it brings up a WireGuard tunnel inside its own container and changes the container's routing, so it needs `NET_ADMIN` but no privileged mode, and it never touches the host's routing. The provided compose file drops every other capability except `NET_RAW` (ping) and `DAC_OVERRIDE` (folders owned by your host user), and sets `no-new-privileges`.

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
    cap_drop:                        # least privilege: only what AirBL uses
      - ALL
    cap_add:
      - NET_ADMIN                    # WireGuard interface, routes, kill switch
      - NET_RAW                      # ping
      - DAC_OVERRIDE                 # use folders that belong to your host user
    security_opt:
      - no-new-privileges:true
    stop_grace_period: 30s           # a stop mid-test tears the tunnel down cleanly
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
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
    --cap-drop ALL \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add DAC_OVERRIDE \
    --security-opt no-new-privileges:true \
    --stop-timeout 30 \
    --sysctl net.ipv4.conf.all.src_valid_mark=1 \
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
| `AIRBL_AUTH_TOKEN` | (unset) | Optional login. Set a long random string (e.g. in `docker/.env`). The browser then asks for it: any user name, the token as password. Scripts send `Authorization: Bearer <token>` or `X-AirBL-Token: <token>`. `/healthz` (Docker's healthcheck) stays open. Unset = no login. |
| `AIRBL_ALLOWED_HOSTS` | (unset) | Extra host names the dashboard answers to, comma-separated (e.g. `airbl.example.com`). IP addresses, `localhost`, single-label names (`peach`) and LAN names (`.local`, `.lan`, `.home.arpa`, `.internal`) always work. Any other name gets "Unknown host name" until it's listed here; this blocks DNS-rebinding attacks from web pages. |
| `AIRBL_ALLOW_HOST_NETWORK` | (unset) | AirBL refuses VPN tests in the host's network namespace (`network_mode: host`), because they would replace the host's own `wg0` / routing. Set to `1` only if you accept that risk. |
| `AIRBL_ALLOWED_ORIGINS` | (unset) | Extra origins allowed to change settings, comma-separated (e.g. `https://airbl.example`). Only needed behind a reverse proxy that changes the host name and doesn't send `X-Forwarded-Host`. |

## Notes

- **Network mode:** use the default bridge network. With `network_mode: host`, AirBL's routing rules would apply to the whole host. There, AirBL leaves `wg0` and routing table 51820 alone at startup and refuses VPN tests, unless `AIRBL_ALLOW_HOST_NETWORK=1`.
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
