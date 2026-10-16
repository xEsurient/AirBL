# AirBL

AirBL keeps your AirVPN connection on servers that aren't on the [DroneBL](https://dronebl.org/) blocklist and are fast enough to use. It runs in Docker with a web dashboard.

[Website](https://xesurient.github.io/AirBL/) · [Documentation](docs/Home.md)

![AirBL dashboard](https://xesurient.github.io/AirBL/assets/overview.jpg)

## What it does

- **Scans** the AirVPN servers you choose and pings their entry and exit IPs.
- **Checks** every exit IP against DroneBL. A server is Clean only when all its exit IPs were verified; failed lookups stay Unverified.
- **Speed-tests** each server through its own WireGuard tunnel, with a kill switch so nothing is measured over your normal connection. Servers that stay slow are disabled.
- **Keeps Gluetun on clean servers** through Gluetun's control API. See [Gluetun integration](docs/Gluetun-Integration.md).
- **Generates WireGuard configs** for the best servers. See [WireGuard generation](docs/WireGuard-Integration.md).

## Requirements

- Docker with Compose
- An AirVPN account and WireGuard `.conf` files from the AirVPN Config Generator
- The `NET_ADMIN` capability (already set in `docker/docker-compose.yml`)

## Quick start

1. Put one AirVPN WireGuard `.conf` per server you want to scan into `docker/conf/`, or a single region config (e.g. `AirVPN_Europe_UDP-1637-Entry3.conf`) to scan every server.
2. Optional: create `docker/.env` with your time zone, e.g. `TZ=Europe/London`, so schedules use local time.
3. Start it:
   ```bash
   cd docker && docker compose up -d --build
   ```
   Or skip the build and run the prebuilt image `ghcr.io/xesurient/airbl` (amd64 and arm64, e.g. a 64-bit Raspberry Pi). Run it from the folder that holds your `conf/` (`docker/` if you cloned the repo):
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
   See [Installation](docs/Installation.md#prebuilt-image) for the compose version, tags and updates.
4. Open `http://<host>:5665` and choose countries, servers and a schedule under **Settings**.

## Using it with Gluetun

In **Settings → Gluetun**, enter Gluetun's control server address and API key, then pick a switch mode such as *Clean Only*. AirBL then moves Gluetun to clean servers after each scan, checks every minute that it stays on one, and does the same on demand with **Apply Now**. It can also write a filtered server list file for Gluetun. Details are in the [Gluetun guide](docs/Gluetun-Integration.md).

## Documentation

- [Installation](docs/Installation.md)
- [Configuration](docs/Configuration.md)
- [Gluetun integration](docs/Gluetun-Integration.md)
- [WireGuard generation](docs/WireGuard-Integration.md)
- [Troubleshooting](docs/Troubleshooting.md)

## Development

Run the tests with `pip install -r requirements.txt pytest pytest-asyncio && python -m pytest -q` (about 1 s, no network). Browser checks for a running instance are in `tests/browser/`.

## License

GPL-3.0-only (see [LICENSE](LICENSE)). AirBL is a community project and is not affiliated with AirVPN or DroneBL.
