<div align="center">
  <p><a href="https://www.airvpn.org">
  <img src="https://airvpn.org/static/img/logo/logo_horiz.png" alt="AirVPN" width="300"/>
  </a></p>
  <h1>AirBL</h1>
  <p><b>An Advanced AirVPN Network Optimizer, Blocklist Checker, and Profile Generator</b></p>
</div>

---

**AirBL** is a comprehensive toolkit designed to optimize your AirVPN connections. It continuously scans AirVPN infrastructure, drops unresponsive or DroneBL-blacklisted endpoints, performs speed and latency tests, and actively generates routing configurations for your local network—all controlled through a beautiful, glassmorphism web dashboard.

![AirBL Dashboard](https://github.com/xEsurient/AirBL/blob/8a61f0061c62e3712833903d1131ce1b1b39015f/assets/dashboard.png)

## 🌟 Key Features

- 🔍 **DNS-Guided Endpoints**: Looks up each server's exit IPs via AirVPN DNS (IPv4 and IPv6) and pings entry and exit IPs over both ICMP and TCP, keeping the lower latency (some hosts block one or the other).
- 🚫 **DroneBL Verification**: Checks every exit IP against the [DroneBL](https://dronebl.org/) blocklist. A server is **Clean** only when every exit IP was verified unlisted; any listing makes it **Blocked**, and failed lookups make it **Unverified** (never treated as clean). Blocked servers show the DroneBL reason.
- 🚀 **Verified Speedtesting**: Brings up its own WireGuard tunnel, waits for a real handshake and confirms traffic leaves via AirVPN before measuring. A kill switch, a fallback route and a per-result exit-IP check make sure nothing is measured over your normal connection. Servers that stay below your thresholds are auto-disabled.
- 📡 **Port & Entry Discovery**: Over a multi-day window, tests every port × entry combination (1637, 47107, 51820 × Entry 1/3) on your best servers. Combos are compared within the same scan, and the winner becomes your preferred port/entry.
- 🔗 **Gluetun Integration**: Writes a filtered AirVPN server list for Gluetun (current `servers/airvpn.json` or legacy `servers.json` format). It can also switch a running local or remote Gluetun to clean servers through its control API (API key supported), using rules like *Clean Only* or *Reset if not Top 4*.
- 🔒 **WireGuard Profile Generation**: Generates `.conf` files per server, the best server per country or city, or just the fastest one, plus an always-current `wg0.conf`.
- 📊 **History & Metrics**: Scan history, speedtests and ban frequency are kept in SQLite and charted on the dashboard.
- 🖥️ **Web Dashboard**: Live dashboard with server filters, settings, discovery results and a debug log.
- 🐳 **Docker-Native**: Policy routing keeps the dashboard reachable while tests run inside the container. Schedules use your local time zone (`TZ`).

> Need to see it to believe it? Check out `https://xesurient.github.io/AirBL/`.

## 🚀 Quick Start (Docker)

### 1. Add your AirVPN WireGuard configs
Put the AirVPN WireGuard `.conf` files for the servers you want to scan into `docker/conf/` (generate them in the AirVPN Config Generator). **Each scanned server needs its own `.conf`.** AirBL also reads your client identity (keys and address) from them to generate extra configs for port/entry discovery.

### 2. Optional: set your time zone
Create `docker/.env` with e.g. `TZ=Europe/London` so schedules like "05:00" use your local time (default UTC).

### 3. Start the stack
```bash
cd docker && docker compose up -d --build
```

### 4. Open the dashboard
`http://<host>:5665`, then choose countries/servers and schedules under **Settings**.

## 🔗 Outputs

### Gluetun
Mount a folder shared with Gluetun at `/app/gluetun` and enable a Gluetun profile. See [Gluetun Integration](docs/Gluetun-Integration.md) for which file your Gluetun version reads and how to set up the control API.

### WireGuard Profiles
Generated configs are written to `/app/wireguard` (mounted as `docker/wireguard`). See [WireGuard Generation](docs/WireGuard-Integration.md).

## 📚 Documentation
- [Installation instructions](https://github.com/xEsurient/AirBL/wiki/Installation.md)
- [Configuration options](https://github.com/xEsurient/AirBL/wiki/Configuration.md)
- [Gluetun Integration](https://github.com/xEsurient/AirBL/wiki/Gluetun-Integration.md)
- [WireGuard Generation](https://github.com/xEsurient/AirBL/wiki/WireGuard-Integration.md)

## 🧪 Tests
`pip install -r requirements.txt pytest pytest-asyncio && python -m pytest -q` (about 1 s, no network). Browser checks for a running instance are in `tests/browser/`.

## 📝 License
Built under the GNU General Public License v3.0 (GPL-3.0). This project is community-supported and unaffiliated directly with AirVPN.
