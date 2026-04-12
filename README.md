<div align="center">
  <p><a href="https://www.airvpn.org">
  <img src="https://airvpn.org/static/img/logo/logo_horiz.png" alt="AirVPN" width="300"/>
  </a></p>
  <h1>AirBL</h1>
  <p><b>An Advanced AirVPN Network Optimizer, Blocklist Checker, and Profile Generator</b></p>
</div>

---

**AirBL** is a comprehensive toolkit designed to optimize your AirVPN connections. It continuously scans AirVPN infrastructure, drops unresponsive or DroneBL-blacklisted endpoints, performs speed and latency tests, and actively generates routing configurations for your local network—all controlled through a beautiful, glassmorphism web dashboard.

## 🌟 Key Features

- 🔍 **DNS-Guided Endpoints**: Uses direct DNS polling and rapid ICMP latency sampling to map accurate Entry and Exit IP pairs without generating legacy subnet noise.
- 🚫 **DroneBL Verification**: Automatically drops Exit IPs logged on the [DroneBL](https://dronebl.org/) abuser blocklist.
- 📡 **Port & Entry Discovery**: Intelligently cycles across all protocol combos (e.g. 1637, 47107) and entry IPs across a multi-day test window to discover the absolute fastest networking route for your ISP.
- ⚡ **"Best Route" Discovery**: Logs historical latency database metrics to deduce the absolute fastest entry point (`AUTO` routing mode).
- 🚀 **Automated Speedtesting**: Validates throughput inline via isolated namespaces and permanently bans under-performing routing chains.
- 🌐 **RFC1918 Policy Routing**: Intelligent Docker bridge bypassing ensures you never lose access to the Web Interface. UI calls are automatically routed over the host while aggressive VPN benchmarks are encapsulated transparently in the background.
- 📊 **Advanced Historic Metrics**: An isolated dashboard dedicated to long-term environment telemetry. Identify systemic latency shifts, map long-tail ban frequencies, and monitor aggregated DroneBL strikes dynamically on interactive Chart.js graphs.
- 🔗 **Gluetun Supercharger**: Natively filters `servers.json` profiles for Gluetun and triggers smart internal control API restarts based on custom rules (e.g., `CLEAN_ONLY`, `NOT_TOP4`).
- 🔒 **Dynamic Config Generation**: Say goodbye to mounting thousands of `wg0.conf` profiles! Provide *one* configuration or just your private key, and AirBL dynamically generates valid WireGuard structures on the fly mapped strictly to clean ping-priority endpoints.
- 🖥️ **Sleek Web Interface**: Fully responsive, dark-mode real-time dashboard to manage server filters, thresholds, and view history.
- 🐳 **Docker-Native**: Built precisely for Docker, with embedded `wg-quick` policy routing that isolates test payloads.

## 📸 Dashboard Preview
*(Add your beautiful Glassmorphism UI screenshots here!)*

> Need to see it to believe it? Direct users to the integrated `landing_page.html` for a full portfolio view of the capabilities.

## 🚀 Quick Start (Docker)

AirBL is designed to run isolated inside a container with `wg-quick` routing correctly sequestered via policy routing.

### 1. Mount Configuration Identity
Drop **just one** standard AirVPN WireGuard `.conf` file into the `/conf` directory. AirBL will parse it to safely extract your `PrivateKey`, `PublicKey`, and internal `Address` parameters without leaking your credentials. After capturing your identity, the system dynamically synthesizes all future port combinations and entry server connections in real time into its internal isolated `/confgen` directory!

### 2. Start the Stack
```bash
docker-compose -f docker/docker-compose.yml up -d
```

### 3. Access Dashboard
Navigate to `http://localhost:5665` in your browser.

## 🔗 Integrated VPN Generation

### Gluetun Generation
AirBL replaces Gluetun's static configuration methodology. You can natively inject a rebuilt `servers.json` packed strictly with latency-optimized endpoints. Furthermore, AirBL can ping Gluetun's control API to trigger a smart container restart only when your active endpoint drops out of the "Top 4" safe list.

### WireGuard Profiles
Build perfect WireGuard sub-configs using `AUTO` Entry-IP resolution, MTU clamping, and split-layer IPv4/IPv6 exit behavior, all injected with your secure private key directly from the dashboard.

## 📚 Documentation
For detailed guidance on configuration filters, network routing, and deployment architecture, please check the [Wiki pages](docs/Home.md) in the `docs/` folder:
- [Installation instructions](docs/Installation.md)
- [Configuration options](docs/Configuration.md)
- [Gluetun Integration](docs/Gluetun-Integration.md)
- [WireGuard Generation](docs/WireGuard-Integration.md)

## 📝 License
Built under the GNU General Public License v3.0 (GPL-3.0). This project is community-supported and unaffiliated directly with AirVPN.
