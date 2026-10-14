# WireGuard Profile Generation

AirBL can write ready-to-use WireGuard `.conf` files from the latest scan, for routers, other machines or containers.

Set this up in **Settings → WireGuard Profile Generation**. Each profile writes to its own output directory (default `/app/wireguard`, mounted as `docker/wireguard`).

## Modes

| Mode | Files written |
|---|---|
| Only Clean Server (default) | One `<Server>.conf` per clean server |
| All Servers (incl. blocked) | One per server, blocked included |
| Fastest Server / Fastest Clean Server | One file for the top-scoring server |
| Best per Country | `CC.conf`: the best clean server per country |
| Best per City | `CC-City.conf`: the best clean server per city |
| Use AirBL Settings | Like Only Clean, limited to the countries/cities selected for scanning |

The **Allowed Countries / Cities** pickers filter in every mode.

**Auto-update wg0.conf** keeps a `wg0.conf` pointing at the best server. It's never a blocked one, except in "Fastest Server" mode.

Files a profile generated earlier but no longer produces are removed on the next run, e.g. a country with no clean server left. Only that profile's own files are touched.

## Options

- **Entry IP:** Entry 1, Entry 3 or AUTO (best ping history from the database).
- **Port:** 1637, 47107 or 51820.
- **IP layer exit:** `Both`, `IPv4` or `IPv6`.
  - IPv6 routes (`::/0`) are only added when your address includes IPv6.
  - AirVPN's DNS (10.128.0.1) is always routed through the tunnel.
  - IPv6 *endpoints* aren't supported; the IPv4 entry is used.
- **MTU / Keepalive.**
- **Keys:** the private key comes from the profile (or is pre-filled from your configs).
  - The address and preshared key come from your AirVPN configs, so use a private key from the same AirVPN device.
  - A **public key override** replaces the server key if set.

Generated files contain your private key, so keep the output folder private.
