# Configuration

## WireGuard configs (`conf/`)

Add the AirVPN WireGuard `.conf` file for **each server you want scanned** (AirVPN Config Generator → WireGuard). File names must keep AirVPN's pattern, e.g. `AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf`.

AirBL also reads your client identity (private key, address, preshared key) from these files. It uses that identity to generate configs for other ports and entry IPs into `/app/confgen`, which port/entry discovery and non-default port/entry choices need.

## Where settings live

- **Base file (optional, read-only):** `AIRBL_CONFIG_FILE`, default `conf/airbl-config.json`. See `CONFIG-EXAMPLE.md`.
- **Your settings:** `data/airbl-settings.json`, written by the Settings page.
  - Only values that differ from the base file are saved, so later edits to the base file still apply.
  - Each save keeps a `.bak` of the previous version.
  - If a value is ever invalid, only that value is dropped (logged) and the rest is kept. The original file is copied aside.

## The Settings page (`/settings`)

### Scan
- **Auto-scan, mode and timing:** either an interval (minutes) or a schedule (time + days). Schedules use the container's time zone (`TZ`).
- **Speedtests:** test clean servers through the VPN after each scan.
- **Tests per server:** how many speedtests to average per server (1-10).
- **VPN cooldown:** wait between servers (120 s or 180 s).

### Port & Entry Discovery
- When enabled, each scan tests every port (1637, 47107, 51820) × entry (1/3) combination on one of your top 3 clean servers, rotating between scans and in random order. Every combo uses the same generated config template.
- Only successful tests that verifiably went through the VPN count. A connect failure counts as one failed attempt (with one retry).
- Combos are scored against each other within the same scan, so different servers and times of day stay comparable.
- After the chosen duration (3/5/7 days), the best combo with at least 3 successful tests becomes your **Preferred Port / Entry**. If none qualifies, the result is "inconclusive" and your settings stay as they are. An **AUTO** entry choice is kept.
- **Preferred Port / Entry IP:** used for AirBL's own speedtests. If the preferred entry doesn't respond, the other entry on the same port is used.
  - **AUTO** picks the entry with the best ping history from the database.
  - Gluetun and WireGuard profiles have their own port/entry settings.
- **MTU for generated test configs:** 1280-1500. Your own `.conf` files keep their MTU.
- Pause stops discovery too. Turning discovery off and on again starts a fresh period.

### Performance
- **Download / upload thresholds and check count:** a server below either threshold for *N* consecutive speedtests is auto-disabled. Disabled servers are listed with a **Re-enable** button.
- **Speedtest server blacklist:** Ookla servers that report themselves unavailable are skipped for a few days. Timeouts and tunnel problems don't count against them.

### Scoring
- **Deviation weighting:** how much download vs upload counts when comparing VPN speed against your baseline (no-VPN) speed.
- **Signal thresholds:** score boundaries for the 3/2/1-bar signal indicator.

### Gluetun / WireGuard
See [Gluetun Integration](Gluetun-Integration.md) and [WireGuard Integration](WireGuard-Integration.md).

### Regions, cities, servers
- Choose countries, cities and individual servers. **Deselect all** means "scan everything" (a quick reset).
- **Excluded countries** are never scanned, even when everything is selected.
- Servers are only scanned if they have a `.conf` in `conf/`.
- Base-file only: `regions.us_near_europe_only: true` limits US servers to cities close to Europe (off by default).

## Server states
- **Clean:** every exit IP was checked against DroneBL and verified unlisted.
- **Blocked:** at least one exit IP is listed. The server details show the reason, code and a DroneBL lookup link.
- **Unverified:** a lookup failed or no exit IPs were found. Unverified servers are never exported as clean or used for Gluetun switching.
