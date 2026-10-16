# Troubleshooting

### "No per-server AirVPN WireGuard configs found"
AirBL takes the server from a config's file name (`AirVPN_AT-Vienna_Alderamin_UDP-1637-Entry3.conf`). With only region configs such as `AirVPN_Europe_UDP-1637-Entry3.conf`, it builds a config for every server from the region config's keys and AirVPN's server list. The error means that wasn't possible: the config has no `PrivateKey`/`Address`, or the server list couldn't be loaded (check the container's internet access). Detailed logs are in the dashboard under **Debug** (`/debug`); `docker logs` shows only startup messages and warnings.

### Dashboard unreachable during speedtests
AirBL keeps dashboard replies out of the VPN with a routing rule for the dashboard port, and replies to private (LAN/Docker) addresses always bypass the tunnel.
- Use the default bridge network, not `network_mode: host`.
- Keep `PORT` consistent: it's used by the server, the healthcheck, the routing rule and the kill switch.
- If your LAN uses addresses inside 10.128.0.0/10 (AirVPN's internal range), the dashboard can be unreachable during tests. Use a different LAN range.

### Gluetun control: "Gluetun rejected the API key (401)"
Gluetun v3.40+ requires an API key. Set the same key in AirBL (Settings → Gluetun → API Key) and in Gluetun, e.g. `HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={"auth":"apikey","apikey":"<key>"}`. Use **Test** to check reachability and the key.

A 403 means the key's role lacks a route: it needs `GET /v1/vpn/status`, `GET /v1/publicip/ip` and `PUT /v1/vpn/settings`. A 400 naming a server means Gluetun doesn't know that server name (its own server list is older).

### Gluetun ignores the updated server list
Gluetun only reads its server file at startup. Current Gluetun versions read `/gluetun/servers/airvpn.json` and import a legacy `servers.json` only once (log: "reading legacy servers file … migrating"). Point your profile at the file your Gluetun version reads (see [Gluetun Integration](Gluetun-Integration.md)), or use the control API to switch servers without a restart.

### Servers marked "Unverified"
The DroneBL lookup failed (DNS timeout, unexpected answer) or AirVPN DNS returned no exit IPs. The reason is shown in the server details. Check `DNS_SERVERS` and network access; the next scan retries.

If **every** server is unverified with a note about "DroneBL's test entry 127.0.0.2", your DNS resolver doesn't really answer for `dronebl.org`. Filtering resolvers (Pi-hole, NextDNS, some router DNS) often block it, and then every IP would look clean. AirBL checks the test entry DroneBL always lists and refuses to call anything clean when it's missing. Set `DNS_SERVERS` to a plain resolver, e.g. `1.1.1.1,8.8.8.8`.

### Speedtests fail
- **"No WireGuard handshake":** the config's key/endpoint is wrong, or UDP to that port is blocked.
- **"Traffic is not leaving via AirVPN" / "Measured outside the VPN":** a leak was detected and the result discarded, by design.
- **Ookla errors:** the log (Debug page) shows Ookla's own message. Unavailable Ookla servers are skipped automatically.

### Next-scan countdown or schedule looks wrong
Schedules run in the container's time zone. Set `TZ` (e.g. in `docker/.env`) and recreate the container.

### Old dashboard after an update
Not expected any more: assets are versioned and revalidated. If it happens, check for a caching proxy in front of AirBL.

### AUTO entry always picks Entry 3
AUTO needs ping history in the database. Until a few scans have run, or if Entry 1 doesn't respond, Entry 3 is the fallback.
