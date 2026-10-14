# Gluetun Integration

[Gluetun](https://github.com/qdm12/gluetun) is famously strict. It does not possess banlists or rotation logic for blocked IPs. If you assign Gluetun to AirVPN, it connects blindly.

AirBL helps in two ways:
1. **servers.json profiles**: write a filtered AirVPN server list Gluetun loads **at startup**.
2. **Control server API**: point a running Gluetun (local or remote) at clean servers **without restarting the container**.

Gluetun only reads its server list when the container starts. Cycling the VPN does not reload it, so on a running Gluetun only option 2 changes anything.

## Creating a Profile

Inside the Settings UI > **Gluetun Integration**:
1. Click **Add Profile**.
2. **Output Path**: where to write the file. It must be the file Gluetun actually reads (see below).
3. **Endpoint Route Strategy**:
   - `ALL`: Exports both Entry 1 and Entry 3.
   - `ENTRY1`/`ENTRY3`: Forces strict routes.
   - `PING_PRIORITY`: Exports only the lowest-latency alive entry IP.
4. Set allowed countries/cities and bandwidth limits.

If a profile matches no servers, the previous file is kept. An empty file would leave Gluetun with no AirVPN servers.

### Which file Gluetun reads

Share Gluetun's `/gluetun` directory with AirBL's `/app/gluetun`, e.g. `./gluetun:/gluetun` in the Gluetun service and `./gluetun:/app/gluetun` in AirBL. Mount the directory, not a single file, because AirBL replaces the file atomically.

| Gluetun version | Output Path |
| --- | --- |
| Current (uses `/gluetun/servers/` + `manifest.json`) | `/app/gluetun/servers/airvpn.json` |
| Older (single `/gluetun/servers.json`) | `/app/gluetun/servers.json` |

Default profiles: two clean-only, 120/120 Mbps profiles, one for each row above. Enable the one matching your Gluetun. Each profile card shows whether Gluetun reads its path.

A file named `airvpn.json` is written in Gluetun's per-provider format. Any other name gets the legacy `servers.json` format. Current Gluetun migrates a legacy `servers.json` into `servers/` once, then ignores it. After that, write to `servers/airvpn.json`.

The file is marked `"preferred": true`, so Gluetun uses it even when its built-in list is newer. Look for `Using airvpn servers from file` in the Gluetun log.

For a **remote** Gluetun, the file only matters if you sync it to that host yourself. Use the control API instead.

## Controlling Gluetun (local or remote)

Settings > Gluetun Integration:
- **Control Server Host / Port**: Gluetun's control server (default port 8000). For a remote host, publish 8000 only on a trusted network.
- **API Key**: sent as `X-API-Key`. Gluetun v3.40+ requires auth. The key is stored in AirBL's settings file and is never sent back to the browser. Example Gluetun setup:
  ```
  HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE={"auth":"apikey","apikey":"<your key>"}
  ```
  Or use a role in Gluetun's auth `config.toml` that includes `GET /v1/vpn/status`, `GET /v1/publicip/ip` and `PUT /v1/vpn/settings`.
- **Control Profile**: the profile whose clean servers are offered to Gluetun. Leave it empty to use the first enabled profile.
- **Test**: checks reachability and the key, and shows the current public IP and the matching server.
- **Apply Now**: runs the switch logic immediately.

When enabled, after every scan AirBL sends `PUT /v1/vpn/settings` with `{"provider":{"server_selection":{"names":[...], "countries":[], "regions":[], "cities":[], "hostnames":[]}}}`. The empty lists clear any `SERVER_COUNTRIES`/`SERVER_CITIES` set on Gluetun, so only the pushed names decide. Gluetun validates the names, then reconnects to one of them. Blocklisted servers are never sent, even if the profile allows them.

**Switch Mode** (the current server is found by Gluetun's public/exit IP):
- **Clean Only:** stay while the current server is clean. Otherwise limit Gluetun to all clean servers in the profile.
- **Reset if not Top 4:** stay if the current server is in the profile's top 4 by score. Otherwise limit Gluetun to those 4.
- **Reset if not Best:** same, with only the top server.
- **Always:** push the full clean list after every scan, which causes a reconnect.
- **Disabled:** never touch Gluetun.

If Gluetun can't be reached or rejects the key, AirBL logs the reason and leaves the selection unchanged.
