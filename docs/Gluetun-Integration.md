# Gluetun Integration

[Gluetun](https://github.com/qdm12/gluetun) is famously strict. It does not possess banlists or rotation logic for blocked IPs. If you assign Gluetun to AirVPN, it connects blindly.

AirBL helps in two ways:
1. **servers.json profiles**: write a filtered AirVPN server list Gluetun loads **at startup**.
2. **Control server API**: point a running Gluetun (local or remote) at clean servers **without restarting the container**.

Gluetun only reads its server list when the container starts. Cycling the VPN does not reload it, so on a running Gluetun only option 2 changes anything.

## Creating a Profile

Inside the Settings UI > **Gluetun Integration**:
1. Click **Add Profile**.
2. **Output Path**: where to write the file. It must be the file Gluetun actually reads (see below), and it must be inside `/app/gluetun/` (the mounted folder); other paths are refused.
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
- **Control Profile**: the profile whose clean servers are offered to Gluetun. Leave it empty to use the first enabled profile. Profiles are optional: with none enabled, AirBL offers every clean scanned server that isn't disabled.
- **Test**: checks reachability and the key, and shows the current public IP and the matching server.
- **Apply Now**: runs the switch logic immediately (skips the cooldown below).
- **Watchdog interval**: how often AirBL checks between scans that Gluetun is still on a server the switch mode allows (default 60 s; 0 = only after scans). Gluetun can reconnect by itself (restart, network drop) and pick any server; the watchdog moves it back. It skips while a scan runs, while Gluetun isn't connected yet, and for 3 minutes after any switch so Gluetun can reconnect.

When enabled, after every scan (and whenever the watchdog finds Gluetun outside the allowed servers) AirBL sends `PUT /v1/vpn/settings` with `{"provider":{"server_selection":{"names":[...], "countries":[], "regions":[], "cities":[], "hostnames":[]}}}`. The empty lists clear any `SERVER_COUNTRIES`/`SERVER_CITIES` set on Gluetun, so only the pushed names decide. Gluetun validates the names, then reconnects to one of them. Blocklisted servers are never sent, even if the profile allows them.

**Switch Mode** (the current server is found by Gluetun's public/exit IP):
- **Clean Only:** stay while the current server is clean. Otherwise limit Gluetun to all clean servers in the profile.
- **Reset if not Top 4:** stay if the current server is in the profile's top 4 by score. Otherwise limit Gluetun to those 4.
- **Reset if not Best:** same, with only the top server.
- **Always:** push the full clean list after every scan, which causes a reconnect. Between scans the watchdog only switches if Gluetun is outside that list.
- **Disabled:** never touch Gluetun.

If Gluetun can't be reached or rejects the key, AirBL logs the reason and leaves the selection unchanged.

**When Gluetun doesn't report its public IP.** AirBL normally recognises Gluetun's server by its public IP (`/v1/publicip/ip`). If Gluetun leaves that empty (its public IP lookup is off, or the lookup service rate-limits it), AirBL judges Gluetun's server list instead (`/v1/vpn/settings`):
- Gluetun only connects to servers in its list. With "Clean Only", AirBL leaves it alone while every listed server is clean, and pushes a fresh list (all clean servers, so Gluetun keeps its own fallback) when one becomes listed. "Top N" and "Best" stay while the whole list is within the allowed servers.
- The header shows the first server and a count (e.g. "Mirzam +1"); hover for the full list. If the list holds a single server, that server is shown.
- About 45 s after every switch, AirBL checks once where Gluetun ended up and logs it. Gluetun looks up its public IP again after each reconnect, so a switch may bring the IP back.
- The real fix is on the Gluetun side: check its logs for "public ip" and its `PUBLICIP_*` settings.

## Second control target (seedbox)

A second Gluetun, or the [AirBL companion](../companion/README.md) on a Mac or Linux seedbox, can be controlled separately from the main one (Settings > Gluetun Integration > **Second Control Target**). It uses the same API (`/v1/vpn/status`, `/v1/publicip/ip`, `PUT /v1/vpn/settings`, `X-API-Key`), with its own host, port, key, watchdog interval and cooldown.

What's different from the main target:
- **Allow Blocked Servers:** DroneBL-listed servers may be chosen. For torrents a listing rarely matters, but speed does. This needs **Seedbox: Listed Servers to Test** (Settings > Speedtest), or blocked servers have no speed result.
- **Rank By Speed:** servers are ranked by their speedtest result only (percentage of your no-VPN baseline, not capped at 100), with upload as the tie-breaker. Untested servers, and servers whose last speedtest failed, are never chosen.
  - When the candidates mix baseline-relative results with results that have no baseline (tested before a baseline existed, or restored from an older database), they are ranked by measured upload, then download, instead.
  - **Score** uses AirBL's normal score instead, and is only allowed with blocked servers off, since every listed server scores 0.
- **Names in rank order:** the list is sent fastest first. Gluetun ignores the order; the companion connects to the first server that works.
- **Switch Mode:** *Reset if not Top N* (N = 1-20) stays while the current server is among the N fastest. *Reset if not Best* wants the fastest. *Stay while allowed* moves only when the current server is no longer allowed (disabled, filtered out, failed, or listed with blocked servers off).
- **Minimum Dwell:** after a successful switch, AirBL doesn't move the target to a faster server for this many minutes while the current one is still allowed (default 30), in every mode. Every switch drops all torrent peers.
  - A server that is no longer allowed is left at once.
  - A rejected push doesn't start the dwell.
  - After an AirBL restart, the dwell continues from the companion's own last switch time.
  - **Apply Now** ignores the dwell.
- **Profile Filter (optional):** use an enabled profile's speed thresholds and countries/cities. With none, every scanned server that isn't disabled (on the main or the seedbox list) is a candidate.
  - A profile's "clean only" option is ignored while blocked servers are allowed.
  - If the chosen profile is disabled, renamed outside Settings, or deleted, the target is not changed and the reason is shown. It doesn't silently fall back to "no filter".
- **Address:** it must differ from the main Gluetun's control server while main control is on. AirBL refuses to save that, so listed servers can never reach the main Gluetun. Changing the address removes the saved key; enter it again.
- **Re-tests:** the server the second target is on is always speedtested again while it's listed, even if its ping drops it out of the blocked queue. A listed server that wasn't re-tested keeps its previous result for one scan, marked "previous scan".
- Each target has its own watchdog, so an unreachable second target never delays the main one. Saving the second target's settings only updates the second target.

**Note on profiles that allow listed servers:** a profile with "clean only" off and speed thresholds now also lists tested DroneBL-listed servers in the file it writes, because those now have speed results. Gluetun reads that file at startup and may connect to any server in it. The main control still only ever pushes clean servers. The default profiles are clean-only.

The dashboard's **Fastest (any reputation)** table (also `GET /api/ranking/speed`) shows the ranking the second target uses. It appears once a blocked server has been speedtested.
