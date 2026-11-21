# AirBL companion (seedbox on macOS)

A small daemon that puts a Mac's WireGuard tunnel under AirBL's control, so a native
seedbox app (qBittorrent) always runs on one of the fastest AirVPN servers. That includes
DroneBL-listed servers, which usually don't matter for torrents.

AirBL controls it like a Gluetun container. The companion speaks the same control API
(`/v1/vpn/status`, `/v1/publicip/ip`, `PUT /v1/vpn/settings`), so in AirBL it is simply the
**Second Control Target** (Settings → Gluetun). Your main Gluetun stays as it is: clean servers
only.

```
AirBL (Pi) ── scan + speedtests (clean + top N blocked) ── ranking by speed
     │  PUT /v1/vpn/settings  ["Fastest", "2nd", "3rd"]
     ▼
companion (Mac, root) ── wg set endpoint … / wg-quick ── utun (AirVPN) ── qBittorrent bound to the tunnel IP
```

## How it works

- **Switching keeps the tunnel up.** Every AirVPN server uses the same WireGuard public key,
  and your device key and tunnel address are the same on every server. A switch therefore only
  changes the peer's endpoint. The interface, its IP, the routes and the DNS stay up, so
  qBittorrent's listening socket survives. The handshake with the new server takes about a second.
  A full `wg-quick` restart is used only if that fails.
- **Name order is a preference.** AirBL sends names fastest first. The companion connects to the
  first one that works. A server that doesn't answer is skipped for 30 minutes and the next one is
  tried. If none work, it goes back to the last good server.
- **It stays where it is when it can.** If the current server is in AirBL's list, the companion
  doesn't move. AirBL's Top N mode and minimum dwell, plus the companion's own 10 minutes between
  switches, stop it from dropping all your peers every scan.
- **Health watchdog (every 15 s).**
  - A handshake older than 3 minutes counts as a dead tunnel. The companion first tries to switch
    in place, to the same server and then the next ones from AirBL's list, and only restarts the
    tunnel if none of them answers. A dead first choice never tears down a working tunnel.
  - After a wake from sleep or a Wi-Fi/Ethernet change, it re-routes the endpoint through the new
    gateway and gives the tunnel 45 s to reconnect by itself before doing anything else.
  - With no network at all (no default gateway) it waits. No server is blamed for that.
  - If no server connects, it retries after 30 s, 60 s, … up to 10 minutes, instead of
    hammering the tunnel.
  - If the tunnel was taken down by something else, it is brought back.
- **qBittorrent.**
  - **After every switch it reannounces the torrents that benefit, in small batches.**
    - Order: downloads first, then seeds with leechers waiting (most first). Idle seeds and
      stopped, queued or broken torrents are skipped; they pick up the new IP at their next
      normal announce.
    - Default pace: 8 torrents every 20 s, at most 2 per tracker per batch, and at most 200
      torrents per switch. That is about 9 minutes for 200 torrents.
    - Why pace it: qBittorrent's forced reannounce ignores a tracker's minimum announce interval.
      Hundreds at once looks like announce spam to a private tracker.
  - **10 minutes after a switch it checks that incoming connections arrive.** If qBittorrent was
    reachable before the switch and isn't now, it first makes qBittorrent listen again (moves the
    listen port away and back). If that doesn't help, it restarts the app, once per switch. A
    restarted qBittorrent announces everything itself, so no extra wave follows.
  - **Optionally it stops running torrents while the tunnel is down.** Afterwards it resumes only
    those, paced the same way. Torrents you stopped yourself stay stopped.
- **Restarts and reboots.**
  - If the companion restarts or crashes, it adopts the running tunnel instead of reconnecting.
  - After a reboot it reconnects to the last server it was on, which it remembers in
    `/var/db/airbl-companion/state.json`.

## Requirements

- macOS with [Homebrew](https://brew.sh): `brew install wireguard-tools bash`. That gives `wg`,
  `wg-quick`, `wireguard-go`, and the bash 4 that `wg-quick` needs.
  - The installer copies them into the root-owned `/opt/airbl-companion/bin`. Homebrew's folders
    belong to your user account, and a root daemon must not run anything a normal program could
    replace.
  - Homebrew's bash also loads libraries from Homebrew (readline, ncurses, gettext). The installer
    copies those into `/opt/airbl-companion/lib/dylib`, points bash at the copies and re-signs it
    (ad hoc), so nothing the daemon loads belongs to your account either.
  - After `brew upgrade wireguard-tools`, run the installer again to refresh the copies.
- Apple's `python3` from the Xcode command line tools (`xcode-select --install`). No packages are
  needed.
- AirBL with a **Second Control Target**, and ideally **Seedbox: Listed Servers to Test** set (for
  example 10). Both are in Settings.
- **A separate AirVPN device for this Mac.** In the AirVPN Client Area, add a device (e.g.
  "seedbox-mac"), then use the Config Generator: WireGuard, that device, any server. Copy
  `PrivateKey`, `PresharedKey` and `Address` from the generated file.
  - Don't reuse the key of AirBL's scan tunnel or your main Gluetun. The same key on two servers
    at once makes the connections fight.
  - Each connection counts towards your AirVPN connection limit.
- **A forwarded port** (Client Area → Ports), for incoming peers. It works on every server, so it
  never changes when the companion switches.

## Install

```bash
cd companion
sudo ./install.sh
sudo nano /opt/airbl-companion/etc/config.json   # see below
sudo airbl-companion check
# Disconnect the WireGuard app's tunnel (the two would fight over routes and DNS), then:
sudo launchctl bootstrap system /Library/LaunchDaemons/org.airbl.companion.plist
```

- **Update:** run `sudo ./install.sh` again. It keeps your config and restarts the daemon; the
  tunnel stays up. Version 1.0's config in `/usr/local/etc/airbl-companion` is moved over.
- **Uninstall:** `sudo ./install.sh uninstall`.
- **Log:** `/var/log/airbl-companion.log`.
- **macOS firewall:** if the Application Firewall is on, allow incoming connections for
  `/usr/bin/python3`, or AirBL can't reach the API.
- **Network layout:** AirBL must be on the same subnet as the Mac. With the full tunnel up, the
  Mac's replies to any other network, such as another VLAN, go into the VPN and never arrive.
- **Sleep:** for a seedbox, turn off automatic sleep (System Settings → Energy).

## Configuration (`/opt/airbl-companion/etc/config.json`, root only, mode 600)

| Key | Meaning |
|---|---|
| `api.listen`, `api.port` | Where the control API listens (default `0.0.0.0:8000`). If another program already uses the port, the companion can't start (log: "Can't listen on …"): pick a free one, e.g. 8765, and use the same in AirBL |
| `api.api_key` | Generated by the installer. Enter the same key in AirBL (`X-API-Key`) |
| `api.allow_from` | Addresses or networks allowed to use the API, e.g. `["192.168.1.10"]` (your AirBL host) or `["192.168.1.0/24"]`. Empty = any. Loopback is always allowed. Other sources are dropped before anything is read |
| `wireguard.private_key`, `preshared_key`, `address` | From the AirVPN config generator (this Mac's device) |
| `wireguard.dns` | AirVPN DNS (`wg-quick` sets it on all network services and restores it on exit). IPv6 servers are skipped automatically when `address` has no IPv6 |
| `wireguard.port`, `entry` | AirVPN WireGuard port (1637, 47107, 51820…) and entry IP (`ENTRY1`/`ENTRY3`) |
| `wireguard.mtu`, `keepalive`, `allowed_ips` | Usually leave as is (full tunnel). **IPv4 only:** drop the IPv6 part of `address`, but keep `::/0` in `allowed_ips`. IPv6 then goes into the tunnel and nowhere, instead of bypassing the VPN; `check` warns if it would leak |
| `initial_servers` | Servers for the very first start, before AirBL has sent any |
| `health.*` | Check interval (15 s), dead-tunnel age (180 s), switch timeout (20 s), minimum time between switches (600 s), cooldown for a failed server (1800 s), reconnect grace after wake/network change (45 s), longest retry backoff (600 s) |
| `qbittorrent.enabled`, `url` | qBittorrent's Web UI (Preferences → Web UI) |
| `qbittorrent.username`, `password` | Web UI login. Leave empty if "Bypass authentication for clients on localhost" is on |
| `qbittorrent.forwarded_port` | Your AirVPN forwarded port. The companion warns if qBittorrent listens on another |
| `qbittorrent.enforce_bind` | Set qBittorrent's bind address to the tunnel IP automatically |
| `qbittorrent.pause_when_down` | Stop running torrents when a working tunnel goes down, resume them after (50 per batch; `sudo airbl-companion resume` restarts them all at once). Never at startup: qBittorrent is bound to the tunnel IP, so nothing leaks before the tunnel is up |
| `qbittorrent.restart_if_unreachable` | Restart qBittorrent if it can't be reached from outside after a switch |
| `qbittorrent.user`, `app_path` | Who runs qBittorrent (default: the logged-in user) and where the app is |
| `qbittorrent.restart_command` | Your own restart command instead (e.g. on Linux) |
| `qbittorrent.reannounce.batch_size`, `interval` | Torrents per batch (8) and seconds between batches (20) |
| `qbittorrent.reannounce.per_tracker` | At most this many from one tracker host per batch (2) |
| `qbittorrent.reannounce.max_torrents` | Reannounce at most this many per switch, most useful first (200; 0 = all) |
| `qbittorrent.reannounce.skip_idle_seeds` | Skip seeding torrents nobody is leeching (true) |
| `qbittorrent.reannounce.skip_if_qbit_does_it` | After a tunnel restart, skip the wave if qBittorrent's own "reannounce when IP or port changed" is on (true) |

## qBittorrent settings

1. **Tools → Preferences → Web UI:** enable it on `127.0.0.1:8080`. Either set a username and
   password (and put them in the config) or tick *Bypass authentication for clients on localhost*.
2. **Advanced → Optional IP address to bind to:** set it to your AirVPN tunnel IP (the IPv4 part
   of `address`, shown by `check`). This is the kill switch: when the tunnel is down, qBittorrent
   can't send anything. Bind to the IP, not to a `utunN` network interface, because the utun
   number can change.
3. **Connection → Port used for incoming connections:** your AirVPN forwarded port. Turn off
   UPnP/NAT-PMP.
4. **Advanced → Reannounce to all trackers when IP or port changed:** turn it **off**. When it's
   on, qBittorrent reannounces every torrent at once when its address changes, alongside the
   companion's paced wave. The companion warns about it but never changes it itself.

`sudo airbl-companion check` verifies all four.

## AirBL settings

- **Settings → Speedtest → Seedbox: Listed Servers to Test:** for example 10. Each one adds 3–5 minutes
  to a scan.
- **Settings → Gluetun → Second Control Target:**
  - enabled;
  - host = the Mac's LAN IP, port 8000, and the API key from the config;
  - *Allow Blocked Servers* on, *Rank By* Speed, *Reset if not Top N* with N = 3, minimum dwell
    30 minutes. The host must not be your main Gluetun's address; AirBL refuses that.
- *Test* shows the companion's VPN state and public IP. *Apply Now* checks it right away and
  ignores the dwell.
- The dashboard's **Fastest (any reputation)** table shows the ranking AirBL uses.

## Commands

```bash
sudo airbl-companion status            # server, handshake, qBittorrent
sudo airbl-companion switch Achernar,Mirzam   # switch now (first that works)
sudo airbl-companion down              # take the tunnel down and keep it down
sudo airbl-companion up
sudo airbl-companion check             # config, tools, AirVPN list, qBittorrent settings
sudo airbl-companion resume            # restart all torrents the companion stopped (pause_when_down)
sudo airbl-companion render Achernar   # the WireGuard config it would use (keys hidden)
```

## Security notes

- The API is plain HTTP on your LAN, protected by the API key and `allow_from`.
  - Anyone who can sniff your LAN could replay the key, and for example take the tunnel down,
    which puts the Mac's traffic outside the VPN.
  - Keep `allow_from` set to your AirBL host, and use a trusted network.
- The config holds your WireGuard key. It is readable only by root, like the log
  (`/var/log/airbl-companion.log`) and the state in `/var/db/airbl-companion`.

## Limitations

- **Full tunnel:** the whole Mac uses the VPN, as with the WireGuard app. Per-app split
  tunnelling isn't possible this way on macOS.
- **AirBL's speedtests run on the AirBL host,** not on the Mac. On the same internet connection
  the ranking carries over well.
- **Switching drops peer connections:** each switch drops every connected peer, and they
  reconnect within minutes. That's why switches are rate-limited.
- **Trackers that reject listed IPs:** some private trackers refuse DroneBL-listed IPs. If yours
  does, turn off *Allow Blocked Servers* for the second target.
- **Linux:** the companion runs there too. Use `systemd` instead of launchd and set
  `qbittorrent.restart_command`.
