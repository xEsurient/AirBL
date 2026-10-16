"""Browser check that untrusted text is rendered as text, never as HTML/JS.

Not collected by pytest (needs a running app + Playwright). Usage:
    /tmp/pw/bin/python tests/browser/check_xss.py http://127.0.0.1:5665

WARNING: it saves hostile-looking Gluetun/WireGuard profile names through the
settings API. Run it against a throwaway instance (copy of the data dir), not
production.

Every payload tries to set window.__xss; the check fails if any page ends up
with window.__xss set, if a payload is not shown literally, or if a form field
doesn't round-trip the exact value.
"""
import json
import sys
import urllib.request

from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5665"
# Breaks out of text, double- and single-quoted attributes and inline JS strings
P = """x"'><img src=x onerror="window.__xss=1">'};window.__xss=1;//"""
results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def api(path, body=None):
    req = urllib.request.Request(BASE + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"}, method="POST" if body is not None else "GET")
    return json.load(urllib.request.urlopen(req))


# Hostile profile names/paths saved through the real API
cur = api("/api/settings")
gp = cur["gluetun_profiles"]
gp[0].update(name="G" + P, output_path="/app/gluetun/" + P + ".json", allowed_cities=[P])
wg = cur.get("wg_profiles") or [{}]
wg[0].update(name="W" + P, output_dir="/app/wireguard/" + P, enabled=False)
saved = api("/api/settings", {"gluetun_profiles": gp, "wg_profiles": wg})
# Warnings mean "invalid, previous profiles kept": then nothing hostile was stored to test
check("hostile profiles accepted by the API", saved.get("status") and not saved.get("warnings"), str(saved)[:120])

HOSTILE_SERVER = {
    "server_name": "S" + P, "country_code": "CH", "country_name": "C" + P, "location": "L" + P,
    "load_percent": 10, "users": 1, "score": 50, "is_clean": False, "is_blocked": True, "reputation": "blocked",
    "reputation_note": "N" + P, "total_ips_scanned": 1, "responsive_count": 1,
    "entry1_ping": None, "entry3_ping": None, "exit_ping": None,
    "speedtest": {"error": "E" + P},
    "exit_ips": [{"ip": "I" + P, "is_blocked": True, "is_responsive": True, "reputation_verified": True,
                  "latency_ms": 20, "dronebl_reason": "R" + P, "dronebl_code": 8,
                  "dronebl_checked_at": "2026-10-04T00:00:00Z"}],
}
UNKNOWN_SERVER = dict(HOSTILE_SERVER, server_name="U" + P, is_blocked=False, reputation="unknown",
                      exit_ips=[{"ip": "1.2.3.4", "is_blocked": False, "is_responsive": False,
                                 "reputation_verified": False, "dronebl_error": "D" + P}])

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("dialog", lambda d: d.dismiss())

    # Servers page: list + modal with hostile server data
    page.goto(BASE + "/servers"); page.wait_for_timeout(2000)
    page.evaluate("""([s, u]) => {
        allResults = {servers_by_country: {CH: [s, u]}};
        _renderResultsImmediate(allResults);
    }""", [HOSTILE_SERVER, UNKNOWN_SERVER])
    page.wait_for_timeout(300)
    check("servers: hostile names render as text", ("S" + P) in page.locator("#resultsContainer").inner_text())
    page.locator(".server-item").first.click(); page.wait_for_timeout(300)
    modal_text = page.locator("#serverModal").inner_text()
    check("servers: modal opens for a name with quotes", page.locator("#serverModal").is_visible())
    check("servers: modal shows hostile values literally",
          all(v in modal_text for v in ("C" + P, "L" + P, "E" + P, "I" + P)))
    check("servers: DroneBL reason kept literal in tooltip",
          page.locator("#modalIPs span.blocked").first.get_attribute("title") == "R" + P)
    page.keyboard.press("Escape")
    page.evaluate("([u]) => showServerDetails(u.server_name)", [UNKNOWN_SERVER]); page.wait_for_timeout(300)
    check("servers: unverified reason shown literally", ("N" + P) in page.locator("#modalServerInfo").inner_text())
    check("servers: window.__xss never set", page.evaluate("window.__xss") is None)

    # Settings page: hostile profile fields round-trip exactly, discovery modal key
    page.goto(BASE + "/settings"); page.wait_for_timeout(2500)
    check("settings: Gluetun name round-trips", page.locator("#gp_name_0").input_value() == "G" + P)
    # Compare with what the API stored (Path() normalises "//" in the payload)
    stored_path = api("/api/settings")["gluetun_profiles"][0]["output_path"]
    check("settings: Gluetun path round-trips", page.locator("#gp_path_0").input_value() == stored_path and P[:20] in stored_path)
    check("settings: Gluetun city label literal", P in page.locator("#gp_cities_label_0").inner_text())
    wg_name = page.locator("input[onchange^='currentWgProfiles[0].name']")
    check("settings: WireGuard name round-trips", wg_name.count() == 1 and wg_name.input_value() == "W" + P)
    page.evaluate("""(k) => { window.currentDiscoveryResults = {[k]: {download_mbps: 1, upload_mbps: 1, ping_ms: 1,
                      history: [{tested_at: '2026-10-04T00:00:00Z', server: k, error: k}]}}; showDiscoveryDetails(k); }""",
                  "1637_E3" + P)
    page.wait_for_timeout(300)
    check("settings: discovery modal shows key/error literally", P in page.locator("body").inner_text())
    check("settings: window.__xss never set", page.evaluate("window.__xss") is None)

    # Disabled-server list with a hostile name (inline onclick moved to data-*)
    page.evaluate("""(n) => renderDisabledServerList(document.getElementById('disabledServersList'), {
                      threshold_download: n, threshold_upload: 1, check_count: n,
                      servers: [{name: 'D' + n, country_code: n, country_name: n, city: n,
                                 recent: [{download: 1, upload: 1, timestamp: n}]}]})""", P)
    page.wait_for_timeout(200)
    btn = page.locator("#disabledServersList button[data-server]")
    check("settings: disabled server name literal + data attribute",
          btn.count() == 1 and btn.get_attribute("data-server") == "D" + P
          and ("D" + P) in page.locator("#disabledServersList").inner_text())
    check("settings: window.__xss still unset", page.evaluate("window.__xss") is None)

    check("no page errors", not errors, "; ".join(errors)[:200])
    browser.close()

# Restore the profile names so the instance stays usable
api("/api/settings", {"gluetun_profiles": cur["gluetun_profiles"] and [dict(g, name=g["name"].split("x\"")[0] if g["name"].startswith("G") else g["name"]) for g in cur["gluetun_profiles"]]})

ok = sum(1 for _, k, _ in results if k)
for name, k, detail in results:
    print(("PASS " if k else "FAIL ") + name + (f"  [{detail}]" if detail and not k else ""))
print(f"\n{ok}/{len(results)} checks passed")
sys.exit(0 if ok == len(results) else 1)
