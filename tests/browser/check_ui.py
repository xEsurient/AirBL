"""Headless browser smoke test for the AirBL dashboard.

Not collected by pytest (needs a running app + Playwright). Usage:
    python -m venv /tmp/pw && /tmp/pw/bin/pip install playwright && /tmp/pw/bin/python -m playwright install --with-deps chromium
    # start AirBL with some scan results (e.g. after one scan), then:
    /tmp/pw/bin/python tests/browser/check_ui.py http://127.0.0.1:5665
Fails on any JS page error, console error or HTTP >= 400, and on broken page features.
"""
import json
import sys
from playwright.sync_api import sync_playwright

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:5665"
results = []          # (check, ok, detail)
page_errors = {}      # page -> [errors]


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def watch(page, label):
    errs = page_errors.setdefault(label, [])
    page.on("pageerror", lambda e: errs.append(f"pageerror: {e}"))
    page.on("console", lambda m: errs.append(f"console.{m.type}: {m.text}") if m.type == "error" else None)
    page.on("response", lambda r: errs.append(f"HTTP {r.status} {r.url}") if r.status >= 400 else None)


def sim_events(page):
    """Feed the websocket handler the events a scan cycle produces."""
    page.evaluate("""() => {
        const now = new Date(Date.now() + 3600e3).toISOString();
        const ev = (type, data) => handleMessage({type, data});
        ev('scan_started', {next_scan_at: now});
        ev('progress_update', {progress: {phase: 'scanning', current: 1, total: 3, server: 'Toliman', country: 'CH', next: ''}});
        ev('network_job_waiting', {job: 'speedtest Hamal', owner: 'scan'});
        ev('discovery_combo_complete', {combo: '1637_E3', results: {}});
        ev('discovery_finalized', {outcome: '47107/ENTRY3'});
        ev('server_disabled', {server: 'Hamal', reason: 'below threshold'});
        ev('settings_changed', {});
        ev('progress_update', {progress: {phase: 'idle', current: 0, total: 0, server: '', country: '', next: ''}, next_scan_at: now});
        ev('speedtest_manual_done', {server: 'Toliman', ok: true, download_mbps: 100, upload_mbps: 20, ping_ms: 30});
        ev('speedtest_manual_done', {server: 'Hamal', ok: false, error: 'All 3 speedtest run(s) failed'});
        ev('scan_error', {error: 'simulated failure'});
        ev('scan_cancelled', {});
    }""")
    page.wait_for_timeout(1500)


with sync_playwright() as p:
    browser = p.chromium.launch()
    ctx = browser.new_context(viewport={"width": 1400, "height": 1000})
    ctx.on("dialog", lambda d: (page_errors.setdefault("dialogs", []).append(d.message), d.dismiss()))

    # --- Overview -----------------------------------------------------------
    page = ctx.new_page(); watch(page, "index")
    page.goto(BASE + "/"); page.wait_for_timeout(3000)
    cards = page.locator("#topServersGrid .summary-card")
    check("index: top servers rendered", cards.count() >= 1, f"{cards.count()} cards")
    if cards.count():
        cards.first.click(); page.wait_for_timeout(300)
        panel = page.locator("#serverDetailPanel")
        check("index: server detail panel opens", panel.is_visible() and "Exit Ping" in panel.inner_text())
    check("index: charts drawn", page.locator("canvas").count() >= 1, f"{page.locator('canvas').count()} canvases")
    sim_events(page)
    check("index: scan controls recover after events (Start shown, Stop hidden)",
          page.locator("#scanBtn").is_visible() and not page.locator("#stopBtn").is_visible())
    page.close()

    # --- Servers ------------------------------------------------------------
    page = ctx.new_page(); watch(page, "servers")
    page.goto(BASE + "/servers"); page.wait_for_timeout(2500)
    page.select_option("#filterStatus", "")  # All
    page.wait_for_timeout(1200)
    items = page.locator(".server-item")
    total = items.count()
    expected = {}
    import urllib.request
    data = json.load(urllib.request.urlopen(BASE + "/api/results"))
    servers = [s for ss in data.get("servers_by_country", {}).values() for s in ss]
    expected = {"unknown": sum(s.get("reputation") == "unknown" for s in servers),
                "blocked": sum(s.get("reputation") == "blocked" for s in servers),
                "clean": sum(bool(s.get("is_clean")) for s in servers)}
    check("servers: list rendered (All)", total == len(servers) and total >= 1, f"{total} items")
    if items.count():
        items.first.click(); page.wait_for_timeout(400)
        modal = page.locator("#serverModal")
        check("servers: modal opens", modal.is_visible())
        ips = page.locator("#modalIPs").inner_text()
        check("servers: modal lists exit IPs", any(ch.isdigit() for ch in ips) and "No IP addresses" not in ips, ips[:60].replace("\n", " "))
        first_blocked = servers and sorted(servers, key=lambda s: -(s.get("score") or 0))[0].get("reputation") == "blocked"
        check("servers: block notes shown only for blocked servers", page.locator("#modalBlockNotesSection").is_visible() == bool(first_blocked))
        page.keyboard.press("Escape"); page.wait_for_timeout(200)
    for value, expect in expected.items():
        page.select_option("#filterStatus", value); page.wait_for_timeout(1000)
        check(f"servers: status filter '{value}'", page.locator(".server-item").count() == expect, f"{page.locator('.server-item').count()} items")
    sim_events(page)
    check("servers: list still populated after cancel refetch", page.locator(".server-item").count() >= 1)
    toasts = page.locator("#appToastBox div").all_inner_texts()
    check("servers: toasts shown for events", len(toasts) >= 3, f"{len(toasts)} toasts")
    page.close()

    # --- Settings -----------------------------------------------------------
    page = ctx.new_page(); watch(page, "settings")
    posts = []
    page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and r.url.endswith("/api/settings") else None)
    page.goto(BASE + "/settings"); page.wait_for_timeout(2500)
    page.click("button.tab-btn:has-text('WIREGUARD')"); page.wait_for_timeout(300)
    wg_cards = page.locator("#wgProfilesContainer .settings-section, [id^=wg_countries_label_]")
    check("settings: WIREGUARD tab shows profiles", wg_cards.count() >= 1 and wg_cards.first.is_visible(), f"{wg_cards.count()} elements")
    page.click("button.tab-btn:has-text('GLUETUN')"); page.wait_for_timeout(300)
    check("settings: GLUETUN tab shows profiles", page.locator("#gluetunProfilesContainer").is_visible()
          and page.locator("[id^=gp_name_]").count() >= 1)
    # rename a profile -> control dropdown follows; add a profile -> rename survives
    name_input = page.locator("#gp_name_0")
    name_input.fill("Renamed POC")
    page.wait_for_timeout(200)
    opts = page.locator("#gluetunControlProfile option").all_inner_texts()
    check("settings: control dropdown follows rename", any("Renamed POC" in o for o in opts), str(opts))
    before = page.locator("[id^=gp_name_]").count()
    page.click("button:has-text('+ Add Profile')"); page.wait_for_timeout(300)
    check("settings: add profile keeps unsaved rename", page.locator("[id^=gp_name_]").count() == before + 1
          and page.locator("#gp_name_0").input_value() == "Renamed POC")
    page.click("button.tab-btn:has-text('DISCOVERY')"); page.wait_for_timeout(300)
    disc = page.locator("#discoveryResults .summary-card")
    settings_data = json.load(urllib.request.urlopen(BASE + "/api/settings"))
    n_combos = len(settings_data.get("port_discovery_results") or {})
    check("settings: discovery result cards", disc.count() == n_combos, f"{disc.count()} cards")
    if disc.count():
        disc.first.click(); page.wait_for_timeout(300)
        check("settings: discovery details modal", page.locator("text=Discovery:").first.is_visible())
        page.locator("text=×").last.click(); page.wait_for_timeout(200)
    # invalid number -> client-side validation blocks the save
    page.click("button.tab-btn:has-text('ALL')"); page.wait_for_timeout(200)
    page.fill("#scanInterval", ""); page.dispatch_event("#scanInterval", "change")
    page.click("button:has-text('Save Changes')"); page.wait_for_timeout(800)
    check("settings: empty number field blocked client-side (no POST)", len(posts) == 0, f"{len(posts)} POSTs")
    sim_events(page)  # app.js handlers on a non-dashboard page must not throw
    page.close()

    # --- Metrics / Debug ----------------------------------------------------
    page = ctx.new_page(); watch(page, "metrics")
    page.goto(BASE + "/metrics"); page.wait_for_timeout(3000)
    check("metrics: charts drawn", page.locator("canvas").count() >= 1, f"{page.locator('canvas').count()} canvases")
    page.close()

    page = ctx.new_page(); watch(page, "debug")
    page.goto(BASE + "/debug"); page.wait_for_timeout(2500)
    body = page.locator("body").inner_text()
    check("debug: log entries rendered", "airbl" in body.lower() or "INFO" in body, "")
    pause = page.locator("button:has-text('Pause')")
    if pause.count():
        pause.first.click(); page.wait_for_timeout(300)
        check("debug: pause toggles (client-side)", page.locator("button:has-text('Resume')").count() >= 1)
    page.close()

    browser.close()

ok = sum(1 for _, k, _ in results if k)
for name, k, detail in results:
    print(("PASS " if k else "FAIL ") + name + (f"  [{detail}]" if detail else ""))
print(f"\n{ok}/{len(results)} checks passed")
for label, errs in page_errors.items():
    if errs:
        print(f"\n{label}: {len(errs)} error(s)")
        for e in errs[:10]:
            print("   ", e[:220])
sys.exit(0 if ok == len(results) and not any(page_errors.values()) else 1)
