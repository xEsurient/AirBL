"""DatabaseManager against a temporary sqlite file."""

from datetime import datetime, timedelta

import aiosqlite
import pytest

from airbl.database import DatabaseManager, row_is_clean, RETENTION_DAYS


@pytest.fixture
async def db(tmp_path):
    d = DatabaseManager(tmp_path / "sub" / "airbl.db")
    await d.init()
    yield d
    await d.close()


def _row(name, reputation, blocked=False):
    return {"server_name": name, "reputation": reputation, "is_blocked": blocked,
            "load_percent": 10, "users": 3, "responsive_count": 1, "score": 50.0,
            "exit_ping": {"ip": "192.0.2.1", "latency_ms": 12.5}}


async def _complete_scan(db, rows, counts=None):
    sid = await db.add_scan_result({"total_servers": 0})
    for r in rows:
        await db.add_server_scan_result(sid, r)
    await db.update_scan_result(sid, counts or {"total_servers": len(rows)}, status="complete")
    return sid


async def test_init_creates_dir_and_status_column(db):
    assert db.db_path.exists()
    async with db._conn.execute("PRAGMA table_info(scan_history)") as cur:
        cols = {r["name"] for r in await cur.fetchall()}
    assert "status" in cols
    async with db._conn.execute("PRAGMA table_info(server_scan_history)") as cur:
        cols = {r["name"] for r in await cur.fetchall()}
    assert "reputation" in cols


async def test_new_scan_is_running_and_hidden(db):
    sid = await db.add_scan_result({"total_servers": 0})
    async with db._conn.execute("SELECT status FROM scan_history WHERE id=?", (sid,)) as cur:
        assert (await cur.fetchone())["status"] == "running"
    assert await db.get_scan_history() == []
    assert await db.get_last_complete_scan() is None
    assert await db.get_last_scan_servers() == []


async def test_only_complete_scans_returned(db):
    first = await _complete_scan(db, [_row("Toliman", "clean"), _row("Ran", "blocked", True)])
    # A newer scan that was cancelled with partial rows must not shadow the complete one
    cancelled = await db.add_scan_result({"total_servers": 0})
    await db.add_server_scan_result(cancelled, _row("Partial", "clean"))
    await db.set_scan_status(cancelled, "cancelled")

    last = await db.get_last_complete_scan()
    assert last["id"] == first
    names = [r["server_name"] for r in await db.get_last_scan_servers()]
    assert names == ["Ran", "Toliman"]
    assert [h["id"] for h in await db.get_scan_history()] == [first]
    stats = await db.get_stats()
    assert stats["total_scans"] == 1


async def test_ban_history_counts_complete_scans_only(db):
    await _complete_scan(db, [_row("Ran", "blocked", True)])
    await _complete_scan(db, [_row("Ran", "blocked", True), _row("Toliman", "clean")])
    failed = await db.add_scan_result({})
    await db.add_server_scan_result(failed, _row("Toliman", "blocked", True))
    await db.set_scan_status(failed, "failed")
    assert await db.get_ban_history() == {"Ran": 2}


async def test_server_row_fields(db):
    sid = await db.add_scan_result({})
    r = _row("Toliman", "unknown")
    r["entry1_ping"] = {"latency_ms": 30.0}
    r["entry3_ping"] = {"latency_ms": 20.0}
    await db.add_server_scan_result(sid, r)
    await db.update_scan_result(sid, {"total_servers": 1})
    (row,) = await db.get_last_scan_servers()
    assert row["reputation"] == "unknown"
    assert row["exit_ip"] == "192.0.2.1"
    assert row["exit_ping_ms"] == 12.5
    assert row["config_ping_ms"] == 20.0
    assert row["is_blocked"] == 0


async def test_entry_pings_and_best_entry(db):
    sid = await _complete_scan(db, [_row("Toliman", "clean")])
    await db.add_entry_ping(sid, "Toliman", "ENTRY1", "10.0.0.1", 40.0, True)
    await db.add_entry_ping(sid, "Toliman", "ENTRY3", "10.0.0.3", 20.0, True)
    pings = await db.get_last_scan_entry_pings()
    assert {p["entry_type"] for p in pings} == {"ENTRY1", "ENTRY3"}
    assert await db.get_best_entry_for_server("Toliman") == "ENTRY3"
    assert await db.get_best_entry_for_server("Nobody") == "ENTRY3"
    assert await db.get_best_entries_bulk(["Toliman", "Nobody"]) == {"Toliman": "ENTRY3", "Nobody": "ENTRY3"}


def test_row_is_clean_reputation_and_legacy():
    assert row_is_clean({"reputation": "clean", "is_blocked": 0})
    assert not row_is_clean({"reputation": "unknown", "is_blocked": 0})
    assert not row_is_clean({"reputation": "blocked", "is_blocked": 1})
    # Legacy rows (no reputation column value) fall back to is_blocked
    assert row_is_clean({"reputation": None, "is_blocked": 0})
    assert not row_is_clean({"is_blocked": 1})


async def test_prune_removes_old_rows(db):
    old = (datetime.now() - timedelta(days=RETENTION_DAYS + 5)).isoformat()
    await db._conn.execute(
        "INSERT INTO scan_history (timestamp, total_servers, status) VALUES (?, 3, 'complete')", (old,))
    await db._conn.execute(
        "INSERT INTO speedtest_history (server_name, timestamp) VALUES ('x', ?)", (old,))
    await db._conn.commit()
    new_id = await _complete_scan(db, [_row("Toliman", "clean")])
    await db.prune(RETENTION_DAYS)
    assert [h["id"] for h in await db.get_scan_history()] == [new_id]
    assert await db.get_speedtest_history() == []


async def test_migration_of_legacy_db(tmp_path):
    path = tmp_path / "legacy.db"
    now = datetime.now().isoformat()
    async with aiosqlite.connect(path) as conn:
        await conn.execute("""CREATE TABLE scan_history (id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, total_servers INTEGER DEFAULT 0, clean_servers INTEGER DEFAULT 0,
            blocked_servers INTEGER DEFAULT 0, disabled_servers INTEGER DEFAULT 0)""")
        await conn.execute("INSERT INTO scan_history (timestamp, total_servers) VALUES (?, 5)", (now,))
        await conn.execute("INSERT INTO scan_history (timestamp, total_servers) VALUES (?, 0)", (now,))
        await conn.commit()
    d = DatabaseManager(path)
    await d.init()
    try:
        async with d._conn.execute("SELECT id, status FROM scan_history ORDER BY id") as cur:
            rows = [(r["id"], r["status"]) for r in await cur.fetchall()]
        assert rows == [(1, "complete"), (2, "cancelled")]
    finally:
        await d.close()


async def test_running_scan_marked_cancelled_on_restart(tmp_path):
    path = tmp_path / "a.db"
    d = DatabaseManager(path)
    await d.init()
    sid = await d.add_scan_result({})
    await d.close()
    d2 = DatabaseManager(path)
    await d2.init()
    try:
        async with d2._conn.execute("SELECT status FROM scan_history WHERE id=?", (sid,)) as cur:
            assert (await cur.fetchone())["status"] == "cancelled"
    finally:
        await d2.close()


async def test_speedtest_result_success_flag(db):
    await db.add_speedtest_result({"server_name": "Ookla", "download_mbps": 100, "upload_mbps": 50,
                                   "ping_ms": 10, "error": None, "vpn_server_name": "Toliman"})
    await db.add_speedtest_result({"error": "timeout", "vpn_server_name": "Ran"})
    rows = await db.get_speedtest_history()
    by = {r["vpn_server_name"]: r for r in rows}
    assert by["Toliman"]["is_success"] == 1
    assert by["Ran"]["is_success"] == 0 and by["Ran"]["error_message"] == "timeout"
    assert by["Ran"]["server_name"] == ""


async def test_close_twice(tmp_path):
    d = DatabaseManager(tmp_path / "c.db")
    await d.init()
    await d.close()
    await d.close()  # must not raise
    assert d._conn is None


async def test_find_server_by_exit_ip_newest_wins(db):
    await _complete_scan(db, [_row("Hamal", "clean")])
    assert await db.find_server_by_exit_ip("192.0.2.1") == "Hamal"
    await _complete_scan(db, [_row("Toliman", "clean")])  # IP reassigned later
    assert await db.find_server_by_exit_ip("192.0.2.1") == "Toliman"
    assert await db.find_server_by_exit_ip("192.0.2.99") is None


async def test_historical_averages_include_disabled(db):
    await _complete_scan(db, [], counts={"total_servers": 4, "clean_servers": 1, "blocked_servers": 2,
                                         "disabled_servers": 3})
    avg = await db.get_historical_averages()
    assert avg["7d"]["avg_disabled"] == 3.0 and avg["7d"]["total_scans"] == 1
