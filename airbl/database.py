import aiosqlite
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any
import asyncio

logger = logging.getLogger("airbl.database")

# History older than this is pruned at startup
RETENTION_DAYS = 180

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def init(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute("PRAGMA synchronous=NORMAL;")
        await self._ensure_tables()

    async def close(self):
        conn, self._conn = self._conn, None  # tolerate double close
        if conn:
            await conn.close()

    async def commit(self):
        """Commit writes made with commit=False."""
        await self._conn.commit()

    async def _ensure_tables(self):
        try:
            conn = self._conn
            # Scan History Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    total_servers INTEGER DEFAULT 0,
                    clean_servers INTEGER DEFAULT 0,
                    blocked_servers INTEGER DEFAULT 0,
                    disabled_servers INTEGER DEFAULT 0
                )
            """)
            
            # Migration: scan status (running / complete / cancelled / failed). Only a
            # completed scan's summary was ever written, so 0-count legacy rows are the
            # cancelled or crashed ones.
            try:
                await conn.execute("ALTER TABLE scan_history ADD COLUMN status TEXT")
            except Exception:
                pass
            await conn.execute("""
                UPDATE scan_history SET status = CASE WHEN total_servers > 0 THEN 'complete' ELSE 'cancelled' END
                WHERE status IS NULL
            """)
            # Nothing runs yet at startup: a 'running' row is from a crash or restart
            await conn.execute("UPDATE scan_history SET status = 'cancelled' WHERE status = 'running'")

            # Speedtest History Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS speedtest_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    server_name TEXT NOT NULL,
                    server_country TEXT,
                    vpn_server_name TEXT,
                    vpn_country_code TEXT,
                    download_mbps REAL,
                    upload_mbps REAL,
                    ping_ms REAL,
                    timestamp TEXT NOT NULL,
                    is_success INTEGER DEFAULT 0,
                    error_message TEXT,
                    FOREIGN KEY(scan_id) REFERENCES scan_history(id)
                )
            """)
            
            # Migration: add vpn columns to existing DBs
            for col in ["vpn_server_name TEXT", "vpn_country_code TEXT", "vpn_port INTEGER", "vpn_entry TEXT"]:
                try:
                    await conn.execute(f"ALTER TABLE speedtest_history ADD COLUMN {col}")
                except Exception:
                    pass
            
            # Server Scan History Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS server_scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    server_name TEXT NOT NULL,
                    exit_ip TEXT,
                    exit_ping_ms REAL,
                    config_ping_ms REAL,
                    load_percent INTEGER,
                    users INTEGER,
                    is_blocked INTEGER DEFAULT 0,
                    is_responsive INTEGER DEFAULT 0,
                    score REAL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_history(id)
                )
            """)
            # Migration: reputation state (clean / blocked / unknown); older rows have NULL
            try:
                await conn.execute("ALTER TABLE server_scan_history ADD COLUMN reputation TEXT")
            except Exception:
                pass

            # Entry Ping History Table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS entry_ping_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    server_name TEXT NOT NULL,
                    entry_type TEXT NOT NULL,
                    ip TEXT,
                    latency_ms REAL,
                    is_alive INTEGER DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scan_history(id)
                )
            """)
            
            # Indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_speedtest_timestamp ON speedtest_history(timestamp)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_speedtest_server ON speedtest_history(server_name)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_server_scan_id ON server_scan_history(scan_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_server_scan_name ON server_scan_history(server_name)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_entry_ping_server ON entry_ping_history(server_name)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_entry_ping_scan ON entry_ping_history(scan_id)")
            
            await conn.commit()
            await self.prune(RETENTION_DAYS)
            logger.info(f"Database initialized at {self.db_path} (WAL Mode enabled)")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    async def prune(self, days: int):
        """Delete history older than `days` (timestamps are ISO strings, so they sort as text)."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        removed = 0
        for table in ("entry_ping_history", "server_scan_history", "speedtest_history", "scan_history"):
            cursor = await self._conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
            removed += max(cursor.rowcount, 0)
        await self._conn.commit()
        if removed:
            logger.info(f"Pruned {removed} history rows older than {days} days")

    async def add_entry_ping(self, scan_id: int, server_name: str, entry_type: str, ip: str, latency_ms: float, is_alive: bool, commit: bool = True):
        await self._conn.execute("""
            INSERT INTO entry_ping_history 
            (scan_id, server_name, entry_type, ip, latency_ms, is_alive, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id, server_name, entry_type, ip, latency_ms,
            1 if is_alive else 0,
            datetime.now().isoformat()
        ))
        if commit:
            await self._conn.commit()

    async def get_best_entry_for_server(self, server_name: str, lookback: int = 10) -> str:
        async with self._conn.execute("""
            SELECT DISTINCT scan_id FROM entry_ping_history
            WHERE server_name = ? AND scan_id IS NOT NULL
            ORDER BY scan_id DESC LIMIT ?
        """, (server_name, lookback)) as cursor:
            scan_ids = await cursor.fetchall()
        
        if not scan_ids:
            return "ENTRY3"
        
        ids = [row["scan_id"] for row in scan_ids]
        placeholders = ",".join("?" for _ in ids)
        
        async with self._conn.execute(f"""
            SELECT entry_type, AVG(latency_ms) as avg_latency, COUNT(*) as sample_count
            FROM entry_ping_history
            WHERE server_name = ? AND scan_id IN ({placeholders})
              AND is_alive = 1 AND latency_ms IS NOT NULL
            GROUP BY entry_type
        """, [server_name] + ids) as cursor:
            rows = await cursor.fetchall()
        
        if not rows:
            return "ENTRY3"
        
        results = {row["entry_type"]: row["avg_latency"] for row in rows}
        e1_avg = results.get("ENTRY1")
        e3_avg = results.get("ENTRY3")
        
        if e1_avg is not None and e3_avg is not None:
            return "ENTRY1" if e1_avg < e3_avg else "ENTRY3"
        elif e1_avg is not None:
            return "ENTRY1"
        return "ENTRY3"

    async def get_best_entries_bulk(self, server_names: list[str], lookback: int = 10) -> dict[str, str]:
        results = {}
        if not server_names:
            return results
        
        placeholders = ",".join("?" for _ in server_names)
        async with self._conn.execute(f"""
            SELECT server_name, entry_type, AVG(latency_ms) as avg_latency
            FROM entry_ping_history
            WHERE server_name IN ({placeholders})
              AND is_alive = 1 AND latency_ms IS NOT NULL
              AND scan_id IN (
                  SELECT DISTINCT scan_id FROM entry_ping_history
                  WHERE scan_id IS NOT NULL
                  ORDER BY scan_id DESC LIMIT ?
              )
            GROUP BY server_name, entry_type
        """, server_names + [lookback]) as cursor:
            rows = await cursor.fetchall()
        
        server_entries = {}
        for row in rows:
            name = row["server_name"]
            if name not in server_entries:
                server_entries[name] = {}
            server_entries[name][row["entry_type"]] = row["avg_latency"]
        
        for name in server_names:
            entries = server_entries.get(name, {})
            e1 = entries.get("ENTRY1")
            e3 = entries.get("ENTRY3")
            if e1 is not None and e3 is not None:
                results[name] = "ENTRY1" if e1 < e3 else "ENTRY3"
            elif e1 is not None:
                results[name] = "ENTRY1"
            else:
                results[name] = "ENTRY3"
        
        return results

    async def add_scan_result(self, summary: Dict[str, Any]) -> int:
        cursor = await self._conn.execute("""
            INSERT INTO scan_history 
            (timestamp, total_servers, clean_servers, blocked_servers, disabled_servers, status)
            VALUES (?, ?, ?, ?, ?, 'running')
        """, (
            datetime.now().isoformat(),
            summary.get("total_servers", 0),
            summary.get("clean_servers", 0),
            summary.get("blocked_servers", 0),
            summary.get("disabled_servers", 0)
        ))
        await self._conn.commit()
        return cursor.lastrowid

    async def add_server_scan_result(self, scan_id: int, result: Dict[str, Any], commit: bool = True):
        exit_ping = result.get("exit_ping")
        exit_ping_ms = None
        exit_ip = None
        if isinstance(exit_ping, dict):
            exit_ping_ms = exit_ping.get("latency_ms")
            exit_ip = exit_ping.get("ip")
        
        # Entry (config endpoint) ping: lowest of Entry 1 / Entry 3
        entry_pings = [
            p.get("latency_ms") for p in (result.get("entry1_ping"), result.get("entry3_ping"))
            if isinstance(p, dict) and p.get("latency_ms") is not None
        ]
        config_ping_ms = min(entry_pings) if entry_pings else None

        await self._conn.execute("""
            INSERT INTO server_scan_history 
            (scan_id, server_name, exit_ip, exit_ping_ms, config_ping_ms, load_percent, users, is_blocked, is_responsive, score, timestamp, reputation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            result.get("server_name"),
            exit_ip,
            exit_ping_ms,
            config_ping_ms,
            result.get("load_percent", 0),
            result.get("users", 0),
            1 if result.get("is_blocked", result.get("blocked_count", 0) > 0) else 0,
            1 if result.get("responsive_count", 0) > 0 else 0,
            result.get("score", 0),
            datetime.now().isoformat(),
            result.get("reputation"),
        ))
        if commit:
            await self._conn.commit()

    async def update_scan_result(self, scan_id: int, summary: Dict[str, Any], status: str = "complete"):
        await self._conn.execute("""
            UPDATE scan_history 
            SET total_servers = ?, clean_servers = ?, blocked_servers = ?, disabled_servers = ?, status = ?
            WHERE id = ?
        """, (
            summary.get("total_servers", 0),
            summary.get("clean_servers", 0),
            summary.get("blocked_servers", 0),
            summary.get("disabled_servers", 0),
            status,
            scan_id
        ))
        await self._conn.commit()

    async def set_scan_status(self, scan_id: int, status: str):
        await self._conn.execute("UPDATE scan_history SET status = ? WHERE id = ?", (status, scan_id))
        await self._conn.commit()

    async def add_speedtest_result(self, result: Dict[str, Any], scan_id: Optional[int] = None):
        await self._conn.execute("""
            INSERT INTO speedtest_history 
            (scan_id, server_name, server_country, vpn_server_name, vpn_country_code, vpn_port, vpn_entry, download_mbps, upload_mbps, ping_ms, timestamp, is_success, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            result.get("server_name") or "",  # Ookla server; column is NOT NULL
            result.get("server_country") or result.get("server_location"),
            result.get("vpn_server_name"),
            result.get("vpn_country_code"),
            result.get("vpn_port"),
            result.get("vpn_entry"),
            result.get("download_mbps"),
            result.get("upload_mbps"),
            result.get("ping_ms"),
            result.get("timestamp") or datetime.now().isoformat(),
            1 if result.get("is_success", True) and not result.get("error") else 0,
            result.get("error") or result.get("error_message")
        ))
        await self._conn.commit()

    async def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        async with self._conn.execute("""
            SELECT * FROM scan_history 
            WHERE status = 'complete'
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,)) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def get_speedtest_history(self, limit: int = 100, server_name: Optional[str] = None) -> List[Dict[str, Any]]:
        if server_name:
            async with self._conn.execute("""
                SELECT * FROM speedtest_history 
                WHERE server_name = ?
                ORDER BY id DESC 
                LIMIT ?
            """, (server_name, limit)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]
        else:
            async with self._conn.execute("""
                SELECT * FROM speedtest_history 
                ORDER BY id DESC 
                LIMIT ?
            """, (limit,)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]
    
    async def get_stats(self) -> Dict[str, Any]:
        async with self._conn.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'complete'") as cursor:
            total_scans = (await cursor.fetchone())[0]
        async with self._conn.execute("SELECT COUNT(*) FROM speedtest_history") as cursor:
            total_speedtests = (await cursor.fetchone())[0]
        
        async with self._conn.execute("""
            SELECT AVG(clean_servers) as avg_clean, AVG(blocked_servers) as avg_blocked 
            FROM (SELECT clean_servers, blocked_servers FROM scan_history WHERE status = 'complete' ORDER BY id DESC LIMIT 10)
        """) as cursor:
            avg_row = await cursor.fetchone()
        
        return {
            "total_scans": total_scans,
            "total_speedtests": total_speedtests,
            "recent_avg_clean": avg_row["avg_clean"] or 0,
            "recent_avg_blocked": avg_row["avg_blocked"] or 0
        }

    async def get_historical_averages(self) -> Dict[str, Any]:
        async def fetch_period(days: int):
            async with self._conn.execute(f"""
                SELECT COUNT(*) as total_scans, 
                       AVG(clean_servers) as avg_clean, 
                       AVG(blocked_servers) as avg_blocked
                FROM scan_history 
                WHERE status = 'complete' AND timestamp >= datetime('now', '-{days} days')
            """) as cursor:
                row = await cursor.fetchone()
            return {
                "total_scans": row["total_scans"] or 0,
                "avg_clean": round(row["avg_clean"] or 0, 1),
                "avg_blocked": round(row["avg_blocked"] or 0, 1)
            }
        
        return {
            "7d": await fetch_period(7),
            "30d": await fetch_period(30),
            "180d": await fetch_period(180)
        }

    async def get_last_complete_scan(self) -> Optional[Dict[str, Any]]:
        """The newest completed scan row (cancelled/crashed/running scans are partial)."""
        async with self._conn.execute(
            "SELECT * FROM scan_history WHERE status = 'complete' ORDER BY id DESC LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()
        return dict(row) if row else None

    async def get_last_scan_servers(self) -> List[Dict[str, Any]]:
        last_scan = await self.get_last_complete_scan()
        if not last_scan:
            return []
        scan_id = last_scan["id"]
        
        async with self._conn.execute("""
            SELECT s.server_name, s.exit_ip, s.exit_ping_ms, s.config_ping_ms,
                   s.load_percent, s.users, s.is_blocked, s.is_responsive, s.score, s.reputation
            FROM server_scan_history s
            WHERE s.scan_id = ?
            ORDER BY s.server_name
        """, (scan_id,)) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def get_last_scan_entry_pings(self) -> List[Dict[str, Any]]:
        last_scan = await self.get_last_complete_scan()
        if not last_scan:
            return []
        scan_id = last_scan["id"]
        
        async with self._conn.execute("""
            SELECT server_name, entry_type, ip, latency_ms, is_alive
            FROM entry_ping_history
            WHERE scan_id = ?
        """, (scan_id,)) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def get_ban_history(self) -> Dict[str, int]:
        async with self._conn.execute("""
            SELECT server_name, COUNT(*) as ban_count
            FROM server_scan_history
            WHERE is_blocked = 1
              AND scan_id IN (SELECT id FROM scan_history WHERE status = 'complete')
            GROUP BY server_name
            ORDER BY ban_count DESC
        """) as cursor:
            return {row["server_name"]: row["ban_count"] for row in await cursor.fetchall()}


def row_is_clean(row: Dict[str, Any]) -> bool:
    """Clean state of a stored server row. Rows from before the reputation column fall back to is_blocked."""
    if row.get("reputation"):
        return row["reputation"] == "clean"
    return not row.get("is_blocked")
