import sqlite3
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
import asyncio

logger = logging.getLogger("airbl.database")

class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._ensure_tables()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a synchronous SQLite connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_tables(self):
        """Create tables if they don't exist."""
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with self._get_connection() as conn:
                # Scan History Table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        total_servers INTEGER DEFAULT 0,
                        clean_servers INTEGER DEFAULT 0,
                        blocked_servers INTEGER DEFAULT 0,
                        disabled_servers INTEGER DEFAULT 0
                    )
                """)
                
                # Speedtest History Table
                conn.execute("""
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
                try:
                    conn.execute("ALTER TABLE speedtest_history ADD COLUMN vpn_server_name TEXT")
                except Exception:
                    pass  # Column already exists
                try:
                    conn.execute("ALTER TABLE speedtest_history ADD COLUMN vpn_country_code TEXT")
                except Exception:
                    pass  # Column already exists
                try:
                    conn.execute("ALTER TABLE speedtest_history ADD COLUMN vpn_port INTEGER")
                except Exception:
                    pass
                try:
                    conn.execute("ALTER TABLE speedtest_history ADD COLUMN vpn_entry TEXT")
                except Exception:
                    pass
                
                # Server Scan History Table (Detailed per-server results for a scan)
                conn.execute("""
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
                """) # turbo-metrics
                # Entry Ping History Table (per-server entry latency tracking for AUTO mode)
                conn.execute("""
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
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_history(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_speedtest_timestamp ON speedtest_history(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_speedtest_server ON speedtest_history(server_name)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_server_scan_id ON server_scan_history(scan_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_server_scan_name ON server_scan_history(server_name)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_entry_ping_server ON entry_ping_history(server_name)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_entry_ping_scan ON entry_ping_history(scan_id)")
                
                conn.commit()
                logger.info(f"Database initialized at {self.db_path}")
                
        except Exception as e:
            conn.rollback() # Ensure rollback on error if possible, though 'with' usually handles it.
            logger.error(f"Failed to initialize database: {e}")
            raise

    async def add_entry_ping(self, scan_id: int, server_name: str, entry_type: str, ip: str, latency_ms: float, is_alive: bool):
        """Record entry ping result for AUTO mode historical analysis."""
        def _insert():
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO entry_ping_history 
                    (scan_id, server_name, entry_type, ip, latency_ms, is_alive, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id, server_name, entry_type, ip, latency_ms,
                    1 if is_alive else 0,
                    datetime.now().isoformat()
                ))
                conn.commit()
        
        await asyncio.to_thread(_insert)

    async def get_best_entry_for_server(self, server_name: str, lookback: int = 10) -> str:
        """
        Determine the best entry point for a server based on historical average latency.
        Returns 'ENTRY1' or 'ENTRY3'. Falls back to 'ENTRY3' if no data.
        """
        def _query():
            with self._get_connection() as conn:
                # Get recent scan IDs to limit lookback
                scan_ids = conn.execute("""
                    SELECT DISTINCT scan_id FROM entry_ping_history
                    WHERE server_name = ? AND scan_id IS NOT NULL
                    ORDER BY scan_id DESC LIMIT ?
                """, (server_name, lookback)).fetchall()
                
                if not scan_ids:
                    return "ENTRY3"  # Default fallback
                
                ids = [row["scan_id"] for row in scan_ids]
                placeholders = ",".join("?" for _ in ids)
                
                rows = conn.execute(f"""
                    SELECT entry_type, AVG(latency_ms) as avg_latency, COUNT(*) as sample_count
                    FROM entry_ping_history
                    WHERE server_name = ? AND scan_id IN ({placeholders})
                      AND is_alive = 1 AND latency_ms IS NOT NULL
                    GROUP BY entry_type
                """, [server_name] + ids).fetchall()
                
                if not rows:
                    return "ENTRY3"
                
                results = {row["entry_type"]: row["avg_latency"] for row in rows}
                
                e1_avg = results.get("ENTRY1")
                e3_avg = results.get("ENTRY3")
                
                if e1_avg is not None and e3_avg is not None:
                    return "ENTRY1" if e1_avg < e3_avg else "ENTRY3"
                elif e1_avg is not None:
                    return "ENTRY1"
                else:
                    return "ENTRY3"
        
        return await asyncio.to_thread(_query)

    async def get_best_entries_bulk(self, server_names: list[str], lookback: int = 10) -> dict[str, str]:
        """
        Batch version: determine best entry for multiple servers.
        Returns {server_name: 'ENTRY1'|'ENTRY3'} for each server.
        """
        def _query():
            results = {}
            if not server_names:
                return results
            
            with self._get_connection() as conn:
                placeholders = ",".join("?" for _ in server_names)
                
                # Get average latency per server per entry type from recent scans
                rows = conn.execute(f"""
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
                """, server_names + [lookback]).fetchall()
                
                # Build per-server map
                server_entries = {}  # server_name -> {entry_type: avg_latency}
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
                        results[name] = "ENTRY3"  # Default
            
            return results
        
        return await asyncio.to_thread(_query)

    async def add_scan_result(self, summary: Dict[str, Any]) -> int:
        """
        Add a completed scan summary to the database.
        Returns the new scan ID.
        """
        def _insert():
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO scan_history 
                    (timestamp, total_servers, clean_servers, blocked_servers, disabled_servers)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    summary.get("total_servers", 0),
                    summary.get("clean_servers", 0),
                    summary.get("blocked_servers", 0),
                    summary.get("disabled_servers", 0)
                ))
                conn.commit()
                return cursor.lastrowid
        
        return await asyncio.to_thread(_insert)

    async def add_server_scan_result(self, scan_id: int, result: Dict[str, Any]):
        """Add a detailed server scan result to the database."""
        def _insert():
            with self._get_connection() as conn:
                # Extract exit ping safely
                exit_ping = result.get("exit_ping")
                exit_ping_ms = None
                exit_ip = None
                if isinstance(exit_ping, dict):
                    exit_ping_ms = exit_ping.get("latency_ms")
                    exit_ip = exit_ping.get("ip")
                
                # Extract config ping safely
                config_ping = result.get("config_ping")
                config_ping_ms = None
                if isinstance(config_ping, dict):
                    config_ping_ms = config_ping.get("latency_ms")

                conn.execute("""
                    INSERT INTO server_scan_history 
                    (scan_id, server_name, exit_ip, exit_ping_ms, config_ping_ms, load_percent, users, is_blocked, is_responsive, score, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    result.get("server_name"),
                    exit_ip,
                    exit_ping_ms,
                    config_ping_ms,
                    result.get("load_percent", 0),
                    result.get("users", 0),
                    1 if not result.get("is_clean", True) else 0, # is_blocked is inverted is_clean usually, or check blocked_count > 0
                    1 if result.get("responsive_count", 0) > 0 else 0,
                    result.get("score", 0),
                    datetime.now().isoformat()
                ))
                conn.commit()
        
        await asyncio.to_thread(_insert)

    async def update_scan_result(self, scan_id: int, summary: Dict[str, Any]):
        """Update an existing scan result with final summary stats."""
        def _update():
            with self._get_connection() as conn:
                conn.execute("""
                    UPDATE scan_history 
                    SET total_servers = ?, clean_servers = ?, blocked_servers = ?, disabled_servers = ?
                    WHERE id = ?
                """, (
                    summary.get("total_servers", 0),
                    summary.get("clean_servers", 0),
                    summary.get("blocked_servers", 0),
                    summary.get("disabled_servers", 0),
                    scan_id
                ))
                conn.commit()
        
        await asyncio.to_thread(_update)

    async def add_speedtest_result(self, result: Dict[str, Any], scan_id: Optional[int] = None):
        """Add a speedtest result to the database."""
        def _insert():
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT INTO speedtest_history 
                    (scan_id, server_name, server_country, vpn_server_name, vpn_country_code, vpn_port, vpn_entry, download_mbps, upload_mbps, ping_ms, timestamp, is_success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    result.get("server_name"),
                    result.get("server_country"),
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
                conn.commit()
        
        await asyncio.to_thread(_insert)

    async def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent scan history."""
        def _query():
            with self._get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM scan_history 
                    ORDER BY id DESC 
                    LIMIT ?
                """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        
        return await asyncio.to_thread(_query)

    async def get_speedtest_history(self, limit: int = 100, server_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent speedtest history, optionally filtered by server."""
        def _query():
            with self._get_connection() as conn:
                if server_name:
                    cursor = conn.execute("""
                        SELECT * FROM speedtest_history 
                        WHERE server_name = ?
                        ORDER BY id DESC 
                        LIMIT ?
                    """, (server_name, limit))
                else:
                    cursor = conn.execute("""
                        SELECT * FROM speedtest_history 
                        ORDER BY id DESC 
                        LIMIT ?
                    """, (limit,))
                return [dict(row) for row in cursor.fetchall()]
        
        return await asyncio.to_thread(_query)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get aggregate stats."""
        def _query():
            with self._get_connection() as conn:
                total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
                total_speedtests = conn.execute("SELECT COUNT(*) FROM speedtest_history").fetchone()[0]
                
                # Get averages from last 10 scans
                avg_row = conn.execute("""
                    SELECT AVG(clean_servers) as avg_clean, AVG(blocked_servers) as avg_blocked 
                    FROM (SELECT clean_servers, blocked_servers FROM scan_history ORDER BY id DESC LIMIT 10)
                """).fetchone()
                
                return {
                    "total_scans": total_scans,
                    "total_speedtests": total_speedtests,
                    "recent_avg_clean": avg_row["avg_clean"] or 0,
                    "recent_avg_blocked": avg_row["avg_blocked"] or 0
                }
                
        return await asyncio.to_thread(_query)

    async def get_historical_averages(self) -> Dict[str, Any]:
        """Get average clean/blocked servers for 7, 30, and 180 days."""
        def _query():
            with self._get_connection() as conn:
                def fetch_period(days: int):
                    row = conn.execute(f"""
                        SELECT COUNT(*) as total_scans, 
                               AVG(clean_servers) as avg_clean, 
                               AVG(blocked_servers) as avg_blocked
                        FROM scan_history 
                        WHERE timestamp >= datetime('now', '-{days} days')
                    """).fetchone()
                    return {
                        "total_scans": row["total_scans"] or 0,
                        "avg_clean": round(row["avg_clean"] or 0, 1),
                        "avg_blocked": round(row["avg_blocked"] or 0, 1)
                    }
                
                return {
                    "7d": fetch_period(7),
                    "30d": fetch_period(30),
                    "180d": fetch_period(180)
                }
        
        return await asyncio.to_thread(_query)

    async def get_last_scan_servers(self) -> List[Dict[str, Any]]:
        """Get per-server results from the most recent scan for metrics restoration."""
        def _query():
            with self._get_connection() as conn:
                # Find the latest scan ID
                last_scan = conn.execute(
                    "SELECT id FROM scan_history ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if not last_scan:
                    return []
                scan_id = last_scan["id"]
                
                rows = conn.execute("""
                    SELECT s.server_name, s.exit_ip, s.exit_ping_ms, s.config_ping_ms,
                           s.load_percent, s.users, s.is_blocked, s.is_responsive, s.score
                    FROM server_scan_history s
                    WHERE s.scan_id = ?
                    ORDER BY s.server_name
                """, (scan_id,))
                return [dict(row) for row in rows.fetchall()]
        
        return await asyncio.to_thread(_query)

    async def get_last_scan_entry_pings(self) -> List[Dict[str, Any]]:
        """Get entry ping data from the most recent scan for metrics restoration."""
        def _query():
            with self._get_connection() as conn:
                last_scan = conn.execute(
                    "SELECT id FROM scan_history ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if not last_scan:
                    return []
                scan_id = last_scan["id"]
                
                rows = conn.execute("""
                    SELECT server_name, entry_type, ip, latency_ms, is_alive
                    FROM entry_ping_history
                    WHERE scan_id = ?
                """, (scan_id,))
                return [dict(row) for row in rows.fetchall()]
        
        return await asyncio.to_thread(_query)

    async def get_ban_history(self) -> Dict[str, int]:
        """Reconstruct ban frequency counts from all historical scan data."""
        def _query():
            with self._get_connection() as conn:
                rows = conn.execute("""
                    SELECT server_name, COUNT(*) as ban_count
                    FROM server_scan_history
                    WHERE is_blocked = 1
                    GROUP BY server_name
                    ORDER BY ban_count DESC
                """)
                return {row["server_name"]: row["ban_count"] for row in rows.fetchall()}
        
        return await asyncio.to_thread(_query)
