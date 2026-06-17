from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

MEMORY_DB = Path("/tmp/skoll_memory.db")


class CampaignMemory:
    """Memoria de campaña: correlación entre hosts, diff entre scans,
    historial por objetivo.

    Construye sobre el Evidence Store y Findings Engine para dar contexto
    temporal y multi-host a las capas superiores.
    """

    def __init__(self, db_path: str | Path = MEMORY_DB):
        self._path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id TEXT PRIMARY KEY,
                    target_range TEXT,
                    created_at REAL NOT NULL,
                    status TEXT DEFAULT 'active'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    scan_target TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    finished_at REAL,
                    status TEXT DEFAULT 'running',
                    findings_count INTEGER DEFAULT 0,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    ip TEXT NOT NULL,
                    campaign_id TEXT NOT NULL,
                    hostname TEXT DEFAULT '',
                    os TEXT DEFAULT '',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    port_count INTEGER DEFAULT 0,
                    service_count INTEGER DEFAULT 0,
                    PRIMARY KEY (ip, campaign_id),
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    host TEXT NOT NULL,
                    scan_run_id INTEGER,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    port INTEGER,
                    service TEXT,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    count INTEGER DEFAULT 1,
                    mitre TEXT DEFAULT '',
                    recommendation TEXT DEFAULT '',
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS host_correlation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    host_count INTEGER DEFAULT 0,
                    hosts TEXT DEFAULT '[]',
                    severity TEXT DEFAULT 'info',
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
                )
            """)
            for idx in [
                "CREATE INDEX IF NOT EXISTS idx_scan_runs_campaign ON scan_runs(campaign_id)",
                "CREATE INDEX IF NOT EXISTS idx_mf_campaign ON memory_findings(campaign_id)",
                "CREATE INDEX IF NOT EXISTS idx_mf_host ON memory_findings(host)",
                "CREATE INDEX IF NOT EXISTS idx_hc_campaign ON host_correlation(campaign_id)",
                "CREATE INDEX IF NOT EXISTS idx_hosts_campaign ON hosts(campaign_id)",
            ]:
                conn.execute(idx)
            conn.commit()
            conn.close()

    # ── Campaign lifecycle ──────────────────────────────────────────

    def create_campaign(
        self, campaign_id: str, target_range: str = ""
    ) -> dict[str, Any]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute(
                "INSERT OR IGNORE INTO campaigns (id, target_range, created_at) VALUES (?, ?, ?)",
                (campaign_id, target_range, time.time()),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
            conn.close()
            return self._row_to_dict(
                row, ["id", "target_range", "created_at", "status"]
            )

    def get_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            row = conn.execute(
                "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
            ).fetchone()
            conn.close()
            if not row:
                return None
            return self._row_to_dict(
                row, ["id", "target_range", "created_at", "status"]
            )

    def list_campaigns(self) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                "SELECT * FROM campaigns ORDER BY created_at DESC"
            ).fetchall()
            conn.close()
            return [
                self._row_to_dict(r, ["id", "target_range", "created_at", "status"])
                for r in rows
            ]

    def close_campaign(self, campaign_id: str) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute(
                "UPDATE campaigns SET status = 'closed' WHERE id = ?",
                (campaign_id,),
            )
            conn.commit()
            conn.close()

    # ── Scan runs ──────────────────────────────────────────────────

    def start_scan(
        self, campaign_id: str, target: str
    ) -> dict[str, Any]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute(
                "INSERT INTO scan_runs (campaign_id, scan_target, started_at) VALUES (?, ?, ?)",
                (campaign_id, target, time.time()),
            )
            conn.commit()
            row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.close()
            return {"scan_run_id": row_id, "campaign_id": campaign_id, "target": target}

    def finish_scan(self, scan_run_id: int, findings_count: int = 0) -> None:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            conn.execute(
                "UPDATE scan_runs SET finished_at = ?, status = 'done', findings_count = ? WHERE id = ?",
                (time.time(), findings_count, scan_run_id),
            )
            conn.commit()
            conn.close()

    def get_scan_runs(self, campaign_id: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                "SELECT * FROM scan_runs WHERE campaign_id = ? ORDER BY started_at DESC",
                (campaign_id,),
            ).fetchall()
            conn.close()
            return [
                self._row_to_dict(
                    r,
                    [
                        "id",
                        "campaign_id",
                        "scan_target",
                        "started_at",
                        "finished_at",
                        "status",
                        "findings_count",
                    ],
                )
                for r in rows
            ]

    # ── Hosts ───────────────────────────────────────────────────────

    def upsert_host(
        self,
        campaign_id: str,
        ip: str,
        hostname: str = "",
        os_info: str = "",
        port_count: int = 0,
        service_count: int = 0,
    ) -> None:
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            existing = conn.execute(
                "SELECT * FROM hosts WHERE ip = ? AND campaign_id = ?",
                (ip, campaign_id),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE hosts SET last_seen = ?, hostname = ?, os = ?,
                       port_count = ?, service_count = ?
                       WHERE ip = ? AND campaign_id = ?""",
                    (now, hostname, os_info, port_count, service_count, ip, campaign_id),
                )
            else:
                conn.execute(
                    """INSERT INTO hosts (ip, campaign_id, hostname, os, first_seen, last_seen, port_count, service_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (ip, campaign_id, hostname, os_info, now, now, port_count, service_count),
                )
            conn.commit()
            conn.close()

    def get_hosts(self, campaign_id: str) -> list[dict[str, Any]]:
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                "SELECT * FROM hosts WHERE campaign_id = ? ORDER BY ip",
                (campaign_id,),
            ).fetchall()
            conn.close()
            return [
                self._row_to_dict(
                    r,
                    [
                        "ip",
                        "campaign_id",
                        "hostname",
                        "os",
                        "first_seen",
                        "last_seen",
                        "port_count",
                        "service_count",
                    ],
                )
                for r in rows
            ]

    # ── Findings Memory ─────────────────────────────────────────────

    def remember_finding(
        self,
        campaign_id: str,
        scan_run_id: int,
        finding: dict[str, Any],
    ) -> int:
        host = finding.get("host", "")
        rule_id = finding.get("rule_id", "")
        title = finding.get("title", "")
        severity = finding.get("severity", "low")
        port = finding.get("port")
        service = finding.get("service", "")
        mitre = finding.get("mitre", "")
        recommendation = finding.get("recommendation", "")
        now = time.time()

        with self._lock:
            conn = sqlite3.connect(str(self._path))
            existing = conn.execute(
                """SELECT id, count FROM memory_findings
                   WHERE campaign_id = ? AND host = ? AND rule_id = ?
                   AND (port IS ? OR port = ?)""",
                (campaign_id, host, rule_id, port, port if port else 0),
            ).fetchone()
            if existing:
                fid, fcount = existing
                conn.execute(
                    "UPDATE memory_findings SET last_seen = ?, count = ?, scan_run_id = ? WHERE id = ?",
                    (now, fcount + 1, scan_run_id, fid),
                )
                row_id = fid
            else:
                conn.execute(
                    """INSERT INTO memory_findings
                       (campaign_id, host, scan_run_id, rule_id, title, severity,
                        port, service, first_seen, last_seen, count, mitre, recommendation)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)""",
                    (
                        campaign_id,
                        host,
                        scan_run_id,
                        rule_id,
                        title,
                        severity,
                        port,
                        service,
                        now,
                        now,
                        mitre,
                        recommendation,
                    ),
                )
                row_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
            conn.commit()
            conn.close()
            return row_id

    def get_findings(
        self,
        campaign_id: str,
        host: str | None = None,
        min_severity: str = "low",
    ) -> list[dict[str, Any]]:
        sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_val = sev_order.get(min_severity, 1)
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            if host:
                rows = conn.execute(
                    "SELECT * FROM memory_findings WHERE campaign_id = ? AND host = ?",
                    (campaign_id, host),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM memory_findings WHERE campaign_id = ?",
                    (campaign_id,),
                ).fetchall()
            conn.close()
            result = [
                self._row_to_dict(
                    r,
                    [
                        "id", "campaign_id", "host", "scan_run_id", "rule_id",
                        "title", "severity", "port", "service", "first_seen",
                        "last_seen", "count", "mitre", "recommendation",
                    ],
                )
                for r in rows
            ]
        return [r for r in result if sev_order.get(r["severity"], 0) >= min_val]

    def get_changed_findings(
        self,
        campaign_id: str,
        since_scan_id: int,
    ) -> dict[str, list[dict[str, Any]]]:
        """Diff findings: cuáles son nuevos vs los que ya existían."""
        all_f = self.get_findings(campaign_id)
        new: list[dict[str, Any]] = []
        existing: list[dict[str, Any]] = []
        for f in all_f:
            if f.get("scan_run_id") == since_scan_id or f.get("count", 1) == 1:
                new.append(f)
            else:
                existing.append(f)
        return {"new": new, "existing": existing}

    # ── Host Correlation ────────────────────────────────────────────

    def correlate_hosts(self, campaign_id: str) -> list[dict[str, Any]]:
        """Analiza findings y agrupa por servicio+puerto entre hosts."""
        with self._lock:
            conn = sqlite3.connect(str(self._path))
            rows = conn.execute(
                """SELECT service, port, COUNT(DISTINCT host) as host_count,
                          GROUP_CONCAT(DISTINCT host) as host_list
                   FROM memory_findings
                   WHERE campaign_id = ? AND service != '' AND port IS NOT NULL
                   GROUP BY service, port
                   HAVING host_count > 1
                   ORDER BY host_count DESC""",
                (campaign_id,),
            ).fetchall()
            now = time.time()
            for row in rows:
                service, port, host_count, host_list = row
                hosts = host_list.split(",") if host_list else []
                existing = conn.execute(
                    "SELECT id FROM host_correlation WHERE campaign_id = ? AND service = ? AND port = ?",
                    (campaign_id, service, port),
                ).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE host_correlation SET host_count = ?, hosts = ?, last_seen = ? WHERE id = ?",
                        (host_count, json.dumps(hosts), now, existing[0]),
                    )
                else:
                    conn.execute(
                        "INSERT INTO host_correlation (campaign_id, service, port, host_count, hosts, severity, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            campaign_id,
                            service,
                            port,
                            host_count,
                            json.dumps(hosts),
                            "medium" if host_count >= 3 else "low",
                            now,
                            now,
                        ),
                    )
            conn.commit()
            result = conn.execute(
                "SELECT * FROM host_correlation WHERE campaign_id = ? ORDER BY host_count DESC",
                (campaign_id,),
            ).fetchall()
            conn.close()
            return [
                self._row_to_dict(
                    r,
                    [
                        "id", "campaign_id", "service", "port",
                        "host_count", "hosts", "severity", "first_seen", "last_seen",
                    ],
                )
                for r in result
            ]

    # ── Summary ─────────────────────────────────────────────────────

    def campaign_summary(self, campaign_id: str) -> dict[str, Any]:
        hosts = self.get_hosts(campaign_id)
        findings = self.get_findings(campaign_id)
        correlations = self.correlate_hosts(campaign_id)
        scan_runs = self.get_scan_runs(campaign_id)

        sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        by_severity: dict[str, int] = {}
        for f in findings:
            s = f["severity"]
            by_severity[s] = by_severity.get(s, 0) + 1

        return {
            "campaign_id": campaign_id,
            "hosts_count": len(hosts),
            "total_findings": len(findings),
            "findings_by_severity": by_severity,
            "max_severity": max(
                (f["severity"] for f in findings),
                key=lambda s: sev_order.get(s, 0),
                default="info",
            ),
            "correlations": len(correlations),
            "scan_count": len(scan_runs),
            "last_scan": scan_runs[0] if scan_runs else None,
        }

    # ── Helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _row_to_dict(
        row: tuple[Any, ...], columns: list[str]
    ) -> dict[str, Any]:
        return dict(zip(columns, row))


_memory: CampaignMemory | None = None


def get_campaign_memory() -> CampaignMemory:
    global _memory
    if _memory is None:
        _memory = CampaignMemory()
    return _memory
