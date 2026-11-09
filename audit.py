"""
Privacy-Safe Audit Logger.
Persists security events into SQLite with HMAC-SHA256 fingerprints and last-4 masked previews.
GUARANTEE: NEVER stores raw user prompts, raw model responses, or full secret values anywhere.
"""

import os
import sqlite3
import time
import hmac
import hashlib
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("gateway.audit")


class AuditLogger:
    """Privacy-preserving audit logger using SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv("AUDIT_DB_PATH", "audit.db")
        self.audit_key = os.getenv("AUDIT_KEY", "ai-gateway-default-audit-secret-key-32b").encode("utf-8")
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _init_db(self):
        """Create audit log schema if not present."""
        with self._get_connection() as conn:
            try:
                conn.execute("PRAGMA journal_mode = WAL")
            except Exception:
                pass
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    request_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    category TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    score REAL NOT NULL,
                    fingerprint TEXT NOT NULL,
                    masked_preview TEXT,
                    latency_ms REAL NOT NULL,
                    stage_latencies TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_req ON audit_events(request_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit_events(category)")
            conn.commit()

    def compute_fingerprint(self, value: str) -> str:
        """Compute truncated HMAC-SHA256 fingerprint for a matched value."""
        if not value:
            return "none"
        h = hmac.new(self.audit_key, value.encode("utf-8", errors="ignore"), hashlib.sha256)
        return h.hexdigest()[:16]

    def compute_masked_preview(self, value: str) -> str:
        """Create privacy-safe preview displaying only the last 4 characters."""
        if not value:
            return ""
        clean = value.strip()
        if len(clean) >= 4:
            return f"...{clean[-4:]}"
        return "****"

    def log_event(
        self,
        request_id: str,
        user_id: str,
        role: str,
        direction: str,
        category: str,
        policy_id: str,
        action: str,
        score: float,
        matched_value: str = "",
        latency_ms: float = 0.0,
        stage_latencies: Optional[Dict[str, float]] = None
    ):
        """
        Write a privacy-safe audit record.
        NEVER stores raw prompts, responses, or full matched strings.
        """
        fingerprint = self.compute_fingerprint(matched_value)
        masked_preview = self.compute_masked_preview(matched_value)
        latencies_json = json.dumps(stage_latencies or {})
        ts = time.time()

        try:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_events (
                        ts, request_id, user_id, role, direction, category,
                        policy_id, action, score, fingerprint, masked_preview,
                        latency_ms, stage_latencies
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts, request_id, user_id, role, direction, category,
                        policy_id, action, round(score, 4), fingerprint, masked_preview,
                        round(latency_ms, 2), latencies_json
                    )
                )
                conn.commit()

            # Mirror to hash-chained tamper-evident audit log
            try:
                from gateway.tee.chain_audit import ChainAuditLogger
                cl = ChainAuditLogger(db_path=self.db_path, audit_key=self.audit_key)
                cl.log_event(
                    request_id=request_id,
                    user_id=user_id,
                    role=role,
                    direction=direction,
                    category=category,
                    policy_id=policy_id,
                    action=action,
                    score=score,
                    matched_value=matched_value,
                    latency_ms=latency_ms,
                    stage_latencies=stage_latencies,
                )
            except Exception as ce:
                logger.debug("Chain audit mirror skipped: %s", ce)
        except Exception as e:
            # We never print the matched_value even in logger exceptions
            logger.error(f"Failed to write audit event for category {category}: {e}")

    def get_events(self, limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent events for UI dashboard (already privacy-masked)."""
        with self._get_connection() as conn:
            if category:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE category = ? ORDER BY ts DESC LIMIT ?",
                    (category, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY ts DESC LIMIT ?",
                    (limit,)
                ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate KPI statistics for the dashboard."""
        with self._get_connection() as conn:
            total_reqs = conn.execute("SELECT COUNT(DISTINCT request_id) FROM audit_events").fetchone()[0]
            total_incidents = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE action IN ('block', 'mask', 'require_approval', 'redact')"
            ).fetchone()[0]
            total_blocked = conn.execute("SELECT COUNT(*) FROM audit_events WHERE action = 'block'").fetchone()[0]
            total_masked = conn.execute("SELECT COUNT(*) FROM audit_events WHERE action = 'mask'").fetchone()[0]
            total_access_denied = conn.execute(
                "SELECT COUNT(*) FROM audit_events WHERE category = 'access_denied'"
            ).fetchone()[0]

            avg_lat = conn.execute("SELECT AVG(latency_ms) FROM audit_events").fetchone()[0] or 0.0

            # Categories count
            cat_rows = conn.execute(
                "SELECT category, COUNT(*) as cnt FROM audit_events GROUP BY category ORDER BY cnt DESC"
            ).fetchall()
            categories = {r["category"]: r["cnt"] for r in cat_rows}

            # Actions count
            act_rows = conn.execute(
                "SELECT action, COUNT(*) as cnt FROM audit_events GROUP BY action ORDER BY cnt DESC"
            ).fetchall()
            actions = {r["action"]: r["cnt"] for r in act_rows}

            # Direction count
            dir_rows = conn.execute(
                "SELECT direction, COUNT(*) as cnt FROM audit_events GROUP BY direction ORDER BY cnt DESC"
            ).fetchall()
            directions = {r["direction"]: r["cnt"] for r in dir_rows}

            # Risky users
            user_rows = conn.execute(
                """SELECT user_id, COUNT(*) as cnt FROM audit_events 
                   WHERE action IN ('block', 'mask', 'require_approval') 
                   GROUP BY user_id ORDER BY cnt DESC LIMIT 5"""
            ).fetchall()
            risky_users = {r["user_id"]: r["cnt"] for r in user_rows}

            return {
                "total_requests": total_reqs,
                "total_incidents": total_incidents,
                "total_blocked": total_blocked,
                "total_masked": total_masked,
                "total_access_denied": total_access_denied,
                "avg_latency_ms": round(avg_lat, 2),
                "categories": categories,
                "actions": actions,
                "directions": directions,
                "risky_users": risky_users
            }
