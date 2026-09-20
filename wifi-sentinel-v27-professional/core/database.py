import sqlite3
from config import DB

def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def latest_assessment_rows(c):
    """Return the complete AP dataset for the latest stored assessment."""
    scan = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    if not scan:
        return None, []
    rows = [dict(x) for x in c.execute(
        "SELECT * FROM observations WHERE scan_id=? ORDER BY risk DESC, ssid COLLATE NOCASE, bssid",
        (scan["id"],)
    )]
    return scan, rows


def recently_observed_assets(c, latest_scan_id=None, assessment_window=10):
    """Return the most recently seen AP record for each BSSID from recent prior assessments.

    These records are explicitly historical: they are never treated as live in the
    current assessment. This preserves useful wireless-environment history without
    inventing current detections when the sensor reports a smaller live snapshot.
    """
    if latest_scan_id is None:
        row = c.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        latest_scan_id = row["id"] if row else None
    if latest_scan_id is None:
        return []
    start_id = max(1, int(latest_scan_id) - max(1, int(assessment_window)) + 1)
    rows = c.execute("""
        SELECT o.*, s.finished_at AS assessment_finished_at
        FROM observations o
        JOIN scans s ON s.id=o.scan_id
        WHERE o.scan_id < ? AND o.scan_id >= ?
          AND o.bssid NOT IN (SELECT bssid FROM observations WHERE scan_id=?)
          AND o.id = (
              SELECT o2.id FROM observations o2
              WHERE o2.bssid=o.bssid AND o2.scan_id < ? AND o2.scan_id >= ?
              ORDER BY o2.scan_id DESC, o2.id DESC LIMIT 1
          )
        ORDER BY o.observed_at DESC, o.risk DESC, o.ssid COLLATE NOCASE, o.bssid
    """, (latest_scan_id, start_id, latest_scan_id, latest_scan_id, start_id)).fetchall()
    return [dict(r) for r in rows]
