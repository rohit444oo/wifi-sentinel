
from flask import Flask, render_template, redirect, url_for, request, send_file, flash, jsonify, session
from datetime import datetime
from config import BASE, DB, SECRET_KEY, ADMIN_USER, ADMIN_PASS
from core.database import db, latest_assessment_rows, recently_observed_assets
from utils.network import vendor_for, clean_bssid, normalize_security, signal_int
from scanner.wireless import discover as _discover, fresh_windows_scan
from detection.engine import assess as _assess_engine
from services.posture import SECURITY_POLICY, posture_for, trust_score, enrich_trust
from clients.inventory import lan_visible_clients

from pathlib import Path
import csv, io, json, os, platform, re, sqlite3, subprocess, time, ipaddress, socket, concurrent.futures, hashlib

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ---------------- Authentication ----------------
def logged_in():
    return bool(session.get("user"))

def role():
    return session.get("role", "viewer")

def can_modify():
    return role() in {"admin", "analyst"}

@app.context_processor
def auth_context():
    return {"logged": logged_in(), "user_role": role(), "current_user": session.get("user")}

# ---------------- Database ----------------
def db():
    c = sqlite3.connect(DB, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    c.execute("PRAGMA journal_mode=WAL")
    return c

def init_db():
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS approved_aps(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ssid TEXT NOT NULL,
      bssid TEXT NOT NULL UNIQUE,
      security TEXT NOT NULL,
      note TEXT DEFAULT '',
      added_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      started_at TEXT NOT NULL,
      finished_at TEXT NOT NULL,
      ap_count INTEGER NOT NULL,
      flagged_count INTEGER NOT NULL,
      max_risk INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS observations(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      ssid TEXT NOT NULL,
      bssid TEXT NOT NULL,
      channel INTEGER,
      signal TEXT,
      security TEXT,
      vendor TEXT,
      status TEXT,
      risk INTEGER,
      level TEXT,
      reason TEXT,
      changed TEXT DEFAULT '',
      observed_at TEXT NOT NULL,
      fingerprint_score INTEGER DEFAULT 0,
      anomaly_score INTEGER DEFAULT 0,
      identity_risk INTEGER DEFAULT 0,
      security_risk INTEGER DEFAULT 0,
      baseline_risk INTEGER DEFAULT 0,
      behavior_risk INTEGER DEFAULT 0,
      fingerprint_risk INTEGER DEFAULT 0,
      band TEXT DEFAULT '',
      radio TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS alerts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER,
      bssid TEXT,
      severity TEXT,
      title TEXT,
      message TEXT,
      created_at TEXT NOT NULL,
      acknowledged INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS baseline(
      bssid TEXT PRIMARY KEY,
      ssid TEXT,
      channel INTEGER,
      security TEXT,
      vendor TEXT,
      signal INTEGER,
      first_seen TEXT,
      last_seen TEXT,
      seen_count INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS sensors(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      location TEXT,
      last_seen TEXT
    );
    CREATE TABLE IF NOT EXISTS incidents(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_key TEXT UNIQUE,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Open',
      bssid TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      evidence_json TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS network_devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL,
      mac TEXT DEFAULT '',
      hostname TEXT DEFAULT '',
      vendor TEXT DEFAULT '',
      source TEXT DEFAULT 'LAN',
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      seen_count INTEGER DEFAULT 1,
      UNIQUE(ip,mac)
    );
    CREATE TABLE IF NOT EXISTS incident_evidence(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      incident_id INTEGER NOT NULL,
      evidence_type TEXT NOT NULL,
      content TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      captured_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scan_evidence(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_id INTEGER NOT NULL,
      evidence_type TEXT NOT NULL,
      content TEXT NOT NULL,
      sha256 TEXT NOT NULL,
      captured_at TEXT NOT NULL
    );
    """)
    # Lightweight schema migration for databases created by earlier versions.
    existing_cols = {row["name"] for row in c.execute("PRAGMA table_info(observations)")}
    baseline_cols = {row["name"] for row in c.execute("PRAGMA table_info(baseline)")}
    for col, definition in {"band": "TEXT DEFAULT ''", "radio": "TEXT DEFAULT ''"}.items():
        if col not in baseline_cols:
            c.execute(f"ALTER TABLE baseline ADD COLUMN {col} {definition}")
    migrations = {
        "fingerprint_score": "INTEGER DEFAULT 0",
        "anomaly_score": "INTEGER DEFAULT 0",
        "identity_risk": "INTEGER DEFAULT 0",
        "security_risk": "INTEGER DEFAULT 0",
        "baseline_risk": "INTEGER DEFAULT 0",
        "behavior_risk": "INTEGER DEFAULT 0",
        "fingerprint_risk": "INTEGER DEFAULT 0",
        "band": "TEXT DEFAULT ''",
        "radio": "TEXT DEFAULT ''",
    }
    for col, definition in migrations.items():
        if col not in existing_cols:
            c.execute(f"ALTER TABLE observations ADD COLUMN {col} {definition}")
    c.commit(); c.close()







# ---------------- Nearby device discovery ----------------
def local_subnet():
    """Return the connected IPv4 /24 network when available."""
    if platform.system() == "Windows":
        try:
            out=subprocess.run(["ipconfig"],capture_output=True,text=True,encoding="utf-8",errors="ignore",timeout=8).stdout
            ips=re.findall(r"IPv4[^:]*:\s*([0-9.]+)",out,re.I)
            for ip in ips:
                if ip.startswith(("127.","169.254.")): continue
                return ipaddress.ip_network(f"{ip}/24",strict=False)
        except Exception: pass
    try:
        ip=socket.gethostbyname(socket.gethostname())
        if not ip.startswith("127."):
            return ipaddress.ip_network(f"{ip}/24",strict=False)
    except Exception: pass
    return None

def arp_neighbors():
    rows=[]
    try:
        cmd=["arp","-a"] if platform.system()=="Windows" else ["ip","neigh"]
        out=subprocess.run(cmd,capture_output=True,text=True,encoding="utf-8",errors="ignore",timeout=8).stdout
        for line in out.splitlines():
            m=re.search(r"(\d{1,3}(?:\.\d{1,3}){3}).*?([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",line)
            if m:
                ip=m.group(1); mac=clean_bssid(m.group(2))
                try: hostname=socket.gethostbyaddr(ip)[0]
                except Exception: hostname=""
                rows.append({"ip":ip,"mac":mac,"hostname":hostname,"vendor":vendor_for(mac),"source":"ARP"})
    except Exception: pass
    return rows

def ping_host(ip):
    try:
        if platform.system()=="Windows":
            cmd=["ping","-n","1","-w","250",str(ip)]
        else:
            cmd=["ping","-c","1","-W","1",str(ip)]
        r=subprocess.run(cmd,capture_output=True,text=True,encoding="utf-8",errors="ignore",timeout=2)
        return r.returncode==0
    except Exception: return False


def soc_snapshot():
    """Return a compact real-time SOC snapshot without triggering a new scan."""
    try:
        c = db()
        scans = c.execute(
            "SELECT id, started_at, finished_at, max_risk AS risk FROM scans ORDER BY id DESC LIMIT 20"
        ).fetchall()
        alerts = c.execute(
            "SELECT id, severity, title, message, created_at FROM alerts "
            "ORDER BY id DESC LIMIT 12"
        ).fetchall()
        devices = c.execute(
            "SELECT ip, mac, hostname, vendor, last_seen FROM network_devices "
            "ORDER BY last_seen DESC LIMIT 200"
        ).fetchall()
        c.close()
    except Exception:
        scans, alerts, devices = [], [], []

    latest_risk = int(scans[0]["risk"]) if scans else 0
    return {
        "risk": latest_risk,
        "scans": [dict(x) for x in scans],
        "alerts": [dict(x) for x in alerts],
        "devices": [dict(x) for x in devices],
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


@app.get("/api/soc")
def api_soc():
    if "user" not in session:
        return jsonify({"error": "authentication required"}), 401
    return jsonify(soc_snapshot())


def discover_network_devices(active_probe=False):
    """
    Fast LAN device discovery.

    Default behaviour is ARP/cache-first so dashboard pages do not block while
    probing an entire /24 network. Active subnet discovery is opt-in.
    """
    devices = []

    def add_device(ip, mac, hostname="", vendor="", source="ARP"):
        if not ip:
            return
        mac = (mac or "").upper()
        devices.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname or "",
            "vendor": vendor or "Unknown",
            "source": source,
            "first_seen": datetime.now().isoformat(timespec="seconds"),
            "last_seen": datetime.now().isoformat(timespec="seconds"),
        })

    # Windows ARP cache is fast and does not actively probe the whole subnet.
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        for line in out.stdout.splitlines():
            m = re.search(
                r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
                line
            )
            if m:
                ip = m.group(1)
                mac = m.group(2).replace("-", ":")
                if not ip.startswith(("224.", "239.", "255.")):
                    add_device(ip, mac, source="ARP cache")
    except Exception:
        pass

    # Include the local gateway when Windows exposes it in the ARP table.
    # Active discovery is deliberately opt-in.
    if active_probe:
        try:
            import ipaddress
            local = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            ).stdout

            ipv4 = re.findall(
                r"(?:IPv4 Address|IPv4 Address\.)[^:]*:\s*(\d{1,3}(?:\.\d{1,3}){3})",
                local,
                flags=re.I,
            )

            seen_ips = {d["ip"] for d in devices}
            for ip in ipv4[:2]:
                try:
                    addr = ipaddress.ip_address(ip)
                    network = ipaddress.ip_network(f"{addr}/24", strict=False)
                except Exception:
                    continue

                # Parallelize active discovery using a bounded thread pool
                # to avoid blocking the HTTP request handler for 30+ seconds.
                def _probe(target_ip):
                    try:
                        subprocess.run(
                            ["ping", "-n", "1", "-w", "150", target_ip],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=0.35,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                    except Exception:
                        pass

                targets = [
                    str(h) for h in list(network.hosts())[:254]
                    if str(h) not in seen_ips and str(h) != ip
                ]
                with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
                    list(executor.map(_probe, targets))

                # Refresh ARP cache after the explicit probe.
                try:
                    refreshed = subprocess.run(
                        ["arp", "-a"],
                        capture_output=True,
                        text=True,
                        timeout=3,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    ).stdout
                    for line in refreshed.splitlines():
                        m = re.search(
                            r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+"
                            r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+\w+",
                            line
                        )
                        if m:
                            host_ip = m.group(1)
                            mac = m.group(2).replace("-", ":")
                            if host_ip not in seen_ips and not host_ip.startswith(("224.", "239.", "255.")):
                                add_device(host_ip, mac, source="Active ARP discovery")
                                seen_ips.add(host_ip)
                except Exception:
                    pass
        except Exception:
            pass

    # Deduplicate and persist without failing the dashboard.
    unique = {}
    for d in devices:
        key = (d["ip"], d["mac"])
        unique[key] = d

    result = list(unique.values())
    try:
        c = db()
        for d in result:
            c.execute(
                """INSERT INTO network_devices
                   (ip,mac,hostname,vendor,source,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(ip,mac) DO UPDATE SET
                     hostname=excluded.hostname,
                     vendor=excluded.vendor,
                     source=excluded.source,
                     last_seen=excluded.last_seen""",
                (
                    d["ip"], d["mac"], d["hostname"], d["vendor"],
                    d["source"], d["first_seen"], d["last_seen"]
                )
            )
        c.commit()
        c.close()
    except Exception:
        pass

    subnet = local_subnet()
    return result, str(subnet) if subnet else None







# ---------------- Risk + baseline engine ----------------






def save_results(results):
    c = db()
    started = datetime.now().isoformat(timespec="seconds")
    now = started
    flagged = sum(x["status"] != "Authorized" for x in results)
    maxrisk = max([x["risk"] for x in results], default=0)
    cur = c.execute(
        "INSERT INTO scans(started_at,finished_at,ap_count,flagged_count,max_risk) VALUES(?,?,?,?,?)",
        (started, now, len(results), flagged, maxrisk)
    )
    scan_id = cur.lastrowid

    # Preserve a tamper-evident snapshot of the discovery result for assessment evidence.
    snapshot = json.dumps(results, sort_keys=True, default=str)
    digest = hashlib.sha256(snapshot.encode()).hexdigest()
    c.execute(
        "INSERT INTO scan_evidence(scan_id,evidence_type,content,sha256,captured_at) VALUES(?,?,?,?,?)",
        (scan_id, "discovery_snapshot", snapshot, digest, now)
    )

    for x in results:
        c.execute(
            """INSERT INTO observations
            (scan_id,ssid,bssid,channel,signal,security,vendor,status,risk,level,reason,changed,
             observed_at,fingerprint_score,anomaly_score,identity_risk,security_risk,baseline_risk,
             behavior_risk,fingerprint_risk,band,radio)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_id, x.get("ssid","<hidden>"), x["bssid"], x.get("channel"), x.get("signal","N/A"),
                x["security"], x["vendor"], x["status"], x["risk"], x["level"], x["reason"],
                x["changed"], now, x.get("fingerprint_score",0), x.get("anomaly_score",0),
                x.get("identity_risk",0), x.get("security_risk",0), x.get("baseline_risk",0),
                x.get("behavior_risk",0), x.get("fingerprint_risk",0), x.get("band",""), x.get("radio","")
            )
        )

                # Unverified status alone is an inventory state, not a security event.
        # Create a fallback alert only when meaningful security evidence exists.
        meaningful = (
            x.get("spoof_indicator")
            or int(x.get("risk", 0) or 0) >= 40
            or bool(x.get("changed"))
            or str(x.get("security", "")).upper() in ("OPEN", "WEP")
            or int(x.get("anomaly_score", 0) or 0) >= 40
        )
        if meaningful and (
            int(x.get("risk", 0) or 0) >= 65
            or x.get("spoof_indicator")
            or bool(x.get("changed"))
            or str(x.get("security", "")).upper() in ("OPEN", "WEP")
        ):
            severity = x["level"]
            c.execute(
                """INSERT INTO alerts(scan_id,bssid,severity,title,message,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (
                    scan_id, x["bssid"], severity,
                    f"{severity} wireless finding",
                    f"{x['ssid']} ({x['bssid']}): {x['reason']}",
                    now
                )
            )

        sig = signal_int(x.get("signal"))
        existing = c.execute("SELECT * FROM baseline WHERE bssid=?", (x["bssid"],)).fetchone()
        if existing:
            c.execute(
                """UPDATE baseline SET ssid=?,channel=?,security=?,vendor=?,signal=?,
                   band=?,radio=?,last_seen=?,seen_count=seen_count+1 WHERE bssid=?""",
                (x.get("ssid"), x.get("channel"), x["security"], x["vendor"], sig,
                 x.get("band",""), x.get("radio",""), now, x["bssid"])
            )
        else:
            c.execute(
                """INSERT INTO baseline
                   (bssid,ssid,channel,security,vendor,signal,band,radio,first_seen,last_seen,seen_count)
                   VALUES(?,?,?,?,?,?,?,?,?,?,1)""",
                (x["bssid"], x.get("ssid"), x.get("channel"), x["security"], x["vendor"], sig,
                 x.get("band",""), x.get("radio",""), now, now)
            )

    c.commit()
    c.close()
    return scan_id

# ---------------- Security posture / policy / correlation ----------------







def discover():
    return _discover(clean_bssid, normalize_security)

def assess(rows):
    return _assess_engine(rows, db, clean_bssid, normalize_security, signal_int, vendor_for, enrich_trust)

# ---------------- Routes ----------------
# ---------------- Authentication Routes ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        credentials = {
            ADMIN_USER: ADMIN_PASS,
            "analyst": os.environ.get("WIFI_ANALYST_PASS", "analyst"),
            "viewer": os.environ.get("WIFI_VIEWER_PASS", "viewer"),
        }
        if username in credentials and password == credentials[username]:
            session["user"] = username
            session["role"] = username
            return redirect("/")
        flash("Invalid username or password", "error")
    return render_template("login.html")

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/soc")
def soc_dashboard_v20():
    if "user" not in session:
        return redirect("/login")
    return render_template("soc_v20.html", user=session.get("user"), user_role=role())


@app.get("/api/soc/v20")
def api_soc_v20():
    if "user" not in session:
        return jsonify({"error": "authentication required"}), 401

    data = {
        "risk": 0,
        "aps": 0,
        "trusted": 0,
        "untrusted": 0,
        "devices": 0,
        "alerts": [],
        "scans": [],
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }

    try:
        c = db()

        # Discover table names dynamically so the SOC remains compatible with
        # the existing Sentinel database schema.
        tables = {
            r[0] for r in c.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }

        if "scans" in tables:
            rows = c.execute(
                "SELECT id, started_at, finished_at, max_risk AS risk FROM scans ORDER BY id DESC LIMIT 20"
            ).fetchall()
            data["scans"] = [dict(r) for r in rows]
            if rows:
                data["risk"] = int(rows[0]["risk"] or 0)

        if "alerts" in tables:
            rows = c.execute(
                "SELECT id, severity, title, message, created_at "
                "FROM alerts ORDER BY id DESC LIMIT 15"
            ).fetchall()
            data["alerts"] = [dict(r) for r in rows]

        if "network_devices" in tables:
            data["devices"] = c.execute(
                "SELECT COUNT(*) FROM network_devices"
            ).fetchone()[0]

        # AP counts from the latest observation-like table when available.
        for candidate in ("observations", "aps", "access_points"):
            if candidate in tables:
                try:
                    cols = {r[1] for r in c.execute(
                        f"PRAGMA table_info({candidate})"
                    ).fetchall()}
                    if "bssid" in cols:
                        data["aps"] = c.execute(
                            f"SELECT COUNT(DISTINCT bssid) FROM {candidate}"
                        ).fetchone()[0]
                        break
                except Exception:
                    pass

        c.close()
    except Exception:
        pass

    data["trusted"] = 0
    try:
        c = db()
        tables = {r[0] for r in c.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        for candidate in ("inventory", "approved_aps", "trusted_aps"):
            if candidate in tables:
                data["trusted"] = c.execute(
                    f"SELECT COUNT(*) FROM {candidate}"
                ).fetchone()[0]
                break
        c.close()
    except Exception:
        pass

    data["untrusted"] = max(0, int(data["aps"]) - int(data["trusted"]))
    return jsonify(data)


@app.route("/")
def index():
    c = db()
    latest_scan, obs = latest_assessment_rows(c)
    recent_assets = recently_observed_assets(c, latest_scan["id"] if latest_scan else None, 10)
    approved = [dict(x) for x in c.execute("SELECT * FROM approved_aps ORDER BY ssid")]
    alerts = [dict(x) for x in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 8")]
    scans = [dict(x) for x in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")]
    c.close()
    # Rehydrate calculated security intelligence for dashboard-only fields.
    for x in obs:
        x["security"] = normalize_security(x.get("security"))
        x["anomaly_score"] = int(x.get("anomaly_score") or 0)
        x["fingerprint_score"] = int(x.get("fingerprint_score") or 0)
        x["trust_score"] = trust_score(x)
        x["policy_label"] = SECURITY_POLICY.get(x["security"], SECURITY_POLICY["UNKNOWN"])["label"]
    c=db(); device_count=c.execute("SELECT COUNT(*) n FROM network_devices").fetchone()["n"]; sensor_count=c.execute("SELECT COUNT(*) n FROM sensors").fetchone()["n"]; c.close()
    stats={"has_scan": bool(scans),"observations":len(obs),"authorized":sum(x["status"]=="Authorized" for x in obs),
           "flagged":sum(x["status"]!="Authorized" for x in obs),"max_risk":max([x["risk"] for x in obs],default=0),
           "critical":sum(x["level"]=="Critical" for x in obs),"high":sum(x["level"]=="High" for x in obs),
           "medium":sum(x["level"]=="Medium" for x in obs),"low":sum(x["level"]=="Low" for x in obs),
           "latest_scan_id": scans[0]["id"] if scans else None}
    return render_template("index.html", observations=obs, recent_assets=recent_assets, approved=approved, alerts=alerts, scans=scans, stats=stats, device_count=device_count, sensor_count=sensor_count,
                           logged=logged_in(), user=session.get("user"), user_role=role())


def alert_already_open(bssid, title):
    c=db()
    row=c.execute("""SELECT id FROM alerts
                     WHERE bssid=? AND title=? AND acknowledged=0
                     ORDER BY id DESC LIMIT 1""",(bssid,title)).fetchone()
    c.close()
    return bool(row)

def correlated_alerts(alerts_list):
    """Collapse duplicate alerts for the same BSSID and title."""
    priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    unique = {}
    for alert in alerts_list or []:
        bssid = clean_bssid(alert.get("bssid", ""))
        title = (alert.get("title") or "").strip().lower()
        key = (bssid, title)
        current = unique.get(key)
        if current is None:
            unique[key] = dict(alert)
        else:
            if priority.get(alert.get("severity", "Low"), 0) > priority.get(current.get("severity", "Low"), 0):
                unique[key] = dict(alert)
    return list(unique.values())


def classify_ap_status(ap, approved):
    bssid = clean_bssid(ap.get("bssid"))
    ssid = (ap.get("ssid") or "").strip().lower()
    approved_map = {clean_bssid(x.get("bssid")): x for x in (approved or [])}
    if bssid in approved_map:
        return "Authorized"
    approved_ssids = {(x.get("ssid") or "").strip().lower() for x in (approved or []) if x.get("ssid")}
    if ssid and ssid in approved_ssids:
        return "Suspicious"
    return "Unapproved"


def fingerprint_similarity(a, b):
    if not a or not b:
        return 0.0
    weights = {"ssid": 0.3, "vendor": 0.2, "security": 0.2, "channel": 0.15, "signal": 0.15}
    score = 0.0
    if (a.get("ssid") or "").strip().lower() == (b.get("ssid") or "").strip().lower():
        score += weights["ssid"]
    if (a.get("vendor") or "").strip().lower() == (b.get("vendor") or "").strip().lower():
        score += weights["vendor"]
    if normalize_security(a.get("security")) == normalize_security(b.get("security")):
        score += weights["security"]
    if a.get("channel") == b.get("channel"):
        score += weights["channel"]
    sig_a, sig_b = signal_int(a.get("signal")), signal_int(b.get("signal"))
    if sig_a is not None and sig_b is not None:
        diff = abs(sig_a - sig_b)
        score += weights["signal"] * max(0.0, 1.0 - diff / 100.0)
    elif sig_a == sig_b:
        score += weights["signal"]
    return score



def advanced_alerts(results, previous=None, current=None):
    """Build concise, de-duplicated alert candidates without assuming a container shape."""
    previous = previous or {}

    if isinstance(previous, dict):
        previous_rows = list(previous.values())
    elif isinstance(previous, (list, tuple, set)):
        previous_rows = [x for x in previous if isinstance(x, dict)]
    else:
        previous_rows = []

    previous_map = {
        clean_bssid(x.get("bssid")): x
        for x in previous_rows
        if x.get("bssid")
    }

    if isinstance(results, dict):
        result_rows = list(results.values())
    elif isinstance(results, (list, tuple, set)):
        result_rows = [x for x in results if isinstance(x, dict)]
    else:
        result_rows = []

    out=[]
    for x in result_rows:
        bssid=clean_bssid(x.get("bssid"))
        if not bssid:
            continue

        ssid=x.get("ssid") or "<hidden>"
        risk=int(x.get("risk",0) or 0)
        level=x.get("level") or (
            "Critical" if risk>=85 else
            "High" if risk>=65 else
            "Medium" if risk>=40 else "Low"
        )
        status=x.get("status","Untrusted")
        reasons=[]

        if x.get("spoof_indicator"):
            reasons.append("possible SSID spoof")
        if x.get("changed"):
            reasons.append("baseline change: "+str(x["changed"]))
        if int(x.get("anomaly_score",0) or 0)>=65:
            reasons.append("historical behavioral anomaly")
        if int(x.get("fingerprint_score",0) or 0)<65:
            reasons.append("fingerprint deviation")
        if str(x.get("security","")).upper() in ("OPEN","WEP"):
            reasons.append("weak/absent encryption")

        is_new=bssid not in previous_map
        if is_new:
            reasons.append("first observation for this AP")

        meaningful = (
            x.get("spoof_indicator") or risk >= 40 or bool(x.get("changed")) or
            str(x.get("security","")).upper() in ("OPEN","WEP") or
            int(x.get("anomaly_score",0) or 0) >= 40
        )
        if status=="Authorized" and risk<65 and not meaningful:
            continue
        if status=="Unverified" and not meaningful:
            continue

        if is_new and status!="Authorized":
            title="New AP detected"
            severity="High" if risk>=65 else level
            message=f"{ssid} ({bssid}) is newly observed."
        elif x.get("spoof_indicator"):
            title="Possible SSID spoof"
            severity="High" if risk>=65 else "Medium"
            message=f"{ssid} ({bssid}) matches a trusted SSID but has a different BSSID."
        elif risk>=65:
            title="High-risk wireless finding"
            severity=level
            message=f"{ssid} ({bssid}) risk score is {risk}/100."
        else:
            title=f"{level} wireless finding"
            severity=level
            message=f"{ssid} ({bssid}): "+(
                "; ".join(reasons) if reasons else "Untrusted AP requires review."
            )

        out.append({
            "bssid":bssid,
            "severity":severity,
            "title":title,
            "message":message
        })

    seen=set()
    unique=[]
    for item in out:
        key=(item["bssid"],item["title"],item["message"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique



def send_notifications(alerts_list):
    """Optional notification hook. Safe no-op unless notification integrations are configured."""
    if not alerts_list:
        return
    # Keep local operation reliable. External email/Telegram integrations can be
    # plugged in later without making the scan pipeline depend on them.
    return None


def deduplicate_alerts(alerts_list):
    """Suppress identical alert fingerprints generated repeatedly by auto-scan."""
    seen = set()
    result = []
    for a in alerts_list or []:
        key = (
            a.get("severity"),
            a.get("title"),
            a.get("bssid") or a.get("message", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(a)
    return result


def persist_new_alerts(scan_id, alerts_list):
    alerts_list = deduplicate_alerts(alerts_list)
    alerts_list = correlated_alerts(alerts_list) if 'correlated_alerts' in globals() else alerts_list
    c = db()
    now = datetime.now().isoformat(timespec="seconds")
    created = []

    for a in alerts_list:
        bssid = clean_bssid(a.get("bssid"))
        title = a.get("title", "").strip()
        message = a.get("message", "").strip()

        row = c.execute(
            """SELECT id, message FROM alerts
               WHERE bssid=? AND title=? AND acknowledged=0
               ORDER BY id DESC LIMIT 1""",
            (bssid, title)
        ).fetchone()

        # Same active finding: do not generate another alert.
        if row and (row["message"] or "") == message:
            continue

        c.execute(
            """INSERT INTO alerts(scan_id,bssid,severity,title,message,created_at)
               VALUES(?,?,?,?,?,?)""",
            (scan_id, bssid, a["severity"], title, message, now)
        )
        created.append(dict(a))

    c.commit()
    c.close()
    return created


def create_incidents_for_alerts(alerts_list=None):
    if not alerts_list:
        return 0
    """Create one investigation record per BSSID for high/critical alerts and preserve evidence."""
    now=datetime.now().isoformat(timespec="seconds")
    c=db()
    for a in alerts_list or []:
        sev=a.get("severity","Low")
        if sev not in ("High","Critical"): continue
        bssid=clean_bssid(a.get("bssid"))
        key=f"{bssid}:{a.get('title','')}"
        existing=c.execute("SELECT id FROM incidents WHERE incident_key=? AND status!='Closed'",(key,)).fetchone()
        if existing: continue
        cur=c.execute("INSERT OR IGNORE INTO incidents(incident_key,title,severity,status,bssid,created_at,updated_at,evidence_json) VALUES(?,?,?,?,?,?,?,?)",(key,a.get("title","Wireless security incident"),sev,"Open",bssid,now,now,json.dumps(a)))
        iid=cur.lastrowid
        if iid:
            obs=c.execute("SELECT * FROM observations WHERE bssid=? ORDER BY id DESC LIMIT 20",(bssid,)).fetchall()
            snapshot=json.dumps([dict(x) for x in obs],default=str)
            digest=hashlib.sha256(snapshot.encode()).hexdigest()
            c.execute("INSERT INTO incident_evidence(incident_id,evidence_type,content,sha256,captured_at) VALUES(?,?,?,?,?)",(iid,"observation_snapshot",snapshot,digest,now))
            alert_snapshot=json.dumps(a,default=str)
            digest2=hashlib.sha256(alert_snapshot.encode()).hexdigest()
            c.execute("INSERT INTO incident_evidence(incident_id,evidence_type,content,sha256,captured_at) VALUES(?,?,?,?,?)",(iid,"alert_snapshot",alert_snapshot,digest2,now))
    c.commit(); c.close()

@app.post("/scan")
def scan():
    if not logged_in() or not can_modify():
        flash("Assessment requires analyst or administrator access.", "error")
        return redirect(url_for("login"))
    c = db()
    prev = {r["bssid"]: dict(r) for r in c.execute("SELECT * FROM baseline")}
    c.close()
    results = assess(discover())
    current = {x["bssid"] for x in results}
    adv = advanced_alerts(results, prev, current)
    sid = save_results(results)
    created_adv = persist_new_alerts(sid, adv)
    c = db()
    # Include alerts created by the risk engine for this scan plus advanced alerts.
    new_alerts = [dict(x) for x in c.execute("SELECT * FROM alerts WHERE scan_id=? ORDER BY id DESC",(sid,))]
    c.close()
    send_notifications(new_alerts)
    create_incidents_for_alerts(new_alerts)
    flash(f"Scan #{sid} complete: {len(results)} APs observed, {len(new_alerts)} alerts generated.")
    return redirect("/")


def dashboard_enrich(obs):
    for x in obs:
        x["security"] = normalize_security(x.get("security"))
        x["trust_score"] = trust_score(x)
        x["policy_label"] = SECURITY_POLICY.get(
            x["security"], SECURITY_POLICY["UNKNOWN"]
        )["label"]
        x["fingerprint_score"] = int(x.get("fingerprint_score") or 0)
        x["anomaly_score"] = int(x.get("anomaly_score") or x.get("anomaly") or 0)
    return obs


@app.get("/access-points")
def access_points():
    """Display every AP from the latest completed assessment, with no UI truncation."""
    c = db()
    scan, rows = latest_assessment_rows(c)
    recent_assets = recently_observed_assets(c, scan["id"] if scan else None, 10)
    approved=[dict(x) for x in c.execute("SELECT * FROM approved_aps ORDER BY ssid")]
    c.close()
    dashboard_enrich(rows)
    dashboard_enrich(recent_assets)
    for x in rows:
        x["confidence"]=96 if x.get("status")=="Authorized" else min(98,35+int(x.get("evidence_count",0))*9)
    for x in recent_assets:
        x["last_seen"]=x.get("observed_at") or x.get("assessment_finished_at")
        x["historical_status"]="Recently Observed"
    return render_template("access_points.html", rows=rows, recent_assets=recent_assets, scan=dict(scan) if scan else None, approved=approved)

@app.get("/api/access-points")
def api_access_points():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    c = db()
    scan, rows = latest_assessment_rows(c)
    c.close(); dashboard_enrich(rows)
    return jsonify({"scan":dict(scan) if scan else None,"count":len(rows),"access_points":rows})

@app.get("/lab")
def assessment_lab():
    if not logged_in(): return redirect(url_for("login"))
    return render_template("lab.html")

@app.post("/api/lab/simulate")
def simulate_assessment():
    if not logged_in() or not can_modify(): return jsonify({"error":"analyst or administrator access required"}),403
    data=request.get_json(silent=True) or {}; scenario=(data.get("scenario") or "ssid_spoof").strip()
    scenarios={
        "ssid_spoof":{"ssid":"Corporate-WiFi","bssid":"12:34:56:78:9A:BC","security":"WPA2","channel":11,"signal":"-32 dBm","band":"2.4 GHz","radio":"802.11n"},
        "security_downgrade":{"ssid":"Corporate-WiFi","bssid":"12:34:56:78:9A:BD","security":"OPEN","channel":6,"signal":"-40 dBm","band":"2.4 GHz","radio":"802.11ax"},
        "fingerprint_deviation":{"ssid":"Corporate-WiFi","bssid":"12:34:56:78:9A:BE","security":"WPA2","channel":13,"signal":"-25 dBm","band":"5 GHz","radio":"802.11n"},
        "behavior_anomaly":{"ssid":"Corporate-WiFi","bssid":"12:34:56:78:9A:BF","security":"WPA2","channel":1,"signal":"-15 dBm","band":"2.4 GHz","radio":"802.11n"},
    }
    raw=scenarios.get(scenario)
    if not raw: return jsonify({"error":"unknown scenario"}),400
    result=assess([raw])[0]
    return jsonify({"scenario":scenario,"assessment":result,"simulation":True})

@app.get("/history")
def history():
    c=db(); scans=[dict(x) for x in c.execute("SELECT * FROM scans ORDER BY id DESC")]; c.close()
    return render_template("history.html", scans=scans)

@app.get("/ap/<bssid>")
def ap_detail(bssid):
    bssid = clean_bssid(bssid)
    c = db()
    rows = [dict(x) for x in c.execute(
        "SELECT * FROM observations WHERE bssid=? ORDER BY id DESC LIMIT 80", (bssid,)
    )]
    base = c.execute("SELECT * FROM baseline WHERE bssid=?", (bssid,)).fetchone()
    approved = c.execute("SELECT * FROM approved_aps WHERE bssid=?", (bssid,)).fetchone()
    related_alerts = [dict(x) for x in c.execute(
        "SELECT * FROM alerts WHERE bssid=? ORDER BY id DESC LIMIT 30", (bssid,)
    )]
    client_assets = lan_visible_clients(c, 200)
    approved_ssids = {
        (a["ssid"] or "").strip().lower()
        for a in c.execute("SELECT ssid FROM approved_aps")
    }
    c.close()

    latest = rows[0] if rows else {}
    previous = rows[1:] if len(rows) > 1 else []
    channel_changes = sum(1 for x in previous if x.get("channel") != latest.get("channel"))
    security_changes = sum(
        1 for x in previous if normalize_security(x.get("security")) != normalize_security(latest.get("security"))
    )
    signal_values = [signal_int(x.get("signal")) for x in rows if signal_int(x.get("signal")) is not None]

    profile = {
        "ssid": latest.get("ssid", "<hidden>"),
        "bssid": bssid,
        "vendor": latest.get("vendor") or vendor_for(bssid),
        "channel": latest.get("channel"),
        "signal": latest.get("signal", "N/A"),
        "security": normalize_security(latest.get("security")),
        "status": latest.get("status", "Unknown"),
        "risk": int(latest.get("risk", 0)),
        "level": latest.get("level", "Low"),
        "trust": trust_score(latest) if latest else 0,
        "fingerprint": int(latest.get("fingerprint_score", 0) or 0),
        "anomaly": int(latest.get("anomaly_score", 0) or 0),
        "confidence": (96 if latest.get("status") == "Authorized" else min(98, 35 + 12 * sum(bool(v) for v in [
            latest.get("status") in ("Suspicious", "Possible Rogue", "Configuration Mismatch"),
            bool(latest.get("changed")),
            normalize_security(latest.get("security")) in ("OPEN", "WEP", "WPA"),
            int(latest.get("fingerprint_risk", 0) or 0) >= 25,
            int(latest.get("behavior_risk", 0) or 0) >= 20,
        ]))),
        "spoof": bool(latest.get("spoof_indicator") or (
            approved is None and (latest.get("ssid") or "").strip().lower() in approved_ssids
        )) if latest else False,
        "first_seen": base["first_seen"] if base else (rows[-1].get("observed_at") if rows else "—"),
        "last_seen": base["last_seen"] if base else (latest.get("observed_at") if latest else "—"),
        "seen_count": int(base["seen_count"]) if base else len(rows),
        "channel_changes": channel_changes,
        "security_changes": security_changes,
        "signal_min": min(signal_values) if signal_values else None,
        "signal_max": max(signal_values) if signal_values else None,
        "risk_breakdown": {
            "Identity": int(latest.get("identity_risk", 0) or 0),
            "Security": int(latest.get("security_risk", 0) or 0),
            "Baseline": int(latest.get("baseline_risk", 0) or 0),
            "Behavior": int(latest.get("behavior_risk", 0) or 0),
            "Fingerprint": int(latest.get("fingerprint_risk", 0) or 0),
        },
        "decision_indicators": [
            ("Authorization", "Authorized" if approved else "Not in approved inventory", bool(approved)),
            ("SSID impersonation", "Detected" if (latest.get("spoof_indicator") or (approved is None and (latest.get("ssid") or "").strip().lower() in approved_ssids)) else "Not detected", bool(latest.get("spoof_indicator") or (approved is None and (latest.get("ssid") or "").strip().lower() in approved_ssids))),
            ("Security exposure", "Weak or legacy security observed" if normalize_security(latest.get("security")) in ("OPEN", "WEP", "WPA") else "No weak-security indicator", normalize_security(latest.get("security")) in ("OPEN", "WEP", "WPA")),
            ("Baseline deviation", "Detected" if int(latest.get("baseline_risk", 0) or 0) > 0 else "Not detected", int(latest.get("baseline_risk", 0) or 0) > 0),
            ("Behavioral deviation", "Detected" if int(latest.get("behavior_risk", 0) or 0) > 0 else "Not detected", int(latest.get("behavior_risk", 0) or 0) > 0),
            ("Profile consistency", f"{int(latest.get('fingerprint_score', 0) or 0)}% match", int(latest.get("fingerprint_risk", 0) or 0) > 0),
        ],
        "client_visibility": "LAN-visible client telemetry; AP association is not available from the current adapter",
        "client_assets": client_assets,
        "client_count": len(client_assets),
        "deployment_zone": "Not configured"
    }
    return render_template(
        "ap.html",
        profile=profile,
        rows=rows,
        base=dict(base) if base else None,
        alerts=related_alerts,
        approved=dict(approved) if approved else None
    )

@app.get("/api/ap/<bssid>")
def api_ap_detail(bssid):
    bssid = clean_bssid(bssid)
    c = db()
    rows = [dict(x) for x in c.execute(
        "SELECT * FROM observations WHERE bssid=? ORDER BY id ASC LIMIT 100", (bssid,)
    )]
    c.close()
    return jsonify({
        "bssid": bssid,
        "observations": rows,
        "count": len(rows),
        "risk": rows[-1].get("risk", 0) if rows else 0,
        "fingerprint_match": rows[-1].get("fingerprint_score", 0) if rows else 0,
        "anomaly": rows[-1].get("anomaly_score", 0) if rows else 0
    })



@app.get("/incidents")
def incidents():
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM incidents ORDER BY id DESC")]; c.close(); return render_template("incidents.html", incidents=rows)

@app.get("/incident/<int:incident_id>")
def incident_detail(incident_id):
    c=db(); incident=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone(); evidence=[]
    if incident: evidence=[dict(x) for x in c.execute("SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id ASC",(incident_id,))]
    c.close(); return render_template("incident.html", incident=dict(incident) if incident else None, evidence=evidence)

@app.post("/incident/<int:incident_id>/close")
def incident_close(incident_id):
    if not logged_in() or not can_modify():
        flash("Incident updates require analyst or administrator access.", "error")
        return redirect(url_for("login"))
    c=db(); c.execute("UPDATE incidents SET status='Closed',updated_at=? WHERE id=?",(datetime.now().isoformat(timespec="seconds"),incident_id)); c.commit(); c.close(); return redirect(url_for("incident_detail",incident_id=incident_id))

@app.get("/alerts")
def alerts():
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM alerts ORDER BY id DESC")]; c.close()
    return render_template("alerts.html", alerts=rows)

@app.post("/inventory/add")
def inventory_add():
    if not logged_in() or not can_modify():
        flash("Inventory updates require analyst or administrator access.", "error")
        return redirect(url_for("login"))
    ssid=request.form.get("ssid","").strip() or "<hidden>"
    bssid=clean_bssid(request.form.get("bssid")); security=normalize_security(request.form.get("security"))
    note=request.form.get("note","").strip()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", bssid):
        flash("Invalid BSSID format."); return redirect("/")
    c=db()
    try:
        c.execute("INSERT INTO approved_aps(ssid,bssid,security,note,added_at) VALUES(?,?,?,?,?)",
                  (ssid,bssid,security,note,datetime.now().isoformat(timespec="seconds"))); c.commit()
        flash("AP added to approved inventory.")
    except sqlite3.IntegrityError: flash("That BSSID is already in inventory.")
    c.close(); return redirect("/")

@app.post("/inventory/delete/<int:ap_id>")
def inventory_delete(ap_id):
    if not logged_in() or not can_modify():
        flash("Inventory updates require analyst or administrator access.", "error")
        return redirect(url_for("login"))
    c=db(); c.execute("DELETE FROM approved_aps WHERE id=?",(ap_id,)); c.commit(); c.close()
    flash("AP removed."); return redirect("/")


@app.get("/devices")
def devices_page():
    active = request.args.get("active", "0") == "1"
    devices, subnet = discover_network_devices(active_probe=active)
    c=db(); history=[dict(x) for x in c.execute("SELECT * FROM network_devices ORDER BY last_seen DESC LIMIT 200")]; c.close()
    return render_template("devices.html", devices=devices, history=history, subnet=subnet, ap_count=len(discover()))

@app.get("/api/devices")
def api_devices():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    active = request.args.get("active", "0") == "1"
    devices, subnet=discover_network_devices(active_probe=active)
    return jsonify({"subnet":subnet,"count":len(devices),"devices":devices,"note":"LAN-visible devices; Wi-Fi clients outside the local LAN require a monitor-mode capable sensor."})

@app.get("/siem/events.json")
def siem_events():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 500")]; c.close()
    events=[]
    for a in rows:
        events.append({"timestamp":a["created_at"],"event_type":"wireless_security_alert","severity":a["severity"],"title":a["title"],"message":a["message"],"bssid":a["bssid"],"source":"wifi-sentinel"})
    return jsonify(events)

@app.post("/api/sensors/register")
@app.post("/api/sensor/register")
def sensor_register():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    data=request.get_json(silent=True) or {}; name=(data.get("name") or "sensor").strip(); location=(data.get("location") or "unknown").strip(); now=datetime.now().isoformat(timespec="seconds")
    c=db(); c.execute("INSERT INTO sensors(name,location,last_seen) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET location=excluded.location,last_seen=excluded.last_seen",(name,location,now)); c.commit(); c.close()
    return jsonify({"ok":True,"name":name,"location":location,"last_seen":now})

@app.post("/api/sensors/heartbeat")
def sensor_heartbeat():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    data=request.get_json(silent=True) or {}; name=(data.get("name") or "sensor").strip(); now=datetime.now().isoformat(timespec="seconds"); c=db(); c.execute("UPDATE sensors SET last_seen=? WHERE name=?",(now,name)); c.commit(); c.close(); return jsonify({"ok":True,"last_seen":now})

@app.get("/api/sensors")
def sensors_api():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM sensors ORDER BY last_seen DESC")]; c.close(); return jsonify(rows)

@app.get("/api/incidents")
def api_incidents():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM incidents ORDER BY id DESC")]; c.close()
    return jsonify(rows)

@app.get("/executive-report")
def executive_report():
    if not logged_in(): return redirect(url_for("login"))
    c=db(); scan, rows = latest_assessment_rows(c)
    recent_assets = recently_observed_assets(c, scan["id"] if scan else None, 10)
    alerts=[dict(x) for x in c.execute("SELECT * FROM alerts WHERE scan_id=? ORDER BY id DESC",(scan["id"],))] if scan else []
    client_assets=lan_visible_clients(c, 200)
    c.close()
    posture=posture_for(rows)
    summary={"scan":dict(scan) if scan else None,"posture":posture,"total_aps":len(rows),"recent_assets":len(recent_assets),"authorized":sum(x.get("status")=="Authorized" for x in rows),"high_risk":sum(int(x.get("risk",0))>=65 for x in rows),"critical":sum(int(x.get("risk",0))>=85 for x in rows),"alerts":len(alerts),"client_assets":client_assets,"client_count":len(client_assets)}
    return render_template("executive_report.html", summary=summary, rows=rows, recent_assets=recent_assets, alerts=alerts)

@app.get("/export.csv")
def export_csv():
    if not logged_in():
        return redirect(url_for("login"))
    c=db(); scan, latest_rows = latest_assessment_rows(c)
    rows=[tuple(r.get(k) for k in ("scan_id","ssid","bssid","channel","signal","security","vendor","status","risk","level","reason","changed","observed_at")) for r in latest_rows]
    c.close()
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(["Scan","SSID","BSSID","Channel","Signal","Security","Vendor","Status","Risk","Level","Reason","Changes","Observed"])
    w.writerows(rows)
    return send_file(io.BytesIO(out.getvalue().encode()),mimetype="text/csv",as_attachment=True,download_name="wifi_sentinel_report.csv")

def _report_pdf_impl():
    if not logged_in():
        return redirect(url_for("login"))
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    except ImportError:
        flash("Install reportlab with: pip install reportlab")
        return redirect("/")

    c = db()
    scan, latest_rows = latest_assessment_rows(c)
    recent_assets = recently_observed_assets(c, scan["id"] if scan else None, 50)
    client_assets = lan_visible_clients(c, 200)
    alerts = [dict(x) for x in c.execute(
        "SELECT * FROM alerts WHERE scan_id=? ORDER BY id DESC", (scan["id"],)
    )] if scan else []
    c.close()

    latest_rows = [dict(x) for x in latest_rows]
    posture = posture_for(latest_rows)
    total = len(latest_rows)
    authorized = sum(str(x.get("status", "")).lower() == "authorized" for x in latest_rows)
    unverified = sum(str(x.get("status", "")).lower() == "unverified" for x in latest_rows)
    suspicious = sum(str(x.get("status", "")).lower() in ("suspicious", "rogue", "rogue ap candidate") for x in latest_rows)
    high = sum(int(x.get("risk", 0) or 0) >= 65 for x in latest_rows)
    critical = sum(int(x.get("risk", 0) or 0) >= 85 for x in latest_rows)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ---------- visual system ----------
    NAVY = colors.HexColor("#07111B")
    INK = colors.HexColor("#DCEBFA")
    MUTED = colors.HexColor("#8FA6BA")
    LINE = colors.HexColor("#203444")
    SOFT = colors.HexColor("#0E1A26")
    WHITE = colors.white
    BLUE = colors.HexColor("#36B8FF")
    GREEN = colors.HexColor("#42E6A4")
    AMBER = colors.HexColor("#FFC857")
    RED = colors.HexColor("#FF5C7A")

    def risk_color(v):
        v = int(v or 0)
        return RED if v >= 85 else AMBER if v >= 65 else GREEN if v < 35 else BLUE

    def P(text, style):
        return Paragraph(str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>"), style)

    styles = getSampleStyleSheet()
    cover = ParagraphStyle("Cover", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=27, leading=31, textColor=WHITE, spaceAfter=8)
    cover_sub = ParagraphStyle("CoverSub", parent=styles["Normal"], fontSize=10.5, leading=15, textColor=colors.HexColor("#AFC6D9"))
    section = ParagraphStyle("Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=15, leading=18, textColor=INK, spaceBefore=3, spaceAfter=5, borderWidth=0, borderPadding=0)
    section_sub = ParagraphStyle("SectionSub", parent=styles["Normal"], fontSize=8.2, leading=11, textColor=MUTED, spaceAfter=9)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=8.6, leading=13, textColor=INK)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=7.1, leading=9.5, textColor=MUTED)
    tiny = ParagraphStyle("Tiny", parent=styles["BodyText"], fontSize=6.2, leading=8.2, textColor=MUTED)
    card_label = ParagraphStyle("CardLabel", parent=small, fontName="Helvetica-Bold", textColor=colors.HexColor("#73D8FF"), fontSize=6.5, leading=8)
    card_num = ParagraphStyle("CardNum", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=19, leading=21, textColor=colors.white)
    table_h = ParagraphStyle("TableH", parent=small, fontName="Helvetica-Bold", textColor=WHITE, fontSize=6.5, leading=8)
    table_d = ParagraphStyle("TableD", parent=small, fontSize=6.6, leading=8.7, textColor=colors.HexColor("#D7E5F2"))
    table_m = ParagraphStyle("TableM", parent=table_d, textColor=colors.HexColor("#8FA6BA"))
    callout_title = ParagraphStyle("CalloutTitle", parent=small, fontName="Helvetica-Bold", textColor=colors.HexColor("#DCEBFA"), fontSize=8, leading=10)

    def metric_card(label, value, note=""):
        return [[P(label.upper(), card_label)], [P(value, card_num)], [P(note, tiny)]]

    def card_table(cards):
        rows = [[], [], []]
        for card in cards:
            for i, cell in enumerate(card): rows[i].append(cell[0])
        t = Table(rows, colWidths=[43.2*mm]*len(cards), rowHeights=[6*mm, 10*mm, 6*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), SOFT), ("BOX", (0,0), (-1,-1), .7, colors.HexColor("#29475D")),
            ("INNERGRID", (0,0), (-1,-1), .35, LINE), ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("LEFTPADDING", (0,0), (-1,-1), 7), ("RIGHTPADDING", (0,0), (-1,-1), 7),
            ("TOPPADDING", (0,0), (-1,-1), 3), ("BOTTOMPADDING", (0,0), (-1,-1), 3)
        ]))
        return t

    def section_header(title_text, subtitle_text):
        return [Spacer(1, 5*mm), P(title_text, section), P(subtitle_text, section_sub)]

    out = io.BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=14*mm, leftMargin=14*mm,
                            topMargin=17*mm, bottomMargin=17*mm,
                            title="Wi-Fi Sentinel · Wireless Security Assessment", author="Wi-Fi Sentinel")

    story=[]

    # ---------- cover ----------
    cover_data = [[P("Wi-Fi Sentinel", cover), P("WIRELESS SECURITY ASSESSMENT", ParagraphStyle("CoverK", parent=cover_sub, fontName="Helvetica-Bold", fontSize=7.5, textColor=colors.HexColor("#8FB4FF")))],
                  [P("Evidence-based assessment of the observable wireless environment, authorization state and security exposure.", cover_sub), ""]]
    cv=Table(cover_data, colWidths=[150*mm, 30*mm], rowHeights=[22*mm, 18*mm])
    cv.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), NAVY), ("SPAN", (0,1),(1,1)),
        ("VALIGN", (0,0),(-1,-1),"MIDDLE"), ("LEFTPADDING",(0,0),(-1,-1),10),
        ("RIGHTPADDING",(0,0),(-1,-1),10), ("TOPPADDING",(0,0),(-1,-1),6), ("BOTTOMPADDING",(0,0),(-1,-1),6)
    ]))
    story += [cv, Spacer(1, 9*mm)]
    accent=Table([[""]], colWidths=[180*mm], rowHeights=[1.8*mm])
    accent.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),BLUE), ("LINEBELOW",(0,0),(-1,-1),0,BLUE)]))
    story += [accent, Spacer(1, 4*mm)]
    if scan:
        meta = [
            [P("ASSESSMENT", card_label), P(f"#{scan['id']}", card_num), P("COMPLETED", card_label), P(str(scan.get("finished_at") or ""), table_d)],
            [P("GENERATED", card_label), P(now, table_d), P("SCOPE", card_label), P("Observable wireless environment", table_d)]
        ]
        mt=Table(meta,colWidths=[25*mm,35*mm,25*mm,95*mm],rowHeights=[9*mm,9*mm])
        mt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),SOFT),("BOX",(0,0),(-1,-1),.7,colors.HexColor("#29475D")),("INNERGRID",(0,0),(-1,-1),.35,LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),7)]))
        story += [mt, Spacer(1, 8*mm)]
    story += [P("Executive Snapshot", section), P("A concise, decision-ready view of the latest wireless assessment. Live observations are intentionally separated from historical assets.", section_sub)]
    story += [card_table([
        metric_card("Security posture", f"{posture.get('score',0)}/100", "Overall assessment score"),
        metric_card("Live APs", str(total), "Current assessment snapshot"),
        metric_card("Authorized", str(authorized), "Approved inventory matches"),
        metric_card("High / critical", f"{high} / {critical}", "Priority observations")
    ]), Spacer(1, 7*mm)]

    executive = (
        f"The latest assessment recorded <b>{total}</b> live wireless access points. "
        f"<b>{authorized}</b> matched the authorized inventory, while <b>{unverified}</b> were unverified. "
        f"<b>{high}</b> observations reached the high-or-critical threshold. "
        "An unfamiliar BSSID is treated as an investigation indicator rather than proof of malicious activity."
    )
    story += [P("Assessment Interpretation", section), P(executive, body)]
    story += [Spacer(1,5*mm)]
    note=Table([[P("OPERATING PRINCIPLE", card_label), P("Evidence first. Classification follows correlated observations; historical assets are not counted as live detections.", body)]], colWidths=[35*mm,145*mm])
    note.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),colors.HexColor("#0A2536")),("BACKGROUND",(1,0),(1,0),colors.HexColor("#0E1A26")),("BOX",(0,0),(-1,-1),.6,LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
    story += [note, PageBreak()]

    # ---------- current findings ----------
    story += section_header("Current Wireless Findings", "Live observations from the latest assessment snapshot.")
    headers=["SSID / Network Identifier","BSSID / AP Identifier","Security","Classification","Risk","Detection Evidence"]
    data=[[P(x,table_h) for x in headers]]
    for r in latest_rows:
        status=str(r.get("status") or "Unverified")
        reason=str(r.get("reason") or "No additional evidence recorded")
        data.append([P(r.get("ssid") or "<hidden>",table_d),P(r.get("bssid") or "",table_m),P(r.get("security") or "UNKNOWN",table_d),P(status,table_d),P(str(r.get("risk") or 0),table_d),P(reason[:150],table_m)])
    if len(data)==1:
        data.append([P("No live wireless observations were recorded.",table_m),"","","","",""])
    t=Table(data,colWidths=[32*mm,34*mm,22*mm,26*mm,12*mm,54*mm],repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),NAVY),("GRID",(0,0),(-1,-1),.35,LINE),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,SOFT]),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    story += [t]

    if recent_assets:
        story += section_header("Recently Observed Wireless Assets", "Historical wireless assets retained for investigation; these are not current live detections.")
        rd=[[P(x,table_h) for x in ["SSID","BSSID","Security","Last Observed","Previous Risk","Historical State"]]]
        for r in recent_assets:
            rd.append([P(r.get("ssid") or "<hidden>",table_d),P(r.get("bssid") or "",table_m),P(r.get("security") or "UNKNOWN",table_d),P(r.get("observed_at") or r.get("assessment_finished_at") or "",table_m),P(str(r.get("risk") or 0),table_d),P("Recently Observed",table_m)])
        rt=Table(rd,colWidths=[34*mm,34*mm,23*mm,37*mm,18*mm,30*mm],repeatRows=1)
        rt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#102A3D")),("GRID",(0,0),(-1,-1),.35,LINE),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,SOFT]),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
        story += [rt]

    # ---------- client telemetry ----------
    story += section_header("Client Visibility", "LAN-visible client telemetry. The current Windows adapter does not provide reliable per-AP association telemetry.")
    story += [card_table([metric_card("Visible client assets", str(len(client_assets)), "Observed through local telemetry"), metric_card("AP association", "N/A", "Not reliably exposed by adapter"), metric_card("Deployment zone", "Metadata", "Use authorized network context")]), Spacer(1,4*mm)]
    if client_assets:
        cd=[[P(x,table_h) for x in ["Hostname","IP Address","MAC Address","Vendor","Last Observed"]]]
        for d in client_assets:
            cd.append([P(d.get("hostname") or "Unknown host",table_d),P(d.get("ip") or "",table_d),P(d.get("mac") or "",table_m),P(d.get("vendor") or "Unknown vendor",table_d),P(d.get("last_seen") or "",table_m)])
        ct=Table(cd,colWidths=[40*mm,29*mm,40*mm,34*mm,32*mm],repeatRows=1)
        ct.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),NAVY),("GRID",(0,0),(-1,-1),.35,LINE),("VALIGN",(0,0),(-1,-1),"TOP"),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,SOFT]),("LEFTPADDING",(0,0),(-1,-1),4),("RIGHTPADDING",(0,0),(-1,-1),4),("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
        story += [ct]
    else:
        story += [P("No LAN-visible client telemetry is currently available.", body)]

    # ---------- priorities ----------
    story += section_header("Priority Review Actions", "Recommended analyst workflow for the next investigation cycle.")
    actions=[
        ("01", "Validate authorization", "Confirm high-risk and unverified BSSIDs against the approved wireless inventory."),
        ("02", "Review security exposure", "Investigate weak or unexpected authentication and encryption configurations."),
        ("03", "Correlate identity evidence", "Compare SSID, BSSID, vendor/fingerprint and historical observations before classification."),
        ("04", "Investigate persistence", "Review repeated behavioral deviations and APs that disappear from the latest snapshot."),
    ]
    for num,title_text,desc in actions:
        row=Table([[P(num,card_label),P(title_text,callout_title),P(desc,body)]],colWidths=[13*mm,43*mm,109*mm])
        row.setStyle(TableStyle([("BACKGROUND",(0,0),(0,0),colors.HexColor("#0A2536")),("BOX",(0,0),(-1,-1),.45,LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("LEFTPADDING",(0,0),(-1,-1),7),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
        story += [row, Spacer(1,2*mm)]

    # ---------- methodology ----------
    story += [PageBreak()]
    story += section_header("Methodology & Data Integrity", "How this assessment should be interpreted in an authorized defensive environment.")
    methodology=(
        "The platform performs passive wireless discovery using the capabilities exposed by the local wireless interface. "
        "Observed APs are normalized using SSID and BSSID identifiers, compared against the configured authorized inventory, "
        "and assessed using available security, baseline and behavioral evidence. Risk and confidence are assessment outputs, "
        "not raw measurements emitted by the Wi-Fi adapter."
    )
    story += [P(methodology, body), Spacer(1,4*mm)]
    integrity=Table([
        [P("DATA CLASS",table_h),P("SOURCE / INTERPRETATION",table_h)],
        [P("Wireless observations",table_d),P("Live AP information exposed by the wireless discovery backend.",table_d)],
        [P("Security profile",table_d),P("Observed authentication/encryption information where exposed by the adapter.",table_d)],
        [P("Risk / confidence",table_d),P("Calculated assessment values derived from project detection logic and available evidence.",table_d)],
        [P("Historical assets",table_d),P("Prior observations retained for context and explicitly excluded from live counts.",table_d)],
        [P("Client visibility",table_d),P("LAN-visible client telemetry; not presented as per-AP association without reliable association data.",table_d)],
    ],colWidths=[42*mm,138*mm],repeatRows=1)
    integrity.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),NAVY),("GRID",(0,0),(-1,-1),.35,LINE),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,SOFT]),("VALIGN",(0,0),(-1,-1),"TOP"),("LEFTPADDING",(0,0),(-1,-1),6),("RIGHTPADDING",(0,0),(-1,-1),6),("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    story += [integrity, Spacer(1,6*mm), P("Assessment Disclaimer", section), P("An unverified or unfamiliar wireless asset is an investigation indicator, not proof of compromise. Findings should be validated against the authorized environment, controller telemetry and operational context available to the security team.", body)]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#29475D")); canvas.line(14*mm, 10.5*mm, 196*mm, 10.5*mm)
        canvas.setFont("Helvetica", 6.8); canvas.setFillColor(colors.HexColor("#6F879B"))
        canvas.drawString(14*mm, 6.2*mm, "Wi-Fi Sentinel · Evidence-based wireless assessment")
        canvas.drawRightString(196*mm, 6.2*mm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    out.seek(0)
    return send_file(out, mimetype="application/pdf", as_attachment=True, download_name="wifi_sentinel_modern_security_assessment.pdf")


@app.get("/report.pdf")
def report_pdf():
    """Generate the assessment PDF without exposing an internal server error to the UI."""
    try:
        return _report_pdf_impl()
    except Exception as exc:
        app.logger.exception("PDF report generation failed: %s", exc)
        flash("PDF generation needs the reporting dependencies. Open the Executive Report and use Print / Save PDF.")
        return redirect(url_for("executive_report"))


@app.get("/api/scan/<int:scan_id>/evidence")
def api_scan_evidence(scan_id):
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    c = db()
    rows = [dict(x) for x in c.execute(
        "SELECT id,scan_id,evidence_type,sha256,captured_at FROM scan_evidence WHERE scan_id=? ORDER BY id",
        (scan_id,)
    )]
    c.close()
    return jsonify({"scan_id": scan_id, "evidence": rows})


@app.get("/api/summary")
def api_summary():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    c=db()
    latest=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    alerts=c.execute("SELECT COUNT(*) n FROM alerts WHERE acknowledged=0").fetchone()["n"]
    c.close()
    return jsonify({"latest_scan":dict(latest) if latest else None,"open_alerts":alerts})

@app.post("/api/scan")
def api_scan():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    results=assess(discover()); sid=save_results(results)
    return jsonify({"scan_id":sid,"observations":len(results),"flagged":sum(x["status"]!="Authorized" for x in results)})



@app.get("/api/discovery")
def api_discovery():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    rows=discover()
    return jsonify({
        "platform": platform.system(),
        "backend": "windows-netsh" if platform.system()=="Windows" else "linux-nmcli",
        "count": len(rows),
        "aps": rows,
        "capabilities": scanner_capabilities()
    })

@app.get("/api/status")
def api_status():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    c=db()
    scan=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    alerts=c.execute("SELECT COUNT(*) n FROM alerts WHERE acknowledged=0").fetchone()["n"]
    c.close()
    return jsonify({"status":"ok","latest_scan":dict(scan) if scan else None,"open_alerts":alerts})

@app.post("/api/auto-scan")
def api_auto_scan():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    c=db()
    prev={r["bssid"]:dict(r) for r in c.execute("SELECT * FROM baseline")}
    c.close()
    results=assess(discover())
    current={x["bssid"] for x in results}
    adv=advanced_alerts(results,prev,current)
    sid=save_results(results)
    persist_new_alerts(sid, adv)
    return jsonify({"scan_id":sid,"observations":len(results),"alerts":len(adv),
                    "backend":"windows-netsh" if platform.system()=="Windows" else "linux-nmcli"})

def api_authorized():
    """Allow protected API access for a local session or configured API key."""
    if session.get("user"):
        return True
    configured = os.environ.get("WIFI_SENTINEL_API_KEY", "").strip()
    supplied = (request.headers.get("X-API-Key") or "").strip()
    return bool(configured and supplied and supplied == configured)


@app.get("/api/timeline")
def api_timeline():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    c=db()
    rows=[dict(x) for x in c.execute(
        "SELECT id,started_at,ap_count,flagged_count,max_risk FROM scans ORDER BY id ASC LIMIT 100")]
    c.close()
    return jsonify(rows)

def scanner_capabilities():
    system = platform.system()
    return {
        "platform": system,
        "wireless_discovery": True,
        "nearby_access_points": True,
        "nearby_wifi_clients": False,
        "lan_asset_discovery": True,
        "active_lan_probe": True,
        "monitor_mode": system != "Windows",
        "backend": "netsh-wlan" if system == "Windows" else "nmcli",
        "limitations": [
            "Windows adapter APIs enumerate nearby access points but do not provide reliable over-the-air client enumeration.",
            "Full RF client discovery requires a monitor-mode-capable sensor and appropriate driver support."
        ] if system == "Windows" else []
    }


@app.get("/api/capabilities")
def api_capabilities():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    return jsonify(scanner_capabilities())


@app.get("/discovery")
def discovery():
    rows=discover()
    return render_template("discovery.html",platform=platform.system(),
                           backend="windows-netsh" if platform.system()=="Windows" else "linux-nmcli",
                           count=len(rows),aps=rows)



@app.get("/api/posture")
def api_posture():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    c=db()
    rows=[dict(x) for x in c.execute("""SELECT bssid,ssid,channel,signal,security,risk FROM observations
                                        ORDER BY id DESC LIMIT 200""")]
    c.close()
    return jsonify(posture_for(rows))

@app.get("/posture")
def posture():
    c=db()
    rows=[dict(x) for x in c.execute("""SELECT bssid,ssid,channel,signal,security,risk FROM observations
                                        ORDER BY id DESC LIMIT 200""")]
    c.close()
    p=posture_for(rows)
    return render_template("posture.html", posture=p)


# ---------------- Monitoring State ----------------
MONITORING_STATE = {"enabled": False}

@app.get("/api/monitoring")
def api_monitoring_get():
    return jsonify({"monitoring": MONITORING_STATE["enabled"]})

@app.post("/api/monitoring")
def api_monitoring_post():
    if not logged_in() and not api_authorized():
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    MONITORING_STATE["enabled"] = bool(data.get("enabled"))
    return jsonify({"monitoring": MONITORING_STATE["enabled"]})



# --- Wi-Fi Sentinel v21 safe telemetry layer ---
# This layer is deliberately read-only and fail-safe. It never performs
# active probing, packet injection, deauthentication, or network modification.

@app.get("/api/health")
def sentinel_health():
    database = "ok"
    try:
        c = db(); c.execute("SELECT 1"); c.close()
    except Exception:
        database = "error"
    return jsonify({
        "status": "ok" if database == "ok" else "degraded",
        "service": "wifi-sentinel",
        "database": database,
        "scanner": "available",
        "version": "v29",
        "time": datetime.now().isoformat(timespec="seconds"),
    })


@app.get("/api/telemetry")
def sentinel_telemetry():
    if "user" not in session:
        return jsonify({"error": "authentication required"}), 401

    payload = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "risk": 0,
        "alerts": 0,
        "aps": 0,
        "trusted": 0,
        "untrusted": 0,
        "scans": 0,
    }

    try:
        conn = db()
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}

        # Read common schema variants without changing the DB.
        if "alerts" in tables:
            payload["alerts"] = int(conn.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0] or 0)

        if "scans" in tables:
            payload["scans"] = int(conn.execute(
                "SELECT COUNT(*) FROM scans"
            ).fetchone()[0] or 0)
            try:
                row = conn.execute(
                    "SELECT risk FROM scans ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if row:
                    payload["risk"] = int(row[0] or 0)
            except Exception:
                pass

        for table in ("observations", "aps", "access_points"):
            if table in tables:
                try:
                    cols = {r[1] for r in conn.execute(
                        f"PRAGMA table_info({table})"
                    ).fetchall()}
                    if "bssid" in cols:
                        payload["aps"] = int(conn.execute(
                            f"SELECT COUNT(DISTINCT bssid) FROM {table}"
                        ).fetchone()[0] or 0)
                        break
                except Exception:
                    pass

        for table in ("inventory", "approved_aps", "trusted_aps"):
            if table in tables:
                try:
                    payload["trusted"] = int(conn.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0] or 0)
                    break
                except Exception:
                    pass

        payload["untrusted"] = max(0, payload["aps"] - payload["trusted"])
        conn.close()
    except Exception:
        # Dashboard must never fail because telemetry is unavailable.
        pass

    return jsonify(payload)


@app.get("/api/export/summary.json")
def export_summary_json():
    if "user" not in session:
        return jsonify({"error": "authentication required"}), 401
    response = sentinel_telemetry()
    return response


init_db()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

