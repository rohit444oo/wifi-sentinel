
from flask import Flask, render_template, redirect, url_for, request, send_file, flash, jsonify, session
from datetime import datetime
from pathlib import Path
import csv, io, json, os, platform, re, sqlite3, subprocess, time, ipaddress, socket, concurrent.futures, hashlib

BASE = Path(__file__).resolve().parent
DB = BASE / "wifi_sentinel.db"
app = Flask(__name__)
app.secret_key = "wifi-sentinel-v3-local"
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("WIFI_ADMIN_PASS", "sentinel")

# ---------------- Authentication ----------------
def logged_in():
    return bool(session.get("user"))

def role():
    return session.get("role", "viewer")

@app.context_processor
def auth_context():
    return {"logged": logged_in(), "user_role": role(), "current_user": session.get("user")}

# ---------------- Database ----------------
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
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
    """)
    # Lightweight schema migration for databases created by earlier versions.
    existing_cols = {row["name"] for row in c.execute("PRAGMA table_info(observations)")}
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

# ---------------- OUI ----------------
OUI = {
    "A842A1": "TP-Link / Arcadyan-family OUI (local mapping)",
    "7C21D8": "Wireless AP Vendor (OUI lookup required for authoritative attribution)",
    "001A11": "Apple",
    "3C5A37": "Google",
    "F4F5D8": "Xiaomi",
    "B827EB": "Raspberry Pi",
}

def vendor_for(bssid):
    key = re.sub(r"[^0-9A-F]", "", (bssid or "").upper())[:6]
    return OUI.get(key, "Unknown / local OUI lookup")

def clean_bssid(x):
    return (x or "").strip().upper()

def normalize_security(s):
    raw = (s or "UNKNOWN").strip().upper()
    compact = re.sub(r"[^A-Z0-9]+", "", raw)
    if compact in ("OPEN","NONE","NOSUPPORTED"):
        return "OPEN"
    if "WPA3" in compact:
        return "WPA3"
    if "WPA2" in compact:
        return "WPA2"
    if "WPA" in compact:
        return "WPA"
    if "WEP" in compact:
        return "WEP"
    if compact in ("", "--", "UNKNOWN", "NA", "N/A"):
        return "UNKNOWN"
    return raw

def signal_int(s):
    m = re.search(r"\d+", str(s or ""))
    return int(m.group()) if m else None


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
            "SELECT id, created_at, risk FROM scans ORDER BY id DESC LIMIT 20"
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

                # Limit active discovery to a short, bounded probe set.
                # ARP remains the primary source and this mode is explicit.
                for host in list(network.hosts())[:254]:
                    host_ip = str(host)
                    if host_ip in seen_ips or host_ip == ip:
                        continue
                    try:
                        subprocess.run(
                            ["ping", "-n", "1", "-w", "150", host_ip],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=0.35,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                        )
                    except Exception:
                        continue

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

    return result


def fresh_windows_scan():
    """Refresh the Windows WLAN result cache without forcing a disconnect."""
    try:
        subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=10
        )
    except Exception:
        pass

def scan_windows():
    p = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=15
    )
    text = p.stdout
    rows = []

    headers = list(re.finditer(
        r"(?im)^\s*SSID\s+\d+\s*:\s*(.*?)\s*$", text
    ))

    for i, header in enumerate(headers):
        section_start = header.end()
        section_end = headers[i+1].start() if i+1 < len(headers) else len(text)
        section = text[section_start:section_end]

        # The SSID value is on the header itself. Empty => hidden.
        ssid = header.group(1).strip() or "<hidden>"

        # Windows normally places Authentication at SSID level.
        auth_match = re.search(
            r"(?im)^\s*Authentication\s*:\s*(.+?)\s*$", section
        )
        ssid_security = normalize_security(auth_match.group(1)) if auth_match else "UNKNOWN"

        bssid_matches = list(re.finditer(
            r"(?im)^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]{17})\s*$",
            section
        ))

        for j, bm in enumerate(bssid_matches):
            chunk_end = bssid_matches[j+1].start() if j+1 < len(bssid_matches) else len(section)
            chunk = section[bm.start():chunk_end]
            bssid = clean_bssid(bm.group(1))

            def field(pattern, default=None):
                m = re.search(pattern, chunk, flags=re.I|re.M)
                return m.group(1).strip() if m else default

            signal = field(r"^\s*Signal\s*:\s*(\d+)%\s*$")
            channel = field(r"^\s*Channel\s*:\s*(\d+)\s*$")
            radio = field(r"^\s*Radio type\s*:\s*(.+?)\s*$")
            band = field(r"^\s*Band\s*:\s*(.+?)\s*$")
            local_auth = field(r"^\s*Authentication\s*:\s*(.+?)\s*$")

            security = normalize_security(local_auth or ssid_security)

            rows.append({
                "ssid": ssid,
                "bssid": bssid,
                "signal": (signal + "%") if signal else "N/A",
                "channel": int(channel) if channel and channel.isdigit() else None,
                "security": security,
                "radio": radio,
                "band": band,
            })

    unique = {}
    for row in rows:
        unique[row["bssid"]] = row
    return list(unique.values())


def scan_linux():
    p = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"],
                       capture_output=True, text=True, encoding="utf-8", errors="ignore")
    rows = []
    for line in p.stdout.splitlines():
        m = re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", line)
        if not m: continue
        bssid = clean_bssid(m.group(1))
        before, after = line[:m.start()], line[m.end():]
        ssid = before.rstrip(":").replace("\\:", ":") or "<hidden>"
        vals = after.split(":")
        nums = [int(x) for x in vals if x.isdigit()]
        channel = next((x for x in nums if 1 <= x <= 233), None)
        signal = next((str(x)+"%" for x in nums if 0 <= x <= 100), "N/A")
        security = normalize_security(vals[-1] if vals else "UNKNOWN")
        rows.append({"ssid": ssid, "bssid": bssid, "channel": channel, "signal": signal, "security": security})
    return rows

def discover():
    try:
        return scan_windows() if platform.system() == "Windows" else scan_linux()
    except Exception:
        return []

# ---------------- Risk + baseline engine ----------------
SECURITY_BASE = {"OPEN": 40, "WEP": 35, "WPA": 22, "WPA2": 8, "WPA3": 3, "UNKNOWN": 18}


def ml_anomaly_scores(observations):
    """Optional IsolationForest score; falls back to 0 when history is insufficient."""
    if not observations: return {}
    try:
        from sklearn.ensemble import IsolationForest
        features=[]; keys=[]
        for x in observations:
            keys.append(x.get("bssid"))
            features.append([
                float(x.get("channel") or 0), signal_int(x.get("signal")) or 0,
                {"OPEN":0,"WEP":1,"WPA":2,"WPA2":3,"WPA3":4,"UNKNOWN":2}.get(normalize_security(x.get("security")),2),
                len(str(x.get("ssid") or "")),
            ])
        if len(features)<5: return {k:0 for k in keys}
        model=IsolationForest(n_estimators=80,contamination="auto",random_state=42)
        model.fit(features)
        raw=model.decision_function(features)
        return {k:int(max(0,min(100,(0.5-v)*180))) for k,v in zip(keys,raw)}
    except Exception:
        return {x.get("bssid"):0 for x in observations}

def assess(rows):
    c = db()
    approved = {clean_bssid(r["bssid"]): dict(r) for r in c.execute("SELECT * FROM approved_aps")}
    previous = {clean_bssid(r["bssid"]): dict(r) for r in c.execute("SELECT * FROM baseline")}
    c.close()

    results = []
    for raw in rows:
        r = dict(raw)
        b = clean_bssid(r.get("bssid"))
        ssid = (r.get("ssid") or "<hidden>").strip() or "<hidden>"
        sec = normalize_security(r.get("security"))
        prev = previous.get(b)
        approved_ap = approved.get(b)

        same_ssid = [
            x for x in approved.values()
            if (x.get("ssid") or "").strip().lower() == ssid.lower()
        ]

        changed = []
        reasons = []

        # Explainable risk components, each capped independently.
        identity_risk = 0
        security_risk = SECURITY_BASE.get(sec, SECURITY_BASE["UNKNOWN"])
        baseline_risk = 0
        behavior_risk = 0
        fingerprint_risk = 0

        # Identity / spoof indicators.
        if approved_ap:
            status = "Authorized"
            if normalize_security(approved_ap.get("security")) != sec:
                identity_risk += 8
                security_risk += 15
                reasons.append(
                    f"Security differs from trusted inventory ({approved_ap.get('security')} → {sec})"
                )
                status = "Configuration Mismatch"
        else:
            identity_risk += 25
            reasons.append("BSSID is not in the trusted inventory")
            if same_ssid:
                identity_risk += 25
                fingerprint_risk += 20
                reasons.append("Trusted SSID observed from a different BSSID")
                status = "Suspicious"
            else:
                status = "Untrusted"

        # Security policy.
        if sec in ("OPEN", "WEP"):
            security_risk += 25
            reasons.append("Weak or absent Wi-Fi encryption")
        elif sec == "WPA":
            security_risk += 10
            reasons.append("Legacy WPA security")

        # Baseline changes.
        if prev:
            if prev.get("channel") != r.get("channel"):
                changed.append("channel changed")
                baseline_risk += 6
            if normalize_security(prev.get("security")) != sec:
                changed.append("security changed")
                baseline_risk += 8

            oldsig = prev.get("signal")
            newsig = signal_int(r.get("signal"))
            if oldsig is not None and newsig is not None:
                delta = abs(newsig - oldsig)
                if delta >= 35:
                    changed.append("large signal change")
                    baseline_risk += 5
                elif delta >= 20:
                    changed.append("signal changed")
                    baseline_risk += 2

            if changed:
                reasons.append("Baseline change: " + ", ".join(changed))
        else:
            reasons.append("First observation for this AP")
            baseline_risk += 4

        # Behavioral anomaly: conservative, explainable, and bounded.
        behavior_risk += min(20, len(changed) * 6)
        if prev and prev.get("channel") is not None and r.get("channel") is not None:
            # A large channel jump is more interesting than a normal adjacent movement.
            if abs(int(prev["channel"]) - int(r["channel"])) >= 20:
                behavior_risk += 6

        # Fingerprint deviation combines identity, security, channel and radio/band.
        fingerprint_match = 100
        if not approved_ap and same_ssid:
            fingerprint_match -= 35
        if prev:
            if prev.get("channel") != r.get("channel"):
                fingerprint_match -= 18
            if normalize_security(prev.get("security")) != sec:
                fingerprint_match -= 20
            if (prev.get("vendor") or "") != vendor_for(b):
                fingerprint_match -= 8
        fingerprint_match = max(0, min(100, fingerprint_match))
        fingerprint_risk = max(fingerprint_risk, 100 - fingerprint_match)

        # Composite anomaly score.
        anomaly = min(
            100,
            identity_risk
            + min(25, baseline_risk)
            + min(20, behavior_risk)
            + min(30, fingerprint_risk)
            + (20 if sec in ("OPEN", "WEP") else 0)
        )

        # Risk is a weighted explainable sum.
        risk = round(
            min(100,
                0.28 * min(100, identity_risk)
                + 0.22 * min(100, security_risk)
                + 0.18 * min(100, baseline_risk)
                + 0.17 * min(100, behavior_risk)
                + 0.15 * min(100, fingerprint_risk)
            )
        )

        # Preserve a useful floor for an untrusted AP without calling it malicious.
        if not approved_ap:
            risk = max(risk, 30)
        if same_ssid and not approved_ap:
            risk += 10

        independent_indicators = sum([
            bool(same_ssid and not approved_ap),
            len(changed) >= 2,
            anomaly >= 65,
            sec in ("OPEN", "WEP"),
            fingerprint_match < 65
        ])

        if status not in ("Authorized", "Configuration Mismatch"):
            if independent_indicators >= 2:
                status = "Possible Rogue"
            elif same_ssid and not approved_ap:
                status = "Possible Spoof"
            else:
                status = "Untrusted"

        risk = min(100, max(0, int(risk)))
        level = (
            "Critical" if risk >= 85 else
            "High" if risk >= 65 else
            "Medium" if risk >= 40 else
            "Low"
        )

        reason = "; ".join(reasons) if reasons else "Matches trusted inventory and observed baseline"

        results.append({
            **r,
            "ssid": ssid,
            "bssid": b,
            "security": sec,
            "vendor": vendor_for(b),
            "status": status,
            "risk": risk,
            "level": level,
            "reason": reason,
            "changed": ", ".join(changed),
            "anomaly": anomaly,
            "anomaly_score": int(anomaly),
            "fingerprint_score": int(fingerprint_match),
            "identity_risk": min(100, int(identity_risk)),
            "security_risk": min(100, int(security_risk)),
            "baseline_risk": min(100, int(baseline_risk)),
            "behavior_risk": min(100, int(behavior_risk)),
            "fingerprint_risk": min(100, int(fingerprint_risk)),
            "fingerprint_match": int(fingerprint_match),
            "spoof_indicator": bool(same_ssid and not approved_ap),
        })

    ml_scores = ml_anomaly_scores(results)
    for x in results:
        x["ml_anomaly"] = int(ml_scores.get(x.get("bssid"), 0))
        x["anomaly_score"] = max(int(x.get("anomaly_score", 0)), x["ml_anomaly"])
        x["behavior_risk"] = min(100, int(x.get("behavior_risk", 0)) + x["ml_anomaly"] // 4)
    return enrich_trust(results)

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

        # One concise security finding per AP; advanced correlation adds higher-level events.
        if x["status"] != "Authorized" or x["risk"] >= 65:
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
                   last_seen=?,seen_count=seen_count+1 WHERE bssid=?""",
                (x.get("ssid"), x.get("channel"), x["security"], x["vendor"], sig, now, x["bssid"])
            )
        else:
            c.execute(
                """INSERT INTO baseline
                   (bssid,ssid,channel,security,vendor,signal,first_seen,last_seen,seen_count)
                   VALUES(?,?,?,?,?,?,?,?,1)""",
                (x["bssid"], x.get("ssid"), x.get("channel"), x["security"], x["vendor"], sig, now, now)
            )

    c.commit()
    c.close()
    return scan_id

# ---------------- Security posture / policy / correlation ----------------
SECURITY_POLICY = {
    "OPEN": {"risk": 35, "label": "Prohibited"},
    "WEP": {"risk": 30, "label": "Prohibited"},
    "WPA": {"risk": 18, "label": "Legacy"},
    "WPA2": {"risk": 8, "label": "Allowed"},
    "WPA3": {"risk": 2, "label": "Preferred"},
    "UNKNOWN": {"risk": 15, "label": "Needs verification"},
}

def posture_for(results):
    total=len(results)
    counts={k:0 for k in SECURITY_POLICY}
    for r in results:
        counts.get(r.get("security","UNKNOWN"), counts["UNKNOWN"])
        s=r.get("security","UNKNOWN")
        counts[s]=counts.get(s,0)+1
    score=100
    if total:
        score=max(0, round(100-sum(counts[k]*SECURITY_POLICY[k]["risk"] for k in counts)/total))
    return {"score":score,"counts":counts,"total":total}

def trust_score(ap):
    risk=int(ap.get("risk",0))
    anomaly=int(ap.get("anomaly_score",0) or 0)
    fp=int(ap.get("fingerprint_score",0) or 0)
    security=ap.get("security","UNKNOWN")
    sec_bonus={"WPA3":100,"WPA2":88,"WPA":70,"WEP":35,"OPEN":15,"UNKNOWN":55}.get(security,55)
    return max(0,min(100,round(0.45*(100-risk)+0.20*(100-anomaly)+0.15*(100-fp)+0.20*sec_bonus)))

def enrich_trust(results):
    for r in results:
        r["trust_score"]=trust_score(r)
        r["policy_label"]=SECURITY_POLICY.get(r.get("security","UNKNOWN"),SECURITY_POLICY["UNKNOWN"])["label"]
    return results


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
                "SELECT id, created_at, risk FROM scans ORDER BY id DESC LIMIT 20"
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
    obs = [dict(x) for x in c.execute("SELECT * FROM observations WHERE scan_id=(SELECT MAX(id) FROM scans) ORDER BY risk DESC")]
    approved = [dict(x) for x in c.execute("SELECT * FROM approved_aps ORDER BY ssid")]
    alerts = [dict(x) for x in c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 8")]
    scans = [dict(x) for x in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 10")]
    c.close()
    # Rehydrate calculated security intelligence for dashboard-only fields.
    for x in obs:
        x["security"] = normalize_security(x.get("security"))
        x["anomaly_score"] = int(x.get("risk",0) >= 65) * 70
        x["fingerprint_score"] = min(100, 35 if any(
            a["ssid"].strip().lower() == x["ssid"].strip().lower()
            for a in approved
        ) and not any(a["bssid"] == x["bssid"] for a in approved) else 0)
        x["trust_score"] = trust_score(x)
        x["policy_label"] = SECURITY_POLICY.get(x["security"], SECURITY_POLICY["UNKNOWN"])["label"]
    c=db(); device_count=c.execute("SELECT COUNT(*) n FROM network_devices").fetchone()["n"]; sensor_count=c.execute("SELECT COUNT(*) n FROM sensors").fetchone()["n"]; c.close()
    stats={"observations":len(obs),"authorized":sum(x["status"]=="Authorized" for x in obs),
           "flagged":sum(x["status"]!="Authorized" for x in obs),"max_risk":max([x["risk"] for x in obs],default=0),
           "critical":sum(x["level"]=="Critical" for x in obs),"high":sum(x["level"]=="High" for x in obs),
           "medium":sum(x["level"]=="Medium" for x in obs),"low":sum(x["level"]=="Low" for x in obs)}
    return render_template("index.html", observations=obs, approved=approved, alerts=alerts, scans=scans, stats=stats, device_count=device_count, sensor_count=sensor_count,
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
            reasons.append("behavioral anomaly")
        if int(x.get("fingerprint_score",0) or 0)<65:
            reasons.append("fingerprint deviation")
        if str(x.get("security","")).upper() in ("OPEN","WEP"):
            reasons.append("weak/absent encryption")

        is_new=bssid not in previous_map
        if is_new:
            reasons.append("first observation for this AP")

        if status=="Authorized" and risk<65 and not reasons:
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
        "spoof": bool(latest.get("spoof_indicator") or (
            approved is None and any(
                (a["ssid"] or "").strip().lower() == (latest.get("ssid") or "").strip().lower()
                for a in c.execute("SELECT * FROM approved_aps")
            )
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
        }
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
    c=db(); c.execute("UPDATE incidents SET status='Closed',updated_at=? WHERE id=?",(datetime.now().isoformat(timespec="seconds"),incident_id)); c.commit(); c.close(); return redirect(url_for("incident_detail",incident_id=incident_id))

@app.get("/alerts")
def alerts():
    c=db(); rows=[dict(x) for x in c.execute("SELECT * FROM alerts ORDER BY id DESC")]; c.close()
    return render_template("alerts.html", alerts=rows)

@app.post("/inventory/add")
def inventory_add():
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
    c=db(); c.execute("DELETE FROM approved_aps WHERE id=?",(ap_id,)); c.commit(); c.close()
    flash("AP removed."); return redirect("/")


@app.get("/devices")
def devices_page():
    devices, subnet = discover_network_devices(active_probe=True)
    c=db(); history=[dict(x) for x in c.execute("SELECT * FROM network_devices ORDER BY last_seen DESC LIMIT 200")]; c.close()
    return render_template("devices.html", devices=devices, history=history, subnet=subnet, ap_count=len(discover()))

@app.get("/api/devices")
def api_devices():
    if not api_authorized(): return jsonify({"error":"unauthorized"}),401
    devices, subnet=discover_network_devices(active_probe=True)
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

@app.get("/export.csv")
def export_csv():
    c=db(); rows=c.execute("""SELECT scan_id,ssid,bssid,channel,signal,security,vendor,status,risk,level,reason,changed,observed_at
                              FROM observations ORDER BY id DESC""").fetchall(); c.close()
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(["Scan","SSID","BSSID","Channel","Signal","Security","Vendor","Status","Risk","Level","Reason","Changes","Observed"])
    w.writerows(rows)
    return send_file(io.BytesIO(out.getvalue().encode()),mimetype="text/csv",as_attachment=True,download_name="wifi_sentinel_report.csv")

@app.get("/report.pdf")
def report_pdf():
    # Optional ReportLab: generates a compact security report when installed.
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        flash("Install reportlab with: pip install reportlab")
        return redirect("/")
    c=db()
    rows=c.execute("SELECT * FROM observations WHERE scan_id=(SELECT MAX(id) FROM scans) ORDER BY risk DESC").fetchall()
    c.close()
    buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4)
    styles=getSampleStyleSheet(); story=[Paragraph("Wi-Fi Sentinel — Security Assessment Report",styles["Title"]),
        Paragraph(datetime.now().strftime("Generated %Y-%m-%d %H:%M:%S"),styles["Normal"]),Spacer(1,12)]
    data=[["SSID","BSSID","Security","Status","Risk","Level"]]+[
        [r["ssid"],r["bssid"],r["security"],r["status"],str(r["risk"]),r["level"]] for r in rows]
    t=Table(data,repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.4,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)]))
    story += [t,Spacer(1,12),Paragraph("Interpretation: an unknown BSSID is a possible rogue indicator, not proof of malicious activity. Findings should be validated by an authorized network administrator.",styles["BodyText"])]
    doc.build(story); buf.seek(0)
    return send_file(buf,mimetype="application/pdf",as_attachment=True,download_name="wifi_sentinel_report.pdf")

@app.get("/api/summary")
def api_summary():
    c=db()
    latest=c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    alerts=c.execute("SELECT COUNT(*) n FROM alerts WHERE acknowledged=0").fetchone()["n"]
    c.close()
    return jsonify({"latest_scan":dict(latest) if latest else None,"open_alerts":alerts})

@app.post("/api/scan")
def api_scan():
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
        "aps": rows
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
    """Allow protected API access for an authenticated local dashboard session."""
    return bool(session.get("user"))


@app.get("/api/timeline")
def api_timeline():
    if not api_authorized():
        return jsonify({"error":"unauthorized"}), 401
    c=db()
    rows=[dict(x) for x in c.execute(
        "SELECT id,started_at,ap_count,flagged_count,max_risk FROM scans ORDER BY id ASC LIMIT 100")]
    c.close()
    return jsonify(rows)

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

@app.get("/api/health")
def api_health():
    c=db()
    c.execute("SELECT 1")
    c.close()
    return jsonify({"status":"ok","database":"ok","scanner":"available","version":"v7"})

@app.get("/posture")
def posture():
    c=db()
    rows=[dict(x) for x in c.execute("""SELECT bssid,ssid,channel,signal,security,risk FROM observations
                                        ORDER BY id DESC LIMIT 200""")]
    c.close()
    p=posture_for(rows)
    return render_template("posture.html", posture=p)


init_db()
if __name__=="__main__":
    app.run(host="127.0.0.1",port=5000,debug=False)



# --- Wi-Fi Sentinel v21 safe telemetry layer ---
# This layer is deliberately read-only and fail-safe. It never performs
# active probing, packet injection, deauthentication, or network modification.

@app.get("/api/health")
def sentinel_health():
    return jsonify({
        "status": "ok",
        "service": "wifi-sentinel",
        "version": "v21",
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

