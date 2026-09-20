import platform, subprocess, re, os, time

def fresh_windows_scan():
    """Ask Windows for a fresh nearby-AP snapshot without disconnecting the user."""
    try:
        return subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=10
        ).stdout
    except Exception:
        return ""

def _parse_windows_snapshot(text, clean_bssid, normalize_security):
    rows = []
    headers = list(re.finditer(r"(?im)^\s*SSID\s+\d+\s*:\s*(.*?)\s*$", text))
    for i, header in enumerate(headers):
        section_start = header.end(); section_end = headers[i+1].start() if i+1 < len(headers) else len(text); section = text[section_start:section_end]
        ssid = header.group(1).strip() or "<hidden>"
        if re.match(r"^(Network type|Authentication|Encryption|BSSID|Signal|Radio type|Channel|Basic rates|Other rates)\s*:", ssid, re.I): ssid = "<hidden>"
        auth_match = re.search(r"(?im)^\s*Authentication\s*:\s*(.+?)\s*$", section)
        ssid_security = normalize_security(auth_match.group(1)) if auth_match else "UNKNOWN"
        bssid_matches = list(re.finditer(r"(?im)^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]{17})\s*$", section))
        for j, bm in enumerate(bssid_matches):
            chunk_end = bssid_matches[j+1].start() if j+1 < len(bssid_matches) else len(section); chunk = section[bm.start():chunk_end]; bssid = clean_bssid(bm.group(1))
            def field(pattern, default=None):
                m = re.search(pattern, chunk, flags=re.I|re.M); return m.group(1).strip() if m else default
            signal=field(r"^\s*Signal\s*:\s*(\d+)%\s*$"); channel=field(r"^\s*Channel\s*:\s*(\d+)\s*$"); radio=field(r"^\s*Radio type\s*:\s*(.+?)\s*$"); band=field(r"^\s*Band\s*:\s*(.+?)\s*$"); local_auth=field(r"^\s*Authentication\s*:\s*(.+?)\s*$")
            rows.append({"ssid":ssid,"bssid":bssid,"signal":(signal+"%") if signal else "N/A","channel":int(channel) if channel and channel.isdigit() else None,"security":normalize_security(local_auth or ssid_security),"radio":radio,"band":band})
    return rows

def scan_windows(clean_bssid, normalize_security):
    # Windows WLAN enumeration can transiently return an incomplete snapshot (often just
    # the currently associated AP). Take a few close snapshots and union them by BSSID.
    # This stays within one assessment window, so it does not resurrect stale APs from
    # previous scans, while protecting the inventory from transient omissions.
    passes = max(1, min(int(os.environ.get("WIFI_WINDOWS_SCAN_PASSES", "3")), 5))
    interval = max(0.0, min(float(os.environ.get("WIFI_WINDOWS_SCAN_INTERVAL", "0.8")), 2.0))
    unique = {}
    for attempt in range(passes):
        text = fresh_windows_scan()
        for row in _parse_windows_snapshot(text, clean_bssid, normalize_security):
            unique[row["bssid"]] = row
        if attempt + 1 < passes and interval:
            time.sleep(interval)
    return list(unique.values())

def scan_linux(clean_bssid, normalize_security):
    p=subprocess.run(["nmcli","-t","-f","SSID,BSSID,CHAN,SIGNAL,SECURITY","dev","wifi","list"],capture_output=True,text=True,encoding="utf-8",errors="ignore")
    rows=[]
    for line in p.stdout.splitlines():
        m=re.search(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})",line)
        if not m: continue
        bssid=clean_bssid(m.group(1)); before,after=line[:m.start()],line[m.end():]; ssid=before.rstrip(":").replace("\\:",":") or "<hidden>"; vals=after.split(":"); nums=[int(x) for x in vals if x.isdigit()]; channel=next((x for x in nums if 1<=x<=233),None); signal=next((str(x)+"%" for x in nums if 0<=x<=100),"N/A"); security=normalize_security(vals[-1] if vals else "UNKNOWN"); rows.append({"ssid":ssid,"bssid":bssid,"channel":channel,"signal":signal,"security":security})
    return rows

def discover(clean_bssid, normalize_security):
    try: return scan_windows(clean_bssid, normalize_security) if platform.system()=="Windows" else scan_linux(clean_bssid, normalize_security)
    except Exception: return []
