import re

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
    return (x or "").strip().upper().replace("-", ":")

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
