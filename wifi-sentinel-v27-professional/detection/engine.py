import re
SECURITY_BASE = {"OPEN":40,"WEP":35,"WPA":22,"WPA2":8,"WPA3":3,"UNKNOWN":18}

def ml_anomaly_scores(observations):
    """No cross-sectional ML score: behavior must be compared with AP history."""
    return {x.get("bssid"): 0 for x in (observations or []) if x.get("bssid")}

def _history_for(c, bssid, limit=30):
    return [dict(x) for x in c.execute(
        "SELECT * FROM observations WHERE bssid=? ORDER BY id DESC LIMIT ?", (bssid, limit)
    )]

def _median(values):
    vals=sorted(v for v in values if v is not None)
    if not vals: return None
    m=len(vals)//2
    return vals[m] if len(vals)%2 else (vals[m-1]+vals[m])/2

def _mode(values):
    vals=[v for v in values if v not in (None, "", "N/A")]
    if not vals: return None
    return max(set(vals), key=vals.count)

def assess(rows, db_fn, clean_bssid_fn, normalize_security_fn, signal_int_fn, vendor_for_fn, enrich_trust_fn):
    """Evidence-driven wireless assessment with multi-factor rogue, spoof and behavior analysis."""
    c=db_fn()
    approved={clean_bssid_fn(r["bssid"]):dict(r) for r in c.execute("SELECT * FROM approved_aps")}
    baseline={clean_bssid_fn(r["bssid"]):dict(r) for r in c.execute("SELECT * FROM baseline")}
    histories={}
    for raw in rows or []:
        b=clean_bssid_fn(raw.get("bssid"))
        if re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", b): histories[b]=_history_for(c,b,30)
    c.close()
    results=[]

    for raw in rows or []:
        r=dict(raw); b=clean_bssid_fn(r.get("bssid"))
        if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", b): continue
        ssid=(r.get("ssid") or "<hidden>").strip() or "<hidden>"
        sec=normalize_security_fn(r.get("security")); prev=baseline.get(b); approved_ap=approved.get(b)
        same_ssid=[x for x in approved.values() if (x.get("ssid") or "").strip().lower()==ssid.lower()]
        hist=histories.get(b,[])
        changed=[]; reasons=[]
        identity=security=baseline_risk=behavior=fingerprint=0

        # Identity / authorization
        if approved_ap:
            status="Authorized"
            expected=normalize_security_fn(approved_ap.get("security"))
            if expected != sec:
                identity+=8; security+=18; changed.append("security configuration differs from authorized inventory")
                reasons.append(f"Security configuration differs from authorized inventory ({expected} → {sec})")
                status="Configuration Mismatch"
        else:
            identity+=18; reasons.append("BSSID is not present in the authorized inventory"); status="Unverified"
            if same_ssid:
                identity+=28; fingerprint+=25; reasons.append("Authorized SSID observed from a different BSSID")

        # Security posture
        security += SECURITY_BASE.get(sec, SECURITY_BASE["UNKNOWN"])
        if sec=="OPEN": security+=32; reasons.append("Open wireless security detected")
        elif sec=="WEP": security+=30; reasons.append("Legacy WEP security detected")
        elif sec=="WPA": security+=14; reasons.append("Legacy WPA security detected")

        # Historical baseline comparison
        if prev:
            if prev.get("channel") != r.get("channel"):
                baseline_risk+=8; changed.append("channel changed")
            if normalize_security_fn(prev.get("security")) != sec:
                baseline_risk+=14; changed.append("security changed")
            old,newsig=signal_int_fn(prev.get("signal")),signal_int_fn(r.get("signal"))
            if old is not None and newsig is not None:
                delta=abs(newsig-old)
                if delta>=35: baseline_risk+=9; changed.append("large signal deviation")
                elif delta>=20: baseline_risk+=4; changed.append("signal deviation")
            if (prev.get("band") or "")!=(r.get("band") or "") and (prev.get("band") or r.get("band")):
                baseline_risk+=7; changed.append("radio band changed")
            if (prev.get("radio") or "")!=(r.get("radio") or "") and (prev.get("radio") or r.get("radio")):
                baseline_risk+=6; changed.append("radio type changed")
            if changed: reasons.append("Historical baseline deviation: "+", ".join(changed))
        else:
            baseline_risk=2; reasons.append("First observation for this BSSID")

        # Behavioral persistence: compare current observation with recent history.
        prior=hist[1:] if len(hist)>1 else []
        prior_signals=[signal_int_fn(x.get("signal")) for x in prior]
        median_signal=_median(prior_signals)
        current_signal=signal_int_fn(r.get("signal"))
        if median_signal is not None and current_signal is not None:
            delta=abs(current_signal-median_signal)
            if delta>=25: behavior+=16; reasons.append(f"Signal behavior deviates from historical median by {delta} dB")
            elif delta>=15: behavior+=8
        prior_channels=[x.get("channel") for x in prior]
        if prior_channels and r.get("channel") not in prior_channels and len(prior_channels)>=3:
            behavior+=8; reasons.append("Current channel is outside the historical channel pattern")
        prior_sec=[normalize_security_fn(x.get("security")) for x in prior]
        if prior_sec and sec not in prior_sec and len(prior_sec)>=2:
            behavior+=12; reasons.append("Current security mode is outside the historical pattern")
        if len(changed)>=3: behavior+=10
        elif len(changed)==2: behavior+=5
        behavior=min(40,behavior)

        # Fingerprint similarity to trusted/historical identity.
        fp_match=100
        if not approved_ap and same_ssid: fp_match-=35
        if prev:
            if prev.get("channel")!=r.get("channel"): fp_match-=18
            if normalize_security_fn(prev.get("security"))!=sec: fp_match-=20
            if (prev.get("vendor") or "")!=vendor_for_fn(b): fp_match-=12
            if (prev.get("band") or "")!=(r.get("band") or "") and (prev.get("band") or r.get("band")): fp_match-=8
            if (prev.get("radio") or "")!=(r.get("radio") or "") and (prev.get("radio") or r.get("radio")): fp_match-=7
        fp_match=max(0,min(100,fp_match)); fingerprint=max(fingerprint,100-fp_match)

        spoof=bool(same_ssid and not approved_ap)
        # Composite score: identity, security, baseline, behavior and fingerprint.
        risk=round(min(100,
            .27*min(100,identity)+.22*min(100,security)+.17*min(100,baseline_risk)+
            .18*min(100,behavior)+.16*min(100,fingerprint)))
        if not approved_ap: risk=max(risk,18 if not same_ssid else 42)

        indicators={
            "trusted_ssid_impersonation": spoof,
            "security_downgrade": bool(prev and normalize_security_fn(prev.get("security"))!=sec),
            "weak_security": sec in ("OPEN","WEP","WPA"),
            "historical_behavior_anomaly": behavior>=20,
            "fingerprint_deviation": fp_match<65,
            "baseline_change": len(changed)>=2,
        }
        meaningful=sum(bool(v) for v in indicators.values())
        if status not in ("Authorized","Configuration Mismatch"):
            if meaningful>=3 and risk>=60: status="Suspected Rogue Access Point"
            elif spoof and meaningful>=2: status="Suspicious"
            elif risk>=40: status="Potentially Unauthorized"
            else: status="Unverified"

        risk=min(100,max(0,int(risk)))
        level="Critical" if risk>=85 else "High" if risk>=65 else "Medium" if risk>=40 else "Low"
        evidence_count=meaningful + int(bool(prev)) + int(bool(approved_ap))
        confidence=min(99,38+evidence_count*9)
        if status=="Authorized": confidence=96
        elif status=="Unverified": confidence=min(confidence,58)
        if meaningful>=4: confidence=min(99,confidence+5)
        reason="; ".join(dict.fromkeys(reasons)) or "Matches authorized inventory and historical baseline"
        results.append({
            **r,"ssid":ssid,"bssid":b,"security":sec,"vendor":vendor_for_fn(b),"status":status,"risk":risk,"level":level,
            "reason":reason,"changed":", ".join(dict.fromkeys(changed)),"anomaly":min(100,behavior*2.5),"anomaly_score":min(100,int(behavior*2.5)),
            "ml_anomaly":0,"identity_risk":min(100,int(identity)),"security_risk":min(100,int(security)),"baseline_risk":min(100,int(baseline_risk)),
            "behavior_risk":min(100,int(behavior)),"fingerprint_risk":min(100,int(fingerprint)),"fingerprint_match":int(fp_match),"fingerprint_score":int(fp_match),
            "spoof_indicator":spoof,"confidence":int(confidence),"evidence_count":int(evidence_count),
            "detection_indicators":indicators,
        })
    return enrich_trust_fn(results)
