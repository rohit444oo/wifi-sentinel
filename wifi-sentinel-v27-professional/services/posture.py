SECURITY_POLICY = {"OPEN":{"risk":35,"label":"Prohibited"},"WEP":{"risk":30,"label":"Prohibited"},"WPA":{"risk":18,"label":"Legacy"},"WPA2":{"risk":8,"label":"Allowed"},"WPA3":{"risk":2,"label":"Preferred"},"UNKNOWN":{"risk":15,"label":"Needs verification"}}

def posture_for(results):
    total = len(results)
    counts = {k: 0 for k in SECURITY_POLICY}
    for r in results:
        s = r.get("security", "UNKNOWN")
        if s not in SECURITY_POLICY:
            s = "UNKNOWN"
        counts[s] = counts.get(s, 0) + 1
    score = 100
    if total:
        total_risk = sum(counts[k] * SECURITY_POLICY[k]["risk"] for k in SECURITY_POLICY)
        score = max(0, round(100 - (total_risk / total)))
    return {"score": score, "counts": counts, "total": total}
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
