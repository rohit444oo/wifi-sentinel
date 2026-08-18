# Wi-Fi Sentinel v29 — Alert Correlation Fix

Live testing exposed a logic issue: an unverified WPA2 AP at 18/100 was still
creating repeated low-severity alerts.

Root cause:
save_results() generated a generic alert for every non-authorized AP, bypassing
the evidence-based advanced alert suppression logic.

Fix:
- Unverified status alone no longer creates a security alert.
- Low-risk first observations remain evidence and baseline records.
- Alerts require meaningful indicators: spoof evidence, material baseline change,
  weak encryption, behavioral anomaly, or elevated risk.
- Existing evidence, baseline, incident and reporting behavior is preserved.

Expected normal new WPA2 AP:
Status = Unverified
Risk ≈ 18/100
Security event = none
Evidence = retained
Baseline = retained
