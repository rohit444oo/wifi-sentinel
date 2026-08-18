# 🛡️ Wi-Fi Sentinel v3

## Major Project — Wireless Security Assessment & Rogue AP Detection Platform

### Implemented upgrades
1. Professional security dashboard
2. Scan history
3. AP details/history page
4. Explainable 0–100 risk engine
5. Possible rogue AP detection
6. Security configuration analysis
7. BSSID/OUI vendor enrichment
8. Baseline + change detection
9. CSV + PDF security reports
10. Real-time-style alert feed generated during scans
11. REST summary/scan API
12. Local analyst login scaffold
13. Sensor-ready database schema
14. Deterministic anomaly scoring

### Run
```powershell
cd "C:\Users\rohit\Downloads\wifi-rogue-ap-platform"
python -m venv venv
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

PowerShell activation is optional. If `Activate.ps1` is blocked, simply run `python app.py`.

### Demo
1. Run a scan.
2. Add an AP you are authorized to manage to the inventory.
3. Run another scan.
4. Compare Authorized vs Possible Rogue / Configuration Mismatch.
5. Open an AP for observation history.
6. Open Scan History and Alerts.
7. Export CSV/PDF.

### Risk model
The score combines:
- unknown BSSID
- approved SSID + different BSSID
- security mismatch
- weak/absent encryption
- baseline changes
- new AP detection

The score is intentionally explainable. An unknown BSSID is a **possible rogue indicator**, not proof of malicious activity.

### Important
The local login is a demonstration scaffold; change the demo credentials before any real deployment. The app is for authorized defensive monitoring only. It does not crack passwords, capture credentials, perform deauthentication, or deploy fake access points.


## v4 upgrades
- Live auto-scanning with configurable 15/30/60 second polling
- Real-time-style dashboard refresh
- New AP and previously observed AP disappearance alerts
- Possible SSID spoof detection
- Security downgrade alerts
- Risk timeline API and dashboard visualization
- RBAC roles: admin / analyst / viewer
- API key protected endpoints
- Optional Telegram and SMTP email notifications
- Dockerfile + docker-compose
- Automated unit tests + GitHub Actions
- Sensor-ready architecture for future distributed monitoring

### Live scanning
The browser uses `/api/auto-scan`. Set `WIFI_SENTINEL_API_KEY` and place the same key in browser localStorage as `wifiSentinelApiKey` if API protection is enabled. For a local demo, the default development key is `change-this-api-key`.

### Alerts
Notifications are optional. No credentials are included in the project. Configure them through environment variables or `.env` when you own the notification accounts.

### Security note
The dashboard is a defensive monitoring tool. It does not perform deauthentication, password cracking, credential capture, or fake AP deployment.


## v5 major security-monitoring upgrades

### 1. Advanced Rogue AP Fingerprinting
Combines SSID, BSSID, vendor, channel, security and signal history. Fingerprint anomalies are explainable and contribute to risk instead of being treated as proof of compromise.

### 2. Behavioral Baseline + ML Anomaly Detection
Historical observations form a behavioral baseline. If scikit-learn is installed, an IsolationForest model scores unusual combinations of signal/channel/security/risk. A deterministic fallback keeps the app functional.

### 3. Multi-Sensor Architecture
Sensors can register with `/api/sensor/register` and send events to `/api/sensor/event`. Sensor metadata and raw JSON events are stored for future centralized deployments.

### 4. Incident + Evidence System
High/Critical alerts can become incidents. Alert and observation snapshots are preserved with SHA-256 evidence hashes, timestamps, investigation status and close workflow.

### 5. SOC/SIEM Integration
Alerts can be forwarded as JSON to `SIEM_WEBHOOK_URL` and are retained in a SIEM event audit table. This provides a clean integration point for SOC tooling.

## API examples

Use the configured API key:
```powershell
$headers=@{"X-API-Key"="YOUR_KEY"}
Invoke-RestMethod http://127.0.0.1:5000/api/incidents -Headers $headers
```

Register a sensor:
```json
{"name":"lab-sensor-01","location":"Cyber Lab"}
```

Send a sensor event:
```json
{"sensor_name":"lab-sensor-01","location":"Cyber Lab","observations":[]}
```

## Safety
Only use sensors and scans in networks you own or are authorized to monitor. The platform is defensive: it does not deauthenticate clients, crack Wi-Fi passwords, capture credentials, or deploy fake access points.


## v6 reliability upgrades
- Robust Windows `netsh wlan show networks mode=bssid` parsing
- Authentication-based WPA/WPA2/WPA3 classification
- Per-scan BSSID de-duplication
- OS scan cache refresh attempt before discovery
- First scan initializes baseline without false "New AP" alerts
- Duplicate open-alert suppression
- Browser session accepted for protected timeline/discovery APIs
- `/discovery` diagnostics page and `/api/discovery`
- Wireless backend metadata
- Passive-only discovery; no deauthentication or credential capture


## v7 major upgrades
- Robust Windows authentication/security parsing
- Wireless Security Posture score and policy classification
- Per-AP Trust Score combining risk, anomaly, fingerprint and security posture
- `/posture` dashboard and `/api/posture`
- `/api/health` health endpoint
- Cleaner baseline semantics and alert correlation foundation
- Existing rogue fingerprinting, ML anomaly detection, incidents/evidence, multi-sensor APIs and SIEM integration retained


## v8 final fixes
- Reworked Windows scan parser to parse SSID sections and BSSID blocks robustly.
- Correctly reads `Authentication: WPA2-Personal` as WPA2.
- Removed forced WLAN disconnect from scanning.
- Dashboard now rehydrates Trust, Policy, Fingerprint and Anomaly fields.
- Added `/api/scan-debug` to verify exactly what the OS scanner returns.
- Existing discovery, baseline, rogue detection, ML, incidents, evidence, sensors, SIEM and posture features remain.


## v9 final detection polish
- Unknown/unapproved APs are no longer automatically labeled "Possible Rogue".
- Evidence-based states: Authorized, Unapproved, Suspicious, Possible Rogue, Policy Violation.
- Alert correlation collapses duplicate findings.
- Unchanged active findings are suppressed until they materially change.
- Dashboard messaging explicitly distinguishes unapproved from malicious.
- Added detection-state documentation and tests.


## v10 final fixes
- Fixed hidden SSID parsing: blank SSIDs are displayed as `<hidden>` instead of `Network type : Infrastructure`.
- Fixed evidence-based AP classification so an unapproved BSSID is not automatically called `Possible Rogue`.
- `Possible Rogue` requires multiple independent suspicious indicators.
- WPA2/WPA3/Open/WEP classification remains normalized from Windows Authentication fields.
- Duplicate active alerts are suppressed.


## v10 hotfix
- Fixed `NameError: correlated_alerts is not defined` during POST `/scan`.
- Added regression test for alert correlation.


## v10 final hotfix 2
- Guaranteed `correlated_alerts()` is defined before `/scan` calls it.
- Added static verification and regression test for the exact NameError.


## v11 alert cleanup
- Suppresses duplicate active alerts by BSSID + normalized finding message.
- Dashboard scan message now reports alerts actually created, not raw duplicate candidates.
- Cleaner `Unapproved AP` alert title.
- Clarifies that Windows discovery reports APs currently visible to the OS.


## v12 Premium UI
- Clean, Google-inspired visual system with restrained colors and generous whitespace.
- Responsive cards, KPI hierarchy, badges, meters, tables and forms.
- Mobile-friendly layout.
- Keeps the existing security features and routes.
- Focuses on clarity over visual clutter.


## v13 Dark Premium UI
- Deep graphite/charcoal appearance by default.
- Google-inspired restrained blue accent and accessible severity colors.
- Premium dark cards, subtle borders, compact typography and generous spacing.
- Responsive navigation and tables.
- No neon cyberpunk styling; focus stays on security data.


## v14 Product Copy
- Reworked interface text for concise, professional security-product language.
- Uses clear terms such as Trusted APs, Untrusted APs, Security posture, Risk over time, and Security findings.
- Keeps the defensive-monitoring context visible without clutter.


## v15 Layout
- Rebalanced dashboard hierarchy and spacing.
- Added a restrained wireless-network visual motif instead of stock imagery.
- Improved section grouping, cards, tables and scan controls.
- Dark premium appearance remains the default.


## v16 UI redesign
A full dark product-style dashboard redesign with sidebar navigation, hero command center, KPI hierarchy, risk chart, posture card, alert feed, AP table, trusted inventory, and responsive layout.


## v17 Security Intelligence
- Full AP investigation center with first/last seen, behavior history and related alerts.
- Explainable risk breakdown: identity, security, baseline, behavior and fingerprint.
- SSID spoof indicator when a trusted SSID appears from a different BSSID.
- Fingerprint match/deviation scoring.
- Behavioral anomaly scoring using observed wireless changes.
- Channel/security change tracking.
- AP search/filter on the main dashboard.
- Existing passive Windows/Linux discovery, inventory, alerts, incidents, posture and reporting retained.

## v18 Enterprise upgrades
- LAN-visible device discovery via ARP + ICMP on the local private subnet.
- Wireless AP discovery remains passive through the OS Wi-Fi interface.
- IsolationForest anomaly scoring when enough observations are available.
- Multi-sensor registration/heartbeat APIs.
- SIEM-ready JSON event endpoint at `/siem/events.json`.
- High/Critical alerts can create evidence-backed incidents.
- Important: a normal Windows Wi-Fi adapter cannot reliably enumerate every Wi-Fi client in RF range. Full over-the-air client discovery requires a monitor-mode-capable sensor/driver. The Devices page therefore distinguishes LAN-visible devices from nearby APs.
