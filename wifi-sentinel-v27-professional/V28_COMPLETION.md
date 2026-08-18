# Wi-Fi Sentinel v28

Completed remaining hardening:
- Windows SSID metadata parsing guard.
- Evidence-based risk scoring; no fixed untrusted=30 rule.
- Historical behavioral anomaly detection instead of current-scan ML outliers.
- Stronger AP fingerprinting using historical vendor/channel/security/band/radio.
- Unverified-only observations no longer create noisy security events.
- Band/radio history persisted in baseline.
- Explicit LAN discovery action; fast ARP cache remains default.
- Existing application architecture, authentication, reporting, incidents and evidence preserved.

Windows limitation:
netsh WLAN discovery cannot enumerate every RF client in range. The project reports
LAN-visible devices and does not fabricate wireless-client telemetry.
