# Wi-Fi Sentinel v27 — Professional Security Platform

## Scope

v27 applies the project-specific requirements while preserving the stable v23/v26 architecture.

## Major engineering upgrades

- Protected assessment and mutation operations by role.
- API authentication supports local sessions and `X-API-Key`.
- Removed duplicate `/api/health` route.
- Corrected SOC queries to match the current scan schema.
- Fixed duplicate ARP entries.
- LAN discovery is cache-first; active probing is explicit.
- Added scanner capability reporting and Windows RF limitations.
- Added tamper-evident discovery snapshots for assessment evidence.
- Added scan evidence API.
- Added SQLite busy timeout and WAL mode for better concurrent reliability.
- Added configurable Flask session secret.
- Improved empty-state honesty: no assessment is not shown as a healthy 100/100 result.

## Detection model

Unknown remains distinct from malicious. Risk remains explainable through identity, security, baseline, behavior, and fingerprint factors.

## Windows limitation

Windows WLAN discovery can enumerate nearby access points exposed by the adapter, but it cannot reliably enumerate every Wi-Fi client in RF range. Full over-the-air client visibility requires a monitor-mode-capable sensor.
