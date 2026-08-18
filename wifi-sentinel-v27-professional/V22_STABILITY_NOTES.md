# Wi-Fi Sentinel v22 — Stability Upgrade

This build is based on the working v21 package.

Changes:
- Removes duplicate `/soc` Flask route while retaining the premium `soc_v20.html` route.
- Adds safe alert deduplication helpers.
- Adds explicit passive-monitoring state with Start/Stop control.
- Keeps discovery passive and does not add packet injection, deauthentication, or other disruptive behavior.
- Preserves the existing SQLite database and application modules.

Verification:
1. Start with `python app.py`.
2. Open `/login`.
3. Sign in as an authorized role.
4. Open `/soc`.
5. Confirm the monitoring control appears.
6. Confirm `/api/monitoring` returns 200 after login.
7. Run a scan and verify repeated identical findings do not multiply within the same result set.
