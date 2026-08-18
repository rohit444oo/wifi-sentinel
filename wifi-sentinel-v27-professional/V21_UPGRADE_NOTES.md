# Wi-Fi Sentinel v21 — Safe Upgrade Notes

## What changed

- Preserved the working v20 application and database.
- Added read-only `/api/health` service health endpoint.
- Added read-only `/api/telemetry` endpoint for dashboard metrics.
- Added `/api/export/summary.json` for authenticated JSON summary export.
- Added a lightweight live health indicator to the v20 SOC page.
- No active Wi-Fi attacks, packet injection, deauthentication, or network modification were added.
- Existing routes and templates were preserved.

## Verification

Run:

```powershell
python app.py
```

Then open:

- http://127.0.0.1:5000/login
- http://127.0.0.1:5000/soc

After login, verify:

```text
GET /api/health
GET /api/telemetry
```

## Rollback

Keep the previous v20 ZIP as the rollback copy. The v21 package does not modify your original ZIP.
