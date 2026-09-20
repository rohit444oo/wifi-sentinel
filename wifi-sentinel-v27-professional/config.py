from pathlib import Path
import os

BASE = Path(__file__).resolve().parent
DB = BASE / "wifi_sentinel.db"
SECRET_KEY = os.environ.get("WIFI_SENTINEL_SECRET", "change-this-local-secret")
ADMIN_USER = "admin"
ADMIN_PASS = os.environ.get("WIFI_ADMIN_PASS", "sentinel")
