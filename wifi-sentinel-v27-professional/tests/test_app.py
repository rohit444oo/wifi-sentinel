
import os, tempfile, unittest
os.environ["WIFI_SENTINEL_API_KEY"]="test-key"
from app import app, init_db, DB

class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.client=app.test_client()
    def test_health_requires_api_key(self):
        r=self.client.get("/api/status")
        self.assertEqual(r.status_code,401)
        r=self.client.get("/api/status",headers={"X-API-Key":"test-key"})
        self.assertEqual(r.status_code,200)
    def test_dashboard(self):
        self.assertEqual(self.client.get("/").status_code,200)
if __name__=="__main__":
    unittest.main()
