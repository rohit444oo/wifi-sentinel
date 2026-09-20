import os, unittest
os.environ["WIFI_SENTINEL_API_KEY"] = "test-key"

from app import app, clean_bssid, normalize_security, posture_for, fingerprint_similarity

class SecurityAndFixesTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_posture_for_unknown_or_enterprise_security(self):
        """Ensure posture_for does not crash on unlisted security suites (e.g. WPA-ENTERPRISE, 802.1X)."""
        res = posture_for([{"security": "WPA-ENTERPRISE"}, {"security": "802.1X"}, {"security": "WPA2"}])
        self.assertIn("score", res)
        self.assertGreaterEqual(res["score"], 0)
        self.assertEqual(res["total"], 3)

    def test_clean_bssid_hyphen_normalization(self):
        """Ensure clean_bssid normalizes hyphens from Windows adapters to IEEE standard colons."""
        self.assertEqual(clean_bssid("00-11-22-33-44-55"), "00:11:22:33:44:55")
        self.assertEqual(clean_bssid("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(clean_bssid("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF")

    def test_monitoring_api(self):
        """Ensure /api/monitoring endpoints respond properly."""
        r = self.client.get("/api/monitoring")
        self.assertEqual(r.status_code, 200)
        self.assertIn("monitoring", r.json)

        r = self.client.post("/api/monitoring", headers={"X-API-Key": "test-key"}, json={"enabled": True})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json["monitoring"], True)

    def test_fingerprint_similarity_identical(self):
        """Ensure fingerprint_similarity returns 1.0 for matching attributes."""
        a = {"ssid": "Corporate", "vendor": "Apple", "channel": 6, "security": "WPA2", "signal": 75}
        self.assertAlmostEqual(fingerprint_similarity(a, a), 1.0)

    def test_api_incidents_endpoint(self):
        """Ensure /api/incidents returns list of incidents under auth."""
        r = self.client.get("/api/incidents", headers={"X-API-Key": "test-key"})
        self.assertEqual(r.status_code, 200)
        self.assertIsInstance(r.json, list)

if __name__ == "__main__":
    unittest.main()
