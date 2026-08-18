
import os, unittest
os.environ["WIFI_SENTINEL_API_KEY"]="test-key"
from app import app, normalize_security, fingerprint_similarity

class V6Tests(unittest.TestCase):
    def setUp(self):
        self.client=app.test_client()
    def test_security_parser(self):
        self.assertEqual(normalize_security("WPA2-Personal"),"WPA2")
        self.assertEqual(normalize_security("WPA3-Personal"),"WPA3")
        self.assertEqual(normalize_security("Open"),"OPEN")
    def test_timeline_api_key(self):
        self.assertEqual(self.client.get("/api/timeline").status_code,401)
        self.assertEqual(self.client.get("/api/timeline",headers={"X-API-Key":"test-key"}).status_code,200)
    def test_fingerprint_similarity(self):
        a={"ssid":"A","vendor":"V","channel":48,"security":"WPA2","signal":80}
        self.assertGreater(fingerprint_similarity(a,a),0.9)
if __name__=="__main__":
    unittest.main()
