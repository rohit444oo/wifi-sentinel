
import os, unittest
os.environ["WIFI_SENTINEL_API_KEY"]="test-key"
from app import app

class V5Tests(unittest.TestCase):
    def setUp(self):
        self.client=app.test_client()
    def test_incidents_api_protected(self):
        self.assertEqual(self.client.get("/api/incidents").status_code,401)
        r=self.client.get("/api/incidents",headers={"X-API-Key":"test-key"})
        self.assertEqual(r.status_code,200)
    def test_sensor_register(self):
        r=self.client.post("/api/sensor/register",headers={"X-API-Key":"test-key"},
                           json={"name":"test-sensor","location":"lab"})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json["name"],"test-sensor")
if __name__=="__main__":
    unittest.main()
