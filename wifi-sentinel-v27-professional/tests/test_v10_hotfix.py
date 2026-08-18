
import unittest
from app import correlated_alerts

class HotfixTests(unittest.TestCase):
    def test_correlated_alerts_exists_and_deduplicates(self):
        alerts = [
            {"bssid":"AA:BB:CC:DD:EE:FF","title":"Unapproved access point","severity":"Medium"},
            {"bssid":"AA:BB:CC:DD:EE:FF","title":"Unapproved access point","severity":"High"},
        ]
        result = correlated_alerts(alerts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "High")

if __name__ == "__main__":
    unittest.main()
