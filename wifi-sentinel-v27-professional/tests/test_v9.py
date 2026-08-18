
import unittest
from app import classify_ap_status, correlated_alerts

class V9Tests(unittest.TestCase):
    def test_unapproved_is_not_automatically_rogue(self):
        approved=[{"bssid":"AA:BB:CC:DD:EE:FF","ssid":"CorpWiFi"}]
        ap={"bssid":"11:22:33:44:55:66","ssid":"GuestWiFi","security":"WPA2",
            "fingerprint_score":0,"anomaly_score":0}
        self.assertEqual(classify_ap_status(ap, approved), "Unapproved")

    def test_same_ssid_different_bssid_is_suspicious(self):
        approved=[{"bssid":"AA:BB:CC:DD:EE:FF","ssid":"CorpWiFi"}]
        ap={"bssid":"11:22:33:44:55:66","ssid":"CorpWiFi","security":"WPA2",
            "fingerprint_score":0,"anomaly_score":0}
        self.assertEqual(classify_ap_status(ap, approved), "Suspicious")

    def test_correlation(self):
        alerts=[
            {"bssid":"AA:AA:AA:AA:AA:AA","title":"Unapproved access point","severity":"Medium"},
            {"bssid":"AA:AA:AA:AA:AA:AA","title":"Unapproved access point","severity":"High"},
        ]
        self.assertEqual(len(correlated_alerts(alerts)),1)
        self.assertEqual(correlated_alerts(alerts)[0]["severity"],"High")

if __name__=="__main__":
    unittest.main()
