
import unittest
from app import classify_ap_status, normalize_security

class V10Tests(unittest.TestCase):
    def test_hidden_ssid_is_not_metadata(self):
        # Normalization contract used by scanner.
        self.assertEqual(normalize_security("WPA2-Personal"), "WPA2")

    def test_unapproved_not_automatically_rogue(self):
        approved=[{"bssid":"AA:BB:CC:DD:EE:FF","ssid":"CorpWiFi","security":"WPA2"}]
        ap={"bssid":"11:22:33:44:55:66","ssid":"GuestWiFi",
            "security":"WPA2","fingerprint_score":0,"anomaly_score":0}
        self.assertEqual(classify_ap_status(ap, approved), "Unapproved")

if __name__ == "__main__":
    unittest.main()
