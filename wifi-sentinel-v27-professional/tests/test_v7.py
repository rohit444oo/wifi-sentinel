
import unittest
from app import normalize_security, posture_for, trust_score

class V7Tests(unittest.TestCase):
    def test_security(self):
        self.assertEqual(normalize_security("WPA2-Personal"), "WPA2")
        self.assertEqual(normalize_security("WPA3-Personal"), "WPA3")
        self.assertEqual(normalize_security("Open"), "OPEN")
    def test_posture(self):
        p=posture_for([{"security":"WPA2","risk":5}])
        self.assertEqual(p["counts"]["WPA2"],1)
        self.assertGreaterEqual(p["score"],90)
    def test_trust(self):
        self.assertGreater(trust_score({"risk":0,"anomaly_score":0,"fingerprint_score":0,"security":"WPA3"}),80)

if __name__=="__main__":
    unittest.main()
