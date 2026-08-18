
import unittest
from app import normalize_security

class V8Tests(unittest.TestCase):
    def test_windows_security_values(self):
        self.assertEqual(normalize_security("WPA2-Personal"), "WPA2")
        self.assertEqual(normalize_security("WPA3-Personal"), "WPA3")
        self.assertEqual(normalize_security("Open"), "OPEN")
        self.assertEqual(normalize_security("WEP"), "WEP")

if __name__ == "__main__":
    unittest.main()
