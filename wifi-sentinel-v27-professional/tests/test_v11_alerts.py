
import unittest

def correlate_current(alerts):
    seen=set()
    out=[]
    for a in alerts:
        key=(a["bssid"].lower(), a["message"].strip().lower())
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out

class TestV11Alerts(unittest.TestCase):
    def test_same_finding_different_titles_is_one_alert(self):
        alerts=[
            {"bssid":"AA:BB:CC:DD:EE:FF","title":"Low wireless finding",
             "message":"BSSID not in approved inventory","severity":"Low"},
            {"bssid":"AA:BB:CC:DD:EE:FF","title":"Low wireless finding",
             "message":"BSSID not in approved inventory","severity":"Low"},
        ]
        self.assertEqual(len(correlate_current(alerts)),1)

if __name__=="__main__":
    unittest.main()
