import unittest

def correlated_alerts(alerts_list):
    priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    unique = {}
    for alert in alerts_list or []:
        key = (alert["bssid"].lower(), alert["title"].strip().lower())
        current = unique.get(key)
        if current is None or priority.get(alert["severity"],0) > priority.get(current["severity"],0):
            unique[key] = dict(alert)
    return list(unique.values())

class TestAlertCorrelation(unittest.TestCase):
    def test_duplicates_collapse(self):
        alerts=[
            {"bssid":"AA:BB:CC:DD:EE:FF","title":"Unapproved access point","severity":"Medium"},
            {"bssid":"AA:BB:CC:DD:EE:FF","title":"Unapproved access point","severity":"High"}
        ]
        result=correlated_alerts(alerts)
        assert len(result)==1
        assert result[0]["severity"]=="High"

if __name__=="__main__":
    unittest.main()
