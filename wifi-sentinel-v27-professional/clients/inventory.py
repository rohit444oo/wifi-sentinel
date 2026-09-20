"""Defensive client inventory helpers.

This module deliberately reports only telemetry the current application can
actually observe. It does not infer Wi-Fi AP association from an ARP cache.
"""

def lan_visible_clients(c, limit=200):
    """Return recently observed LAN-visible client assets.

    The current Windows client scanner discovers devices visible on the local
    LAN. Without AP/controller telemetry, these records are not claimed to be
    associated with a particular wireless AP.
    """
    return [dict(r) for r in c.execute(
        "SELECT ip, mac, hostname, vendor, source, first_seen, last_seen, seen_count "
        "FROM network_devices ORDER BY last_seen DESC LIMIT ?", (int(limit),)
    )]
