from scapy.all import Dot11, sniff

import os
WIFI_INTERFACE = os.getenv('WIFI_INTERFACE')

# List of Access Points
aps = []

"""
type 0: Management Frame
subtype 8: Beacon subtype, Bitfield: 1000, 0x08
https://community.cisco.com/t5/wireless-mobility-documents/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/
"""
def PacketHandler(p) :
    if p.haslayer(Dot11) :
        if p.type == 0 and p.subtype == 8:
            if p.addr2 not in aps:    
                # If we haven't seen this Access Point, add it to our list
                aps.append(p.addr2)
                print(str(p.addr2) + " | " + p.info.decode("utf-8"))


sniff(iface=WIFI_INTERFACE, prn = PacketHandler)