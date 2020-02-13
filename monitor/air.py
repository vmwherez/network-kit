from scapy.all import sniff
# import local, modified version of mac_vendor_lookup 
from mac_vendor_lookup import MacLookup

import os
WIFI_INTERFACE = os.getenv('WIFI_INTERFACE')

mac = MacLookup()
mac.load_vendors()  


def find_mac(mac_address):
     return mac.lookup(mac_address)  

"""
Show send/receive 
"""
def PacketHandler(p):
    sn = p.addr2
    rc = p.addr1
    print(str(sn) + ' -> ' +  str(rc))
    print(find_mac(sn) + ' -> ' +  find_mac(rc))
    print("\n")

sniff(iface=WIFI_INTERFACE, prn=PacketHandler)