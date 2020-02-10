from scapy.all import *
# import local, modified version of mac_vendor_lookup
from mac_vendor_lookup import MacLookup

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

sniff(iface="wlp2s0mon", prn=PacketHandler)