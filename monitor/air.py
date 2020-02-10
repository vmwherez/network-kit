from scapy.all import *
from mac_vendor_lookup import MacLookup

mac = MacLookup()
mac.load_vendors()  

aps = []


def find_mac(mac_address):
     return mac.lookup(mac_address)  # <- this will only take a few ms!

observedclients = []

def ShowSendRecieve(p):
    sn = p.addr2
    rc = p.addr1
    print(str(sn) + ' -> ' +  str(rc))
    print(find_mac(sn) + ' -> ' +  find_mac(rc))
    print("\n")

sniff(iface="wlp2s0mon", prn=ShowSendRecieve)