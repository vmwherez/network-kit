from scapy.all import *

from mac_vendor_lookup import MacLookup

mac = MacLookup()
mac.load_vendors()  

# List of clients
observedclients = []

def find_mac(mac_address):
     return mac.lookup(mac_address)  


def PacketHandler(p):
    # List of client-transmitted management frame types, incomplete since
    # some management frames are sent by both clients and APs
    stamgmtstypes = (0, 2, 4)
    if p.haslayer(Dot11):
        
        if p.type == 0 and p.subtype in stamgmtstypes:
            if p.addr2 not in observedclients:                
                print(str(p.addr2) + ' | ' + find_mac(p.addr2))
                observedclients.append(p.addr2)
                # Deauth 
                # sendp(RadioTap()/Dot11(type=0,subtype=12,addr1=p.addr2,addr2=p.addr3,addr3=p.addr3)/Dot11Deauth())


sniff(iface="wlp2s0mon", prn=PacketHandler)