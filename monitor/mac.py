from scapy.all import RadioTap, Dot11, Dot11Elt, sniff, hexdump
import sys

import os
WIFI_INTERFACE = os.getenv('WIFI_INTERFACE')


MAC = str(sys.argv[1]) 
print ("Hexdump of: %s" % MAC)
                       
"""
p.addr1: recieve
p.addr2: send

Maybe this could be expanded 
to include sys.argv[2] as snd/rcv
and look up vendor...
"""
def PacketHandler(p) :
    if p.addr2 == MAC:
     print(p[RadioTap].addr2 + ' | ' + str(p[Dot11Elt].info.decode("utf-8")))
     hexdump(p)
           

sniff(iface=WIFI_INTERFACE, prn = PacketHandler)