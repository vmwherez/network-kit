#!/usr/bin/env python
from scapy.all import RadioTap, Dot11, Dot11Elt, sniff, hexdump
import sys

MAC = str(sys.argv[1]) 
print ("Hexdump of: %s" % MAC)
                       

def PacketHandler(p) :
    if p.addr2 == MAC:
     print(p[RadioTap].addr2 + ' | ' + str(p[Dot11Elt].info.decode("utf-8")))
     hexdump(p)
           

sniff(iface="wlp2s0mon", prn = PacketHandler)