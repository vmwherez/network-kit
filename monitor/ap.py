#!/usr/bin/env python

from scapy.all import Dot11, sniff
                       

aps = []

def PacketHandler(p) :
    if p.haslayer(Dot11) :
        if p.type == 0 and p.subtype == 8:
            if p.addr2 not in aps:    
                aps.append(p.addr2)
                print(str(p.addr2) + " | " + p.info.decode("utf-8"))


sniff(iface="wlp2s0mon", prn = PacketHandler)