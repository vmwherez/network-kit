from scapy.all import Dot11, Dot3, ARP, UDP, TCP, IP, Raw, STP, sniff, hexdump


def dump_packet(p):
    print('Dumping Packet... ')
    print(p.show(dump=True))


def process_raw(p):
    if p.haslayer(Raw):
        load = p[Raw].load
        hexdump(load)
        print('\n')


def process_ip(p):
    if p.haslayer(TCP) :
        tcp = p[TCP]
        print(' # TCP #')
        print(' ' + p[IP].src + ':' + str(tcp.sport) + ' -> ' + p[IP].dst + ':'  + str(p.dport))
        print('\n')
    elif p.haslayer(ARP) :
         print(p[ARP].show())
    else:
          print('cannot find ARP or TCP')
          dump_packet(p)


def PacketHandler(p) :

    if p.haslayer(IP) :
        print('## IP ##')
        if not p.haslayer(Raw) :
                process_ip(p)
        else:
                print(p[IP].src + ' -> ' + p[IP].dst + '\n')
                process_raw(p)

    elif p.haslayer(Dot3) :
          print('# 802.3 # ')
          print(p[Dot3].src + ' -> ' + p[Dot3].dst + '\n')
          # dump_packet(p)


sniff(iface="enp0s20u3", prn = PacketHandler)
