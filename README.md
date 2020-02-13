# Network Kit

## Scapy

Install `scapy`:

```
pip3 install scapy
```

### PacketHandler, meet sniff:

`sniff` has a friend, in the form of a *callback* named PacketHandler. This is continuation-passing style. When the sniffer sniffs, the PacketHandler handles packets.

```python
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
          # dump_packet(packet)

sniff(iface="wlan0", prn = PacketHandler)
```

These Scripts use the enviorment var `WIFI_INTERFACE` to get the wireless interface for the system. 

Find your interfaces: 

```
$ ifconfig
eno1: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        ether f0:1f:af:37:4b:40  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
        device interrupt 20  memory 0xe6f00000-f9e20000  
```

Then set the inerface by setting an enviorment var

```
WIFI_INTERFACE = "eno1"
```

### traffic.py

This is script is a good entry point to learn about packets, network layers, and Scapy. Use it to inspect network traffic while authenticated at an *Access Point*. 

```
$ sudo python3 traffic.py
```

## Bash tricks and tools

This section will be expanded. 

### What ports are doing things?

```
sudo netstat -atunp 

sudo nmap -sT -O localhost

ss -l 
```

## 

