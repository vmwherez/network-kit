# WiFi Monitor Mode With Scapy

## Introduction

In this demonstration we will monitor local network traffic without being connected to any network.  We will utilize the Scapy library in Python. For entering monitor mode, I've found the best luck with `airmon-ng` but you may have to fuss with your wireless interface. An extra network interface is helpful. Make sure the wifi on your system supports monitor mode.

### Find your wireless device name:

```
ifconfig
```

### Enable / disable monitor mode on the wireless interface  

```
sudo airmon-ng start wlan0
sudo airmon-ng stop wlan0mon
```

### ap.py

A basic demonstration of Scapy, filters by packet type 0 and packet subtype 8 to find *Access Points*. It displays the *MAC address* (`XX:XX:XX:XX:XX:XX`) and *BSSID*.

```
$ sudo python3 ap.py 
XX:XX:XX:XX:XX:XX | belkin.d04
XX:XX:XX:XX:XX:XX | MySpectrumWiFi0F-2G
XX:XX:XX:XX:XX:XX | WIN_402298
XX:XX:XX:XX:XX:XX | NETGEAR34
XX:XX:XX:XX:XX:XX | Free Stuff
XX:XX:XX:XX:XX:XX | WIN_801668
```



### clients.py

This script looks for *management frames* (type 0,2, or 4) to find clients. Some management frames are also sent by *Access Points*, so we use a vendor look up to help better identify client devices. Note: this demonstration utilized more than one network interface in order to download the updated vendor list; alternatively one could download a text file. **Having an extra network connection is helpful.**

```
$ sudo python3 clients.py
XX:XX:XX:XX:XX:XX | Motorola Mobility LLC, a Lenovo Company
XX:XX:XX:XX:XX:XX | Hewlett Packard
XX:XX:XX:XX:XX:XX | Apple, Inc
XX:XX:XX:XX:XX:XX | Samsung Electronics Co.,Ltd

```

### air.py

This is a simple script to filter for send and receive addresses `p.addr1, p.addr2` and display what is talking to who. It also utilizes a modified version of `mac_vendor_lookup.py`. You can also grab a MAC from here. The `PacketHandler` *callback* is not filtered like `ap` or `client` and you will probably see a more diverse range of devices.

```
$ sudo python3 air.py
XX:XX:XX:XX:XX:XX -> XX:XX:XX:XX:XX:XX
Actiontec Electronics, Inc -> Liteon Technology Corporation


XX:XX:XX:XX:XX:XX -> XX:XX:XX:XX:XX:XX
Actiontec Electronics, Inc -> Nintendo Co.,Ltd

...
```

You may want to `grep` only for a specific MAC to see who specifically is talking to exactly what:

```
sudo python3 air.py | grep -A1 XX:XX:XX:XX:XX:XX
```

Or, write the statements printed to *stdout* to a file:

```
sudo python3 air.py > traffic.txt
```

### mac.py

For this example we can take a MAC address gleaned from the previous demonstrations, and using the `sys` library, pass that MAC to our `PacketHandler` callback as a command-line argument,  and display a `hexdump`:

```
$ sudo python3 mac.py XX:XX:XX:XX:XX:XX

XX:XX:XX:XX:XX:XX | Free Stuff
0000  000012002E48000010029909A000C407 .....H..........
0010  000080000000FFFFFFFFFFFFBADEAFFE ................
0020  0000BADEAFFE0000A073000000000000 .........s......
0030  000064003104000A4672656520537475 ..d.1...Free Stu
0040  6666010882848B960C12182403010105 ff.........$....
0050  04010200002EE06216               .......b.

```

## Conclusion

In this demonstration we learned a little bit about `scapy`, network layers, packets, and our neighbor's affinity for Apple or Android. From here there is a a lot more to explore. Proceed responsibly and at at your own risk!
