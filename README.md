# Protocol Analyzer

This is a small protocol analyzer that uses the packet capture pcap library (very similar to tcpdump and wireshark) to
read captured files, parse the packets, and identifies protocol information from the link,
network, transport, and application layers.
The meat of the pcap library is the call-back function pk_processor().
The library reads through the file when the function is called for each packet read.

Author: Nhan Tran
Skeleton code and support provided by Professor Phil Romig (Computer Networks 2018)


================================


### Compile the program:
```
make
```

================================


### Command line options:
```
  -f <filename>, where filename is the pcap file to process.
  -d #, Turn on debugging messages. The is a digit that indicates how verbose the messages should be. While you must accept the digit, you don’t have to adjust the verbosity if you don’t want to.
  -m, list unique mac addresses.
  -a, list unique IPv4 addresses.
  -t, list unique TCP port numbers.
  -u, list unique UDP port numbers.
```

================================

### How to run:

```
./packetstats -f ./sampleCaptureFiles/stp.pcap -m -a -t -u
```
```
./packetstats -f sample.pcap -m -a -t -u
```
================================
### Sample Output:

```
ethernet:
	Total Ethernet = 3
	Min Ethernet = 54
	Max Ethernet = 62
	Average Ethernet = 59.3333

IEEE:
	Total IEEE = 0
	Min IEEE = 0
	Max IEEE = 0
	Average IEEE = 0

ARP:
	Total ARP = 0
	Min ARP = 0
	Max ARP = 0
	Average ARP = 0

IPv4:
	Total IPv4 = 3
	Min IPv4 = 54
	Max IPv4 = 62
	Average IPv4 = 59.3333

IPv6:
	Total IPv6 = 0
	Min IPv6 = 0
	Max IPv6 = 0
	Average IPv6 = 0

otherNetwork:
	Total OtherNetwork = 0
	Min OtherNetwork = 0
	Max OtherNetwork = 0
	Average OtherNetwork = 0

TCP:
	Total TCP = 3
	Min TCP = 54
	Max TCP = 62
	Average TCP = 59.3333

UDP:
	Total UDP = 0
	Min UDP = 0
	Max UDP = 0
	Average UDP = 0

ICMP:
	Total ICMP = 0
	Min ICMP = 0
	Max ICMP = 0
	Average ICMP = 0

otherTransport:
	Total OtherTransport = 0
	Min OtherTransport = 0
	Max OtherTransport = 0
	Average OtherTransport = 0

Counts:
	Unique srcMac = 2
	Unique dstMac = 2
	Unique srcIPv4 = 2
	Unique dstIPv4 = 2
	Unique srcUDP = 0
	Unique dstUDP = 0
	Unique srcTCP = 2
	Unique dstTCP =  2
	synCount = 2
	finCount = 0
	fragCount =  0
	totalPacketCount = 3

Unique Source Mac Addresses
	0:6:25:da:af:73
	0:8:74:4f:36:23

Unique Destination Mac Addresses
	0:8:74:4f:36:23
	0:6:25:da:af:73

Unique Source IPv4 Addresses
	128.119.245.12
	192.168.1.102

Unique Destination IPv4 Addresses
	192.168.1.102
	128.119.245.12

Unique UDP Source Ports

Unique UDP Destination Addresses

Unique TCP Source Ports
	80
	4127

Unique TCP Destination Addresses
	4127
	80
```
