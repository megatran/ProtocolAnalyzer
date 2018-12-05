//
// Skeleton code by Phil Romig on 11/13/18.
// Solution Implemented by Nhan Tran December 2018
//

#include "packetstats.h"

resultsC::resultsC(bool dm, bool di, bool du, bool dt) : ethernet("Ethernet"), IEEE("IEEE"), ARP("ARP"), IPv4("IPv4"), IPv6("IPv6"),
otherNetwork("OtherNetwork"), TCP("TCP"), UDP("UDP"), ICMP("ICMP"),
otherTransport("OtherTransport"), synCount(0), finCount(0), fragCount(0),
totalPacketCount(0), displayMacs(dm), displayIPv4(di), displayTCP(dt), displayUDP(du) {}

std::ostream &operator<<(std::ostream &os, const resultsC &c) {
    os << "ethernet: " << std::endl << c.ethernet << std::endl
       << "IEEE: " << std::endl  << c.IEEE << std::endl
       << "ARP: " << std::endl << c.ARP  << std::endl
       << "IPv4: " << std::endl << c.IPv4 << std::endl
       << "IPv6: " << std::endl << c.IPv6 << std::endl
       << "otherNetwork: " << std::endl  << c.otherNetwork  << std::endl
       << "TCP: " << std::endl << c.TCP  << std::endl
       << "UDP: " << std::endl  << c.UDP << std::endl
       << "ICMP: " << std::endl << c.ICMP  << std::endl
       << "otherTransport: " << std::endl  << c.otherTransport << std::endl
       << "Counts: " << std::endl
       << "\tUnique srcMac = " << c.srcMacSet.size() << std::endl
       << "\tUnique dstMac = " << c.dstMacSet.size() << std::endl
       << "\tUnique srcIPv4 = " << c.srcIPv4Set.size() << std::endl
       << "\tUnique dstIPv4 = " << c.dstIPv4Set.size() << std::endl
       << "\tUnique srcUDP = " << c.srcUDPSet.size() << std::endl
       << "\tUnique dstUDP = " << c.dstUDPSet.size() <<  std::endl
       << "\tUnique srcTCP = " << c.srcTCPSet.size() << std::endl
       << "\tUnique dstTCP =  " << c.dstTCPSet.size() << std::endl
       << "\tsynCount = " << c.synCount  << std::endl
       << "\tfinCount = " << c.finCount << std::endl
       << "\tfragCount =  " << c.fragCount << std::endl
       << "\ttotalPacketCount = " << c.totalPacketCount << std::endl;

    if (c.displayMacs) {
      // std::unordered_set<u_int64_t>::const_iterator I;

        os << "\nUnique Source Mac Addresses" << std::endl;
        for(auto I = c.srcMacSet.begin(); I != c.srcMacSet.end(); I++)
         os << "\t" << ether_ntoa((const struct ether_addr *)&(*I)) << std::endl;

        os << "\nUnique Destination Mac Addresses" << std::endl;
        for(auto I = c.dstMacSet.begin(); I != c.dstMacSet.end(); I++)
         os << "\t" << ether_ntoa((const struct ether_addr *)&(*I)) << std::endl;
    }

    if (c.displayIPv4) {
        struct in_addr in;

        os << "\nUnique Source IPv4 Addresses" << std::endl;
        for(auto I = c.srcIPv4Set.begin(); I != c.srcIPv4Set.end(); I++) {
            in.s_addr = *I;
            os << "\t" << inet_ntoa(in) << std::endl;
        }

        os << "\nUnique Destination IPv4 Addresses" << std::endl;
        for(auto I = c.dstIPv4Set.begin(); I != c.dstIPv4Set.end(); I++) {
            in.s_addr = *I;
            os << "\t" << inet_ntoa(in) << std::endl;
        }
    }

    if (c.displayUDP) {

        os << "\nUnique UDP Source Ports" << std::endl;
        for(auto I = c.srcUDPSet.begin(); I != c.srcUDPSet.end(); I++)
            os << "\t" << *I << std::endl;


        os << "\nUnique UDP Destination Addresses" << std::endl;
        for(auto I = c.dstUDPSet.begin(); I != c.dstUDPSet.end(); I++)
            os << "\t" << *I << std::endl;

    }

    if (c.displayTCP) {

        os << "\nUnique TCP Source Ports" << std::endl;
        for(auto I = c.srcTCPSet.begin(); I != c.srcTCPSet.end(); I++)
            os << "\t" << *I << std::endl;


        os << "\nUnique TCP Destination Addresses" << std::endl;
        for(auto I = c.dstTCPSet.begin(); I != c.dstTCPSet.end(); I++)
            os << "\t" << *I << std::endl;

    }

    return os;
}
