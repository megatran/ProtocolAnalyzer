//
// Skeleton code by Phil Romig on 11/13/18.
// Solution Implemented by Nhan Tran December 2018
//

#ifndef PACKETSTATS_RESULTSC_H
#define PACKETSTATS_RESULTSC_H

#include <ostream>
#include "packetstats.h"

class resultsC {
private:
    statisticsC ethernet;
    statisticsC IEEE;
    statisticsC ARP;
    statisticsC IPv4;
    statisticsC IPv6;
    statisticsC otherNetwork;
    statisticsC TCP;
    statisticsC UDP;
    statisticsC ICMP;
    statisticsC otherTransport;

    std::unordered_set<u_int64_t> srcMacSet;
    std::unordered_set<u_int64_t> dstMacSet;
    std::unordered_set<u_int32_t> srcIPv4Set;
    std::unordered_set<u_int32_t> dstIPv4Set;
    std::unordered_set<u_int16_t> srcUDPSet;
    std::unordered_set<u_int16_t> dstUDPSet;
    std::unordered_set<u_int16_t> srcTCPSet;
    std::unordered_set<u_int16_t> dstTCPSet;

    unsigned int synCount;
    unsigned int finCount;
    unsigned int fragCount;
    unsigned int totalPacketCount;

    bool displayMacs;
    bool displayIPv4;
    bool displayUDP;
    bool displayTCP;

public:
    resultsC(bool dm, bool di, bool du, bool dt);

    void displayResults();
    unsigned int packetCount() { return totalPacketCount; }

    void newEthernet(unsigned int size) { ethernet.insert(size); }
    void newIEEE(unsigned int size) { IEEE.insert(size); }
    void newARP(unsigned int size) { ARP.insert(size); }
    void newIPv4(unsigned int size) { IPv4.insert(size); }
    void newIPv6(unsigned int size) { IPv6.insert(size); }
    void newOtherNetwork(unsigned int size) { otherNetwork.insert(size); }
    void newTCP(unsigned int size) { TCP.insert(size); }
    void newUDP(unsigned int size) { UDP.insert(size); }
    void newICMP(unsigned int size) { ICMP.insert(size); }
    void newOtherTransport(unsigned int size) { otherTransport.insert(size); }

    void newSrcMac(uint64_t value) { srcMacSet.insert(value); }
    void newDstMac(uint64_t value) { dstMacSet.insert(value); }
    void newSrcIPv4(uint32_t value) { srcIPv4Set.insert(value); }
    void newDstIPv4(uint32_t value) { dstIPv4Set.insert(value); }
    void newSrcUDP(uint32_t value) { srcUDPSet.insert(value); }
    void newDstUDP(uint32_t value) { dstUDPSet.insert(value); }
    void newSrcTCP(uint32_t value) { srcTCPSet.insert(value); }
    void newDstTCP(uint32_t value) { dstTCPSet.insert(value); }

    void incrementSynCount() { synCount++; }
    void incrementFinCount() { finCount++; }
    void incrementFragCount() { fragCount++; }
    void incrementTotalPacketCount() { totalPacketCount++; }

    friend std::ostream &operator<<(std::ostream &os, const resultsC &c);
};


#endif //PACKETSTATS_RESULTSC_H
