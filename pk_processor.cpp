//
// Skeleton code by Phil Romig on 11/13/18.
// Solution Implemented by Nhan Tran December 2018
//

#include "packetstats.h"

// ****************************************************************************
// * pk_processor()
// *  Most/all of the work done by the program will be done here (or at least it
// *  it will originate here). The function will be called once for every
// *  packet in the savefile.
// ****************************************************************************
void pk_processor(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    resultsC* results = (resultsC*)user;
    results->incrementTotalPacketCount();
    DEBUG << "Processing packet #" << results->packetCount() << ENDL;
    char s[256]; bzero(s,256); bcopy(ctime(&(pkthdr->ts.tv_sec)),s,strlen(ctime(&(pkthdr->ts.tv_sec)))-1);
    TRACE << "\tPacket timestamp is " << s;
    TRACE << "\tPacket capture length is " << pkthdr->caplen ;
    TRACE << "\tPacket physical length is " << pkthdr->len ;

    uint16_t ethertype = packet[12] << 8 | packet[13]; // move the first 8 bits to upper then OR lower 8 bits
    if (ethertype < 1536) {
      // 802.4 according to https://en.wikipedia.org/wiki/EtherType
      //std::cout << "IEEE packet" << std::endl;
      results->newIEEE(pkthdr->len);
    } else {
      // ethernet II according to https://en.wikipedia.org/wiki/EtherType
      results->newEthernet(pkthdr->len);
      if (ethertype ==0x0800) {
        // std::cout << "[TESTING] IPv4 packet" << std::endl;
        uint8_t *payload = (uint8_t*)malloc(pkthdr->len * sizeof(uint8_t));

        for (int cnt = 0; cnt < pkthdr->len; cnt++) {
            payload[cnt] = packet[cnt+14];
        }

        results->newIPv4(pkthdr->len);

        // Source: https://en.wikipedia.org/wiki/IPv4
        uint32_t ipv4_source = ((uint32_t)payload[12] << 24
        | (uint32_t)payload[13] << 16
        | (uint32_t)payload[14] << 8
        | (uint32_t)payload[15]);
        results->newSrcIPv4(htonl(ipv4_source));

        // printf("[TESTING] IP Source %d:%d:%d:%d\n",
        // ipv4_source >> 24 & 0xFF,
        // ipv4_source >> 16 & 0xFF,
        // ipv4_source >> 8 & 0xFF,
        // ipv4_source & 0xFF);

        uint32_t ipv4_destination = ((uint32_t)payload[16] << 24
        | (uint32_t)payload[17] << 16
        | (uint32_t)payload[18] << 8
        | (uint32_t)payload[19]);
        results->newDstIPv4(htonl(ipv4_destination));

        // printf("[TESTING] IP Destination %d:%d:%d:%d\n",
        // ipv4_destination >> 24 & 0xFF,
        // ipv4_destination >> 16 & 0xFF,
        // ipv4_destination >> 8 & 0xFF,
        // ipv4_destination & 0xFF);

        // check fragment
        //https://en.wikipedia.org/wiki/IPv4
        // the sixth field in IPv4 header has 8 bits. Need to grab the FIFTH bit.
        if ((payload[6] & 0b00100000) == 0b00100000) {
          results->incrementFragCount();
        }

        // TRANSPORT LAYER
        /*

        Protocol Number	Protocol Name	Abbreviation
        1	Internet Control Message Protocol	ICMP
        2	Internet Group Management Protocol	IGMP
        6	Transmission Control Protocol	TCP
        17	User Datagram Protocol	UDP
        41	IPv6 encapsulation	ENCAP
        89	Open Shortest Path First	OSPF
        132	Stream Control Transmission Protocol	SCTP
        */

        //on transport layer we call it a packet i think
        uint8_t* tcppacket = (uint8_t*)malloc(pkthdr->len *  sizeof(uint8_t));
        //The Internet Header Length (IHL) field has 4 bits, which is the number of 32-bit words.
        uint8_t internet_header_length = payload[0] & 0b00001111;
        for (int cnt = 0; cnt < pkthdr->len; cnt++) {
          tcppacket[cnt] = payload[cnt + internet_header_length*4];
        }



        uint16_t protocol_num = (uint16_t)payload[9];
        if (protocol_num == 1) {
          //Internet Control Message Protocol	ICMP
          results->newICMP(pkthdr->len);
        } else if (protocol_num == 6) {
          // TCP
          results->newTCP(pkthdr->len);
          // https://en.wikipedia.org/wiki/Transmission_Control_Protocol
          uint32_t source_port = (uint16_t) tcppacket[0] << 8 | tcppacket[1];
          results->newSrcTCP(source_port);
          u_int32_t destination_port = (uint16_t) tcppacket[2] << 8 | tcppacket[3];
          results->newDstTCP(destination_port);
          // printf("[TESTING] TCP srcport: %d\n", source_port);
          // printf("[TESTING] TCP dstport: %d\n", destination_port);
          // check flags (9 bits)
          // check SYN bit in TCP packet (offset )

          uint8_t SYN = tcppacket[13] & 0b00000010;
          uint8_t FIN = tcppacket[13] & 0b00000001;
          //printf("[TESTING] Packet 13: %X | SYN: %X | FIN: %X\n", tcppacket[13], SYN, FIN);
          if (SYN == 0b00000010) {
            results->incrementSynCount();
          }
          if (FIN ==  0b00000001) {
            results->incrementFinCount();
          }

        } else if (protocol_num == 17) {
          // UDP

          results->newUDP(pkthdr->len);
          uint32_t source_port = (uint16_t) tcppacket[0] << 8 | tcppacket[1];
          results->newSrcUDP(source_port);
          u_int32_t destination_port = (uint16_t) tcppacket[2] << 8 | tcppacket[3];
          results->newDstUDP(destination_port);

        } else {
          results->newOtherNetwork(pkthdr->len);
        }

      } else if (ethertype == 0x86DD) {
        results->newIPv6(pkthdr->len);
      } else if (ethertype == 0x0806) {
        // 2054	= 0x0806
        results->newARP(pkthdr->len);
      } else {
        results->newOtherNetwork(pkthdr->len);
      }
    }

    // Get the MAC
    // uint64_t mac_destination = (uint64_t)packet[0] << 40
    // | (uint64_t)packet[1] << 32
    // | (uint64_t)packet[2] << 24
    // | (uint64_t)packet[3] << 16
    // | (uint64_t)packet[4] << 8
    // | (uint64_t)packet[5];
    // REVERSE ORDER
    uint64_t mac_destination = (uint64_t)packet[5] << 40
    | (uint64_t)packet[4] << 32
    | (uint64_t)packet[3] << 24
    | (uint64_t)packet[2] << 16
    | (uint64_t)packet[1] << 8
    | (uint64_t)packet[0];

    results->newDstMac(mac_destination);
    // printf("[TESTING] Destination Mac %X:%X:%X:%X:%X:%X\n",
    // mac_destination >> 40 & 0xFF,
    // mac_destination >> 32 & 0xFF,
    // mac_destination >> 24 & 0xFF,
    // mac_destination >> 16 & 0xFF,
    // mac_destination >> 8 & 0xFF,
    // mac_destination & 0xFF
    // );


    // uint64_t mac_source = (uint64_t)packet[6] << 40
    // | (uint64_t)packet[7] << 32
    // | (uint64_t)packet[8] << 24
    // | (uint64_t)packet[9] << 16
    // | (uint64_t)packet[10] << 8
    // | (uint64_t)packet[11];
    uint64_t mac_source = (uint64_t)packet[11] << 40
    | (uint64_t)packet[10] << 32
    | (uint64_t)packet[9] << 24
    | (uint64_t)packet[8] << 16
    | (uint64_t)packet[7] << 8
    | (uint64_t)packet[6];

    results->newSrcMac(mac_source);
   //  printf("[TESTING] Source Mac %X:%X:%X:%X:%X:%X\n",
   //  mac_source >> 40 & 0xFF,
   //  mac_source >> 32 & 0xFF,Created
   //  mac_source >> 24 & 0xFF,
   //  mac_source >> 16 & 0xFF,
   //  mac_source >> 8 & 0xFF,
   //  mac_source & 0xFF
   // );

  return;
}
