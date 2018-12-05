//
// Created by Phil Romig on 10/30/18.
//

#ifndef PACKETSTATS_PACKETSTATS_H
#define PACKETSTATS_PACKETSTATS_H

// System include files
#include <stdlib.h>
// #include <strings.h>
// #include <string.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <iostream>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unordered_set>
#include <algorithm>    // std::max

// The PCAP library
#include <pcap/pcap.h>


// TCP/IP Headers and Utiltity Functions
#include <arpa/inet.h> // Contains inet_ntoa for printing IP addresses
#include <net/ethernet.h>
 #include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h> // Contains IPv4 header
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Include files specific to this project.
#include "pk_processor.h"
#include "statisticsC.h"
#include "resultsC.h"



// Garbage needed for the debugging functions.
#include <boost/log/trivial.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>

#define TRACE BOOST_LOG_TRIVIAL(trace) << "TRACE: "
#define DEBUG BOOST_LOG_TRIVIAL(debug)  << "DEBUG: "
#define INFO BOOST_LOG_TRIVIAL(info)   << "INFO: "
#define WARNING BOOST_LOG_TRIVIAL(warning) << "WARNING: "
#define ERROR BOOST_LOG_TRIVIAL(error)  << "ERROR: "
#define FATAL BOOST_LOG_TRIVIAL(fatal)  << "FATAL: "
#define ENDL  " (" << __FILE__ << ":" << __LINE__ << ")"

#endif //PACKETSTATS_PACKETSTATS_H
