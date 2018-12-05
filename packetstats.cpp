//
//  project4.cpp
//  project4
//
//  Skeleton code by Phillip Romig on 4/3/12.
//  Solution implemented by Nhan Tran on December 2018
//  Copyright 2012 Colorado School of Mines. All rights reserved.
//

#include "packetstats.h"


// ****************************************************************************
// * main()
// *  You should not have to worry about anything if you don't want to.
// *  My code will open the file, initalize the results container class,
// *  call pk_processor() once for each packet and the finally call
// *  the displayResutls() method.
// ****************************************************************************
int main (int argc, char **argv)
{

    // **********************************************************************
    // * Initalize the debugging class.
    // **********************************************************************
    boost::log::add_console_log(std::cout, boost::log::keywords::format = "%Message%");
    boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::warning);

    // **********************************************************************
    // * The program is called with two arguments:
    // * -f <filename>
    // * -d <debug level>
    // * -m List unique MAC addresses
    // * -a List unique IP addresses
    // * -u List unique UDP addresses
    // * -t List unique TCP addresses
    // **********************************************************************
    int opt = 0;
    char filename[NAME_MAX];
    bool displayMac =  false;
    bool displayIP = false;
    bool displayUDP = false;
    bool displayTCP = false;
    while ((opt = getopt(argc,argv,"mautf:d:")) != -1) {

        switch (opt) {
            case 'f':
                strncpy(filename,optarg,NAME_MAX);
                break;
            case 'd':
                if (atoi(optarg) >= 1) boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::info);
                if (atoi(optarg) >= 2) boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::debug);
                if (atoi(optarg) >= 3) boost::log::core::get()->set_filter(boost::log::trivial::severity >= boost::log::trivial::trace);
                break;
            case 'm':
                displayMac = true;
                break;
            case 'a':
                displayIP = true;
                break;
            case 'u':
                displayUDP = true;
                break;
            case 't':
                displayTCP = true;
                break;
            case ':':
            case '?':
            default:
                std::cout << "useage: " << argv[0] << " -f <cpautre file name> -d <debug level> -m -a -u -t" << std::endl;
                std::cout << "        -m list unique MAC addressses" << std::endl;
                std::cout << "        -a list unique IPv4 addressses" << std::endl;
                std::cout << "        -u list unique UDP ports" << std::endl;
                std::cout << "        -t list unique TCP ports" << std::endl;
                exit(EXIT_FAILURE);
        }
    }
    TRACE << "Running packetstats on file " << filename << ENDL;



    // **********************************************************************
    // * Instantiate the results class.
    // **********************************************************************
    resultsC* results = new resultsC(displayMac,displayIP,displayUDP,displayTCP);
    TRACE << "results object created" << ENDL;



    // **********************************************************************
    // * Attempt to open the file.
    // **********************************************************************
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *PT;

    bzero(errbuf,PCAP_ERRBUF_SIZE);
    if ((PT = pcap_open_offline(filename,errbuf)) == NULL ) {
        FATAL << "Unable to open pcap file: " << filename << ENDL;
        exit(EXIT_FAILURE);
    }
    DEBUG << filename << " has been opened." << ENDL;

    if (strlen(errbuf) > 0)
        WARNING << "pcap_open_offiline encountered a non-fatal error: " << pcap_geterr(PT) << ENDL;



    // **********************************************************************
    // * The dispatcher will call the packet processor once for packet
    // * in the capture file.
    // **********************************************************************
    int pk_count;
    DEBUG << "Calling dispatcher." << ENDL;
    if ((pk_count = pcap_dispatch(PT, -1, pk_processor, (u_char *)results)) < 0) {
        FATAL << "Error calling dispatcher: " << pcap_geterr(PT) << ENDL;
        exit(EXIT_FAILURE);
    }
    DEBUG << "Dispatcher finished with " << pk_count << " packets left in the queue." << ENDL;


    // **********************************************************************
    // * File your report here.
    // **********************************************************************
    std::cout << *results << std::endl;
    exit(EXIT_SUCCESS);
}
