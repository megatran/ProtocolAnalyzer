//
// Skeleton code by Phil Romig on 11/13/18.
// Solution Implemented by Nhan Tran December 2018
//

#include "packetstats.h"

statisticsC::statisticsC(std::string name) {
    name_v = name;
    min_v = INT_MAX;
    max_v = 0;
    average_v = 0.0;
    count_v = 0;
}

void statisticsC::insert(unsigned int newValue) {
    max_v = std::max(max_v,newValue);
    min_v = std::min(min_v,newValue);
    average_v = ((average_v * count_v) + newValue) / (count_v + 1);
    count_v++;
}

std::ostream &operator<<(std::ostream &os, const statisticsC &c) {
    os << "\tTotal " << c.name_v <<  " = " << c.count_v << std::endl;
    if (c.min_v < c.max_v) {
        os << "\tMin " << c.name_v  << " = " <<  c.min_v << std::endl;
    } else {
        os << "\tMin " << c.name_v << " = " << c.max_v << std::endl;
    }
    os << "\tMax " << c.name_v  << " = " <<  c.max_v << std::endl;
    os << "\tAverage " << c.name_v  << " = " <<  c.average_v << std::endl;
    return os;
}
