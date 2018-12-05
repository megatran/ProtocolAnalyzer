//
// Skeleton code by Phil Romig on 11/13/18.
// Solution Implemented by Nhan Tran December 2018
//

#ifndef PACKETSTATS_STATISTICSC_H
#define PACKETSTATS_STATISTICSC_H


#include <ostream>

class statisticsC {
private:
    std::string name_v;
    unsigned int count_v;
    unsigned int min_v;
    unsigned int max_v;
    double average_v;

public:
    statisticsC(std::string name);
    void insert(unsigned int newValue);

    friend std::ostream &operator<<(std::ostream &os, const statisticsC &c);
};


#endif //PACKETSTATS_STATISTICSC_H
