// -*- c++ -*-
//
// $Id: ResultTable.h 1082 2005-02-12 19:40:04Z bmah $
//
// ResultTable.h
// Bruce A. Mah <bmah@acm.org>
//
// This work was first produced by an employee of Sandia National
// Laboratories under a contract with the U.S. Department of Energy.
// Sandia National Laboratories dedicates whatever right, title or
// interest it may have in this software to the public. Although no
// license from Sandia is needed to copy and use this software,
// copying and using the software might infringe the rights of
// others. This software is provided as-is. SANDIA DISCLAIMS ANY
// WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
//
// Table of pc results.
//

#ifndef RESULTTABLE_H
#define RESULTTABLE_H

#include <stdio.h>

class ResultTable {
    
  public:
    const unsigned int increment, mtu, burst, repetitions;
    const unsigned int columns;
    ResultTable(unsigned int i, unsigned int m, unsigned int b, 
		unsigned int r);
    virtual ~ResultTable();
    
    int put(int size, double time);
    ResultTable *getMin();
    double queueing();
    void slr(double &a, double &b, double &r2, double &sa, double &sb);
    void tau(double &a, double &b, double &blower, double &bupper);
    void lms(double &a, double &b, double &r2);
    void lmsint(double &a, double &b, double &r2);
    double median(double *values, unsigned int numValues);
    unsigned int median(unsigned int *values, unsigned int numValues);

    int Print(FILE *fp, char *tag, int hop);

  protected:
    double **data;
    int *used;
	
    bool cacheSlrValid;	// Cached SLR results valid?
    double cacheSlrA, cacheSlrB, cacheSlrR2;
    double cacheSlrSA, cacheSlrSB;

    bool cacheTauValid;		// Cached tau results valid?

    bool cacheLmsValid;		// Cached tau results valid?

    bool cacheQueueingValid;	// Cached queueing results valid?
    double cacheQueueing;

    int size2column(int s) { return (s); }
    int column2size(int c) { return (c); }
};

#endif /* RESULTTABLE_H */

