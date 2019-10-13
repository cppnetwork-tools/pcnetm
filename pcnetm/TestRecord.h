// -*- c++ -*-
//
// $Id: TestRecord.h 1082 2005-02-12 19:40:04Z bmah $
//
// TestRecord.h
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
// Encapsulation of test data structure
//

#ifndef TESTRECORD_H
#define TESTRECORD_H

#include <stdio.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif /* STDC_HEADERS */

#if HAVE_UNISTD_H
#include <sys/types.h>
#endif /* HAVE_UNISTD_H */

#include <sys/time.h>

#include "pc.h"
#include "Pctest.h"

class TestRecord {

  public:

    bool used;			// has this TestRecord been used yet?
    TestRecord *next;		// for supporting a SLL of these things

    unsigned int size;		// bytes in the packet in this test
    unsigned int hops;		// TTL used for this packet
    unsigned int burst;		// burst size for multi-packet tests
    struct timeval tvstart;	// starting timestamp
    struct timeval tv;		// RTT recorded
    void *icmpSourceAddress;		// source address of ICMP packet
    int icmpSourceAddressLength;	// length of source address
    PctestActionType result;	// test result
    unsigned int replsize;	// bytes in the response packet

    char *htoa(Pctest *pct);
    static TestRecord *atoh(char *, Pctest *);

};

#endif /* TESTRECORD_H */

