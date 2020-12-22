// -*- c++ -*-
//
// $Id: Pctest.h 1082 2005-02-12 19:40:04Z bmah $
//
// Pctest.h
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
// Header for virtual base class of tests.  A particular protocol (e.g.
// IPv4, IPv6) will override the methods of this base class
// with protocol-specific implementations.
//
//

#ifndef PCTEST_H
#define PCTEST_H

#include <stdio.h>

#if defined(STDC_HEADERS)
#include <stdlib.h>
#include <string.h>
#endif /* STDC_HEADERS */

#if defined(HAVE_UNISTD_H)
#include <sys/types.h>
#endif /* HAVE_UNISTD_H */

#include <sys/socket.h>
#include <sys/time.h>

#if defined(HAVE_PCAP)
#include <pcap.h>
#endif /* HAVE_PCAP */

#include "pc.h"
// #include "TestRecord.h"
class TestRecord;

// Action codes.  ICMPv4 and ICMPv6 have different values for their type
// and code fields.  The Pctest abstracts these differences.
enum class PctestActionType {
    PctestActionReserved = 0,	// reserved code
    PctestActionValid = 1,	// store valid measurement (e.g. ICMP
				// time exceeded)
    PctestActionValidLasthop = 2,	// store valid measurement, this 
				// is last hop (e.g. ICMP port unreachable)
    PctestActionFiltered = 3,	// packets filtered, give up (e.g. 
				// ICMP prohibited)
    PctestActionTimeout = 4,	// Timeout
    PctestActionAbort = 255	// huh?  we haven't a clue
};

class Pctest {

  public:
    Pctest();
    virtual ~Pctest();

    // Get gettimeofday() system call overhead.
    virtual void TimeSyscall(struct timeval &diff);

    // Get random payload buffer
    virtual char *GeneratePayload(int size);

    // Determine origin address for our tests (resolve if necessary)
    virtual int SetOriginName(char *origin) = 0;

    // Get origin host name and address
    char *GetOriginName() { return originName; };
    virtual void *GetOriginAddress() = 0;

    // Set target host for our tests (resolve if necessary)
    virtual int SetTargetName(char *target) = 0;

    // Get target host name and address
    char *GetTargetName() { return targetName; };
    virtual char *GetPrintableAddress() = 0;
    virtual char *GetPrintableAddress(void *a) = 0;
    virtual char *GetName(void *a) = 0;
    virtual char *GetAddressFamilyString() = 0;
    virtual int GetAddressFamily() = 0;

    // Get input and output sockets needed
    virtual int GetSocketOut() = 0;
    virtual int GetSocketIn() = 0;

    // Perform a test and return statistics
    virtual int Test(TestRecord &tr) = 0;
    virtual unsigned int GetMinSize() = 0;

  protected:
    int initialized;		// initialization flag
    char *originName;		// origin hostname
    char *targetName;		// target hostname
    struct timeval tvBefore, tvAfter;	// timestamps
    struct timeval syscallTime;	// estimated overhead for gettimeofday()

#if defined(HAVE_PCAP)
    pcap_t *pc;			// pcap structure
    bpf_u_int32 netp, maskp;	// net and mask parameters
    struct bpf_program fp;	// filter program

    // pcap callback
    static void callback(u_char *puc,
			 const struct pcap_pkthdr *ph,
			 const u_char *pd);
    // Fields for callback to communicate information back to the
    // main object's methods    
    u_char *packet;		// start of IP packet
    unsigned int packetLength;	// packet length
#endif /* HAVE_PCAP */

    u_short InCksum(u_short *addr, int len);	// IP checksum routine

};

#endif /* PCTEST_H */
