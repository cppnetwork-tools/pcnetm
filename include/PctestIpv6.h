// -*- c++ -*-
//
// $Id: PctestIpv6.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv6.h
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
// Header class for IPv6 tests
//
#ifndef PCTESTIPV6_H
#define PCTESTIPV6_H

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if defined(STDC_HEADERS)
#include <string.h>
#endif /* STDC_HEADERS */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef NEED_NRL_IPV6_HACK
#include <netinet6/in6.h>
#endif /* NEED_NRL_IPV6_HACK */

#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "pc.h"
#include "Pctest.h"
#include "TestRecord.h"

class PctestIpv6 : public Pctest {

  public:

    PctestIpv6() { 
	socketOut = 0;
	socketIn = 0;
	destPort = 32768; 

	icmp6Id = (u_short) getpid(); // cache PID for ICMP ID field
	icmp6Sequence = 0;	// init sequence number
    };
    PctestIpv6(int p) { 
	socketOut = 0;
	socketIn = 0;
	destPort = p; 

	icmp6Id = (u_short) getpid(); // cache PID for ICMP ID field
	icmp6Sequence = 0;	// init sequence number
    };
    virtual ~PctestIpv6() { 
	if (socketOut > 0) {
	    close(socketOut);
	}
	if (socketIn > 0) {
	    close(socketIn);
	}
	if (advanceSocketOut > 0) {
	    close(advanceSocketOut);
	}
    };

    virtual int SetOriginName(char *origin);
    virtual void *GetOriginAddress() {return &originAddress;};
    virtual int SetTargetName(char *target);
    virtual int GetSocketIn();
    virtual char *GetPrintableAddress();
    virtual char *GetPrintableAddress(void *a);
    virtual char *GetName(void *a);
    virtual char *GetAddressFamilyString() { return "AF_INET6"; }
    virtual int GetAddressFamily() { return (AF_INET6); }
    
  protected:

    struct in6_addr originAddress;
    struct in6_addr targetAddress;
    struct sockaddr_in6 targetSocketAddress;
    struct sockaddr_in6 icmpDestSocketAddress;
    struct sockaddr_in6 icmpSourceSocketAddress;

    int socketOut;		// output socket (RAW)
    int socketIn;		// input socket (ICMP)
    int advanceSocketOut;	// output socket (RAW for ICMP)
    int proto;			// (hopefully) ICMP protocol number
    int destPort;		// destination port number

    u_short icmp6Id;		// ICMP ID
    u_short icmp6Sequence;	// ICMP sequence number

    virtual int GetAdvanceSocketOut();
    virtual char *GenerateAdvancePacket(TestRecord &tr);

};

#endif /* PCTESTIPV6_H */


