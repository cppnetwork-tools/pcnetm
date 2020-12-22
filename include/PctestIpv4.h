// -*- c++ -*-
//
// $Id: PctestIpv4.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4.h
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
// Header class for IPv4 tests
//
#ifndef PCTESTIPV4_H
#define PCTESTIPV4_H

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if defined(STDC_HEADERS)
#include <string.h>
#endif /* STDC_HEADERS */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "pc.h"
#include "Pctest.h"
#include "TestRecord.h"

class PctestIpv4 : public Pctest {

  public:

    PctestIpv4() { 
	socketOut = 0;
	socketIn = 0;
	destPort = 32768; 

	icmpId = (u_short) getpid(); // cache PID for ICMP ID field
	icmpSequence = 0;	// init sequence number
    };

    PctestIpv4(int p) { 
	socketOut = 0;
	socketIn = 0;
	destPort = p; 

	icmpId = (u_short) getpid(); // cache PID for ICMP ID field
	icmpSequence = 0;	// init sequence number
    };

    virtual ~PctestIpv4() { 
	if (socketOut > 0) {
	    close(socketOut);
	}
	if (socketIn > 0) {
	    close(socketIn);
	}
    };

    virtual int SetOriginName(char *origin);
    virtual void *GetOriginAddress() {return &originAddress;};
    virtual int SetTargetName(char *target);
    virtual int GetSocketIn();
    virtual char *GetPrintableAddress();
    virtual char *GetPrintableAddress(void *a);
    virtual char *GetName(void *a);
    virtual char *GetAddressFamilyString() { return "AF_INET"; };
    virtual int GetAddressFamily() { return (AF_INET); };
    
  protected:


    struct in_addr originAddress;
    struct in_addr targetAddress;
    struct sockaddr_in targetSocketAddress;

    int socketOut;		// output socket (RAW)
    int socketIn;		// input socket (ICMP)
    int proto;			// (hopefully) ICMP protocol number
    int destPort;		// destination port number

    u_short icmpId;		// ICMP ID
    u_short icmpSequence;	// ICMP sequence number

    virtual char *GenerateAdvancePacket(TestRecord &tr);
};

#endif /* PCTESTIPV4_H */
