static char rcsid[] = "$Id: TestRecord.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: TestRecord.cc 1082 2005-02-12 19:40:04Z bmah $
//
// TestRecord.cc
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
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pc.h"
#include "TestRecord.h"

static const int buflen=1024;
static char buffer[buflen];
static char buffer2[buflen];

//
// TestRecord::htoa
//
// Input:  Pctest structure, needed for figuring out the right
// representations of IP addresses.
//
// Output:  Pointer to a statically-allocated buffer with an ASCII
// representation of the TestRecord.
//
// Make an ASCII representation of a TestRecord structure.
//
char *TestRecord::htoa(Pctest *pct) 
{

    // The way we build up the output is an artifact of various
    // method calls (i.e. Pctest::GetPrintableAddress) that used fixed,
    // statically-allocated buffers for returning their output.

    buffer[0] = '\0';
#ifdef HAVE_SNPRINTF
    snprintf(buffer2, buflen, 
#else
    sprintf(buffer2, 
#endif /* HAVE_SNPRINTF */
      "probe t %ld.%06ld ", tvstart.tv_sec, tvstart.tv_usec);
    strncat(buffer, buffer2, buflen);

#ifdef HAVE_SNPRINTF
    snprintf(buffer2, buflen, 
#else
    sprintf(buffer2, 
#endif /* HAVE_SNPRINTF */
      "h %d b %d addr %s res %d rtt %ld.%06ld rb %d", hops, size, pct->GetPrintableAddress(icmpSourceAddress), result, tv.tv_sec, tv.tv_usec, replsize);
    strncat(buffer, buffer2, buflen);

    return buffer;
}

//
// TestRecord::atoh
//
// Input: input string, Pctest record
//
// Output: pointer to a new TestRecord, NULL if an error
//
// Parse the ASCII representation described above and make up a new
// TestRecord with demarshalled parameters.  The caller "owns"
// this object and is responsible for deallocating it.
//
// The Pctest record is necessary to determine the address family
// that needs to be used when parsing addresses on this line.
//
TestRecord *TestRecord::atoh(char *s, Pctest *pct) 
{

    TestRecord *tr;

    char icmpsrcChars[256];
    float tvstartFloat, tvFloat;
    int hops, size, replsize;
    int result;

    if (sscanf(s, "probe t %f h %d b %d addr %s res %d rtt %f rb %d", &tvstartFloat, &hops, &size, icmpsrcChars, &result, &tvFloat, &replsize) == 7) {

	tr = new TestRecord;
	tr->size = size;
	tr->hops = hops;
	tr->tvstart.tv_sec = (long) tvstartFloat;
	tr->tvstart.tv_usec = (long) ((tvstartFloat - ((long) tvstartFloat)) * 1000000.0);
	tr->tv.tv_sec = (long) tvFloat;
	tr->tv.tv_usec = (long) ((tvFloat - ((long) tvFloat)) * 1000000.0);

	// Parse the gateway address in an address-family dependant
	// way.
	int af = pct->GetAddressFamily();
	if (af == AF_INET) {
	    tr->icmpSourceAddress = new char[sizeof(in_addr)];
	    ((in_addr *) tr->icmpSourceAddress)->s_addr = 
		inet_addr(icmpsrcChars);
	    tr->icmpSourceAddressLength= sizeof(in_addr);
	}
#ifdef HAVE_IPV6
	else if (af == AF_INET6) {
	    tr->icmpSourceAddress = new char[sizeof(in6_addr)];
	    inet_pton(AF_INET6, icmpsrcChars, (void *) tr->icmpSourceAddress);
	    tr->icmpSourceAddressLength= sizeof(in6_addr);
	}
#endif // HAVE_IPV6
	else {
	    fprintf(stderr, "Unknown address family: %s\n", s);
	    return NULL;
	}

	tr->result = (PctestActionType) result;
	tr->replsize = replsize;

	return tr;

    }
    else {
	fprintf(stderr, "Syntax error: %s\n", s);
	return NULL;
    }

}


