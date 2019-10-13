static char rcsid[] = "$Id: Pctest.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: Pctest.cc 1082 2005-02-12 19:40:04Z bmah $
//
// Pctest.cc
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
// Placeholder for virtual base class of tests.
//

#include <stdio.h>

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#endif /* STDC_HEADERS */

#ifdef HAVE_UNISTD_H
#include <sys/types.h>
#endif /* HAVE_UNISTD_H */

#include <sys/socket.h>
#include <sys/time.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#ifdef __OpenBSD__
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#else
#include <net/ethernet.h>
#endif
#ifdef HAVE_BPF
#include <sys/ioctl.h>
#endif /* HAVE_BPF */
#endif /* HAVE_PCAP */

#include "Pctest.h"

//
// Pctest::Pctest
//
// Pctest constructor
//
Pctest::Pctest()
{
    initialized = 0;
    TimeSyscall(syscallTime);
    
    IF_DEBUG(3, fprintf(stderr, "syscallTime.tv_usec = %ld\n", syscallTime.tv_usec));
    
#ifdef HAVE_PCAP
    // If we're running with pcap enabled, set this up.
    extern bool PcapFlag;
    extern char PcapErrBuf[];
    extern char *Interface;
    extern unsigned int Mtu;
    extern unsigned int Timeout;

    int fileno;

    if (PcapFlag) {
	if (Interface == NULL) {
	    Interface = pcap_lookupdev(PcapErrBuf);
	    if (Interface == NULL) {
		fprintf(stderr, "%s\n", PcapErrBuf);
		exit(1);
	    }
	}

	pc = pcap_open_live(Interface, Mtu, 0, 1000 * Timeout, PcapErrBuf);
	if (pc == NULL) {
	    fprintf(stderr, "%s\n", PcapErrBuf);
	    exit(1);
	}

	if (pcap_lookupnet(Interface, &netp, &maskp, PcapErrBuf) < 0) {
	    fprintf(stderr, "%s\n", PcapErrBuf);
	    exit(1);
	}

	fileno = pcap_fileno(pc);
	if (fileno < 0) {
	    fprintf(stderr, "pcap_fileno() failed\n");
	    exit(1);
	}

#ifdef HAVE_BPF
	// Set "immediate" mode in BPF.  We need this to avoid libpcap
	// waiting the entire timeout period before passing any received
	// packets to us.
	u_int immediate = 1;
	if (ioctl(fileno, BIOCIMMEDIATE, &immediate) < 0) {
	    perror("ioctl(BIOCIMMEDIATE)");
	    exit(1);
	}
#endif /* HAVE_BPF */
    }
#endif /* HAVE_PCAP */
}

//
// Pctest::~Pctest
//
// Pctest destructor
//
Pctest::~Pctest() {
#ifdef HAVE_PCAP
    extern bool PcapFlag;

    if (PcapFlag) {
	if (pc != NULL) {
	    pcap_close(pc);
	}
    }
#endif /* HAVE_PCAP */
}

//
// Pctest::TimeSyscall
//
// Input:  None
//
// Output:  timeval to hold gettimeofday overhead
//
// Determine the gettimeofday() syscall overhead.  Probably this is going
// to be negligible compared to the data we're getting back from the
// network.
//
void Pctest::TimeSyscall(struct timeval &diff)
{
    struct timeval t1, t2;

    gettimeofday(&t1, NULL);
    gettimeofday(&t2, NULL);
    
    diff.tv_sec = t2.tv_sec - t1.tv_sec;
    diff.tv_usec = t2.tv_usec - t1.tv_usec;
    if (diff.tv_usec < 0) {
	diff.tv_usec += 1000000;
	diff.tv_sec--;
    }
    
}

//
// Pctest::GeneratePayload
//
// Input:  Number of bytes to get
//
// Output:  Pointer to payload (owned by caller, NULL if an error)
//
// Generate a random number of bytes in a heap-allocated buffer.
// for use as a payload.  Having random data in the packet will hopefully
// defeat link-level compression.
//
char *Pctest::GeneratePayload(int size)
{
    char *buf;
    int i;

    if (size <= 0) {
	return NULL;
    }

    buf = new char[size];
    if (buf == NULL) {
	return buf;
    }
    for (i = 0; i < size; i++) {
	buf[i] = random() & 0xff;
    }
    return buf;
}

//
// Pctest::InCksum
//
// Input:  addr, len (buffer to checksum)
//
// Output:  IP checksum for this buffer in return value
//
// Compute IP checksum for a buffer.  It's put here because it's fairly
// general-purpose, and both the IPv4 and IPv6 tests could potentially
// make use of it.  RFC 1071 has implementation notes, and we use
// the sample implementation (essentially unmodified) therein.
//
u_short
Pctest::InCksum(u_short *addr, int len)
{
    register int sum = 0;
    u_short checksum;
    
    while (len > 1)  {
	sum += *addr++;
	len -= 2;
    }
    
    // Add left-over byte, if any
    if (len > 0) {
	sum += * (u_char *) addr;
    }
    
    // fold 32-bit sum to 16 bits
    while (sum >> 16) {
	sum = (sum & 0xffff) + (sum >> 16);
    }
    
    checksum = ~sum;
    return(checksum);
}

#ifdef HAVE_PCAP
//
// Pctest::callback
//
// Inputs:  Object pointer, pcap_pkthdr pointer, pointer to packet
// data.
//
// Outputs:  None.
//
// pcap callback routine.
//
// XXX This function needs some work.  It only deals with Ethernet-
// like datalinks.  We need something like what tcpdump's packet-
// printing does.
//
void 
Pctest::callback(u_char *puc, 
		 const struct pcap_pkthdr *ph, 
		 const u_char *pd) {
    
    Pctest *obj = (Pctest *) puc;
    obj->tvAfter.tv_sec = ph->ts.tv_sec;
    obj->tvAfter.tv_usec = ph->ts.tv_usec;
    obj->packetLength = ph->len;
    obj->packet = (u_char *) pd; // we need to compute an offset to this

    switch (pcap_datalink(obj->pc)) {
    case DLT_NULL:
	break;

    case DLT_EN10MB:
	obj->packetLength -= sizeof(struct ether_header);
	obj->packet += sizeof(struct ether_header);
	break;

    default:
	fprintf(stderr, "Unknown datalink layer %d\n", pcap_datalink(obj->pc));
	exit(1);
	break;
    }

}
#endif /* HAVE_PCAP */
