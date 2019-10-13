static char rcsid[] = "$Id: PctestIpv4.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv4.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4.cc
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
// Class of IPv4 tests
//

#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "pc.h"
#include "PctestIpv4.h"

extern unsigned int Mtu;

//
// PctestIpv4::SetOriginName
//
// Input:  origin hostname
//
// Output:  success code (negative if error)
//
// Attempt to set the origin of probe packets emanating from this host,
// for tests where it is applicable, using protocol family-dependent
// resolution as necessary.  If no origin hostname is given, 
// then use the target address to compute the correct outgoing interface.
// originName and originAddress are set.
//
int PctestIpv4::SetOriginName(char *o)
{

    // If nothing was passed in, then bind a dummy socket to try
    // to figure out where packets exit this host.
    if (o == NULL) {

	int dummySock;
	struct sockaddr_in dummyAddr, localAddr;
#ifdef HAVE_SOCKLEN_T
	socklen_t localAddrLength;
#else /* HAVE_SOCKLEN_T */
#ifdef NEED_GETSOCKNAME_HACK
	int localAddrLength;
#else /* NEED_GETSOCKNAME_HACK */
	size_t localAddrLength;
#endif /* NEED_GETSOCKNAME_HACK */
#endif /* HAVE_SOCKLEN_T */

	// Create socket, then connect to it, and then read out
	// the local socket address with a getsockname call.
	dummySock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dummySock < 0) {
	    perror("socket");
	    return -1;
	}

	memset((void *) &dummyAddr, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SOCKADDR_SA_LEN
	dummyAddr.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_SOCKADDR_SA_LEN */
	dummyAddr.sin_family = AF_INET;
	dummyAddr.sin_port = htons(32768); // port number irrelevant
	memcpy(&dummyAddr.sin_addr, &targetAddress, 
	       sizeof(struct in_addr));

	if (connect(dummySock, (sockaddr *) &dummyAddr, 
		    sizeof(struct sockaddr_in)) < 0) {
	    perror("connect");
	    return -1;
	}

	localAddrLength = sizeof(sockaddr_in);
	memset((void *) &localAddr, 0, sizeof(struct sockaddr_in));
	if (getsockname(dummySock, (struct sockaddr *) &localAddr,
			&localAddrLength) < 0) {
	    perror("getsockname");
	    return -1;
	}

	// Got the local address, now do a reverse DNS looup
	memcpy(&originAddress, &localAddr.sin_addr, sizeof(struct in_addr));
	originName = strdup(GetName((char *) &originAddress));
	if (originName == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for origin hostname.\n");
	    return -1;
	}

	close(dummySock);
    }

    // User gave a source name/address.  Attempt to resolve, if possible.
    else {

	struct hostent *host;	// resolver host entry

	host = gethostbyname(o);

	// Resolver failed
	if (host == NULL) {

#ifdef HAVE_HERROR
	    herror(o);
#else
	    fprintf(stderr, "%s: Host not found\n", o);
#endif /* HAVE_HERROR */

	    memset((void *) &originAddress, 0, sizeof(struct in_addr));
	    originName = strdup(o);

	    if (originName == NULL) {
		fprintf(stderr, "Couldn't allocate space for origin hostname.\n");
		return -1;
	    }
	    return -1;
	}

	IF_DEBUG(3, fprintf(stderr, "h_name = %s\n", host->h_name));
	IF_DEBUG(3, fprintf(stderr, "h_length = %d\n", host->h_length));
	IF_DEBUG(3, fprintf(stderr, "h_addr_list[0] = %x\n", *((int *)(host->h_addr_list[0]))));
	     
	// Get IP address
	memcpy(&originAddress, host->h_addr_list[0], host->h_length);

	// Make a copy of the canonical hostname
	originName = strdup(host->h_name);
	if (originName == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for origin hostname.\n");
	    return -1;
	}
    }

    return 0;
}

//
// PctestIpv4::SetTargetName
//
// Input:  target hostname (target)
//
// Output:  success code (negative if error)
//
// Set target name and do protocol-dependent resolving to get a 
// network address.  In case of an error, we're responsible for
// printing some error message.
//
int PctestIpv4::SetTargetName(char *t)
{

    int len;			// temporary buffer length
    struct hostent *host;	// resolver host entry

    // Attempt to resolve, if possible
    host = gethostbyname(t);

    // Resolver failed
    if (host == NULL) {

	// Some systems don't have herror (non-BSD?), so for those,
	// we'll cobble together an error message.
#ifdef HAVE_HERROR
	herror(t);
#else
	fprintf(stderr, "%s: Host not found\n", t);
#endif /* HAVE_HERROR */

	memset((void *) &targetAddress, 0, sizeof(struct in_addr));
	targetName = strdup(t);

	if (targetName == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for target hostname.\n");
	    return -1;
	}
	return -1;
    }

    IF_DEBUG(3, fprintf(stderr, "h_name = %s\n", host->h_name));
    IF_DEBUG(3, fprintf(stderr, "h_length = %d\n", host->h_length));
    IF_DEBUG(3, fprintf(stderr, "h_addr_list[0] = %x\n", *((int *)(host->h_addr_list[0]))));
	     
    // Get IP address
    memcpy(&targetAddress, host->h_addr_list[0], host->h_length);

    memset((void *) &targetSocketAddress, 0, sizeof(struct sockaddr_in));
    // Note:  Only BSD4.3Reno and later have sin_len in struct
    // sockaddr_in, so we need to test for it.
#ifdef HAVE_SOCKADDR_SA_LEN
    targetSocketAddress.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_SOCKADDR_SA_LEN */
    targetSocketAddress.sin_family = AF_INET;
    targetSocketAddress.sin_port = htons(0); // set on each test
    memcpy(&targetSocketAddress.sin_addr, host->h_addr_list[0], host->h_length);

    // Make a copy of the canonical hostname
    targetName = strdup(host->h_name);
    if (targetName == NULL) {
	fprintf(stderr, "Couldn't allocate memory for target hostname.\n");
	return -1;
    }

    return 0;

}

//
// GetSocketIn
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get input socket of an appropriate type.
//
int PctestIpv4::GetSocketIn() {
    struct protoent *icmpProto = getprotobyname("icmp"); 
				// be really anal-retentive
    if (icmpProto == NULL) {
	fprintf(stderr, "Warning: Couldn't determine ICMP protocol number, using 1\n");
	proto = 1;		// instance variable of PctestIpv4
    }
    else {
	proto = icmpProto->p_proto;
    }
    socketIn = socket(PF_INET, SOCK_RAW, proto);
    if (socketIn < 0) {
	perror("socket");
	return socketIn;
    }

    return socketIn;
}

//
// PctestIpv4::GetPrintableAddress
//
// Input:  None
//
// Output:  Pointer to ASCII representation of address (in return
// value)
//
char *PctestIpv4::GetPrintableAddress()
{
    return (GetPrintableAddress(&targetAddress));
}

//
// PctestIpv4::GetPrintableAddress
//
// Input:  Pointer to address structure
//
// Output:  Pointer to ASCII representation of address (in return
// value)
//
char *PctestIpv4::GetPrintableAddress(void *a)
{
    return (inet_ntoa(*((struct in_addr *) a)));
}

//
// PctestIpv4::GetName
//
// Input:  Pointer to address structure
//
// Output:  Pointer to ASCII representation of name (in return
// value)
//
char *PctestIpv4::GetName(void *a)
{
    struct hostent *host;
    host = gethostbyaddr((char *) a, sizeof(struct in_addr), AF_INET);

    if (host) {
	return (host->h_name);
    }
    else {
	return (GetPrintableAddress(a));
    }

}

//
// PctestIpv4::GenerateAdvancePacket
//
// Generate an ICMP throwaway packet, with all headers, owned by
// the caller.  This is an ICMP echo reply packet, crafted in
// such a way that it will (should) travel all the way to its target,
// but be dropped by the target without generating anything coming
// back at us.  In other words, it just occupies bandwidth on links.
//
char *PctestIpv4::GenerateAdvancePacket(TestRecord &tr) {

    // Parameters stored as globals
    extern unsigned int Tos;

    // If the requested sending size is too small or too large, 
    // then return an error.  The caller should have figured out the 
    // minimum sending size by calling Pctest::GetMinSize().
//    if ((tr.size < GetMinSize()) || (tr.size > IP_MAXPACKET)) {
//	fprintf(stderr, "Bad packet size\n");
//	return NULL;
//    }

    // Make up a ICMP packet to send out.
    struct ip ipHeader;
    memset(&ipHeader, 0, sizeof(ipHeader));
#ifdef __osf__
    // Tru64 <netinet/ip.h> does not declare ip_hl if __STDC__ == 1
    ipHeader.ip_vhl = (sizeof(ip) >> 2) | (4 << 4);
#else    
    ipHeader.ip_hl = sizeof(ip) >> 2;
    ipHeader.ip_v = 4;
#endif /* __osf__ */
    ipHeader.ip_tos = Tos;
#ifdef linux
    ipHeader.ip_len = htons(tr.size);
#else
    ipHeader.ip_len = Mtu;
#endif /* linux */
    ipHeader.ip_id = htons(0);
#ifdef linux
    ipHeader.ip_off = htons(IP_DF);
#else
    ipHeader.ip_off = IP_DF;
#endif /* linux */
    ipHeader.ip_ttl = MAXTTL;
    ipHeader.ip_p = IPPROTO_ICMP;
    ipHeader.ip_sum = 0;
    memcpy(&(ipHeader.ip_src), &(originAddress), sizeof(struct in_addr));
    memcpy(&(ipHeader.ip_dst), &(targetSocketAddress.sin_addr), sizeof(struct in_addr));

    // Make up ICMP header.
    int icmpPayloadSize = Mtu - sizeof(ip) - ICMP_MINLEN;
				// need to hardcode size of headers for an ICMP
				// echo reply packet
    struct icmp icmpHeader;

    icmpHeader.icmp_type = ICMP_ECHOREPLY;
    icmpHeader.icmp_code = 0;
    icmpHeader.icmp_cksum = htons(0); // compute checksum
    icmpHeader.icmp_id = htons(icmpId);
    icmpHeader.icmp_seq = htons(icmpSequence++);

    // ICMP payload
    char *icmpPayload;
    icmpPayload = GeneratePayload(icmpPayloadSize);
    if (icmpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return NULL;
    }

    // Build the packet now.
    char *ipPacket;
    int ipPacketSize;
    ipPacketSize = sizeof(ip) + ICMP_MINLEN + icmpPayloadSize;
    ipPacket = new char[ipPacketSize];
    if (ipPacket == NULL) {
	fprintf(stderr, "Couldn't allocate space for packet\n");
	return NULL;
    }
    memcpy(ipPacket, &ipHeader, sizeof(ipHeader));
    memcpy(ipPacket + sizeof(ipHeader), &icmpHeader, ICMP_MINLEN);
    memcpy(ipPacket + sizeof(ipHeader) + ICMP_MINLEN,
	   icmpPayload, icmpPayloadSize);

    // Compute ICMP checksum.  This is much simpler than the TCP or
    // UDP checksums, because there is no pseudo-header.
    u_int checksum;
    checksum = (u_short) InCksum((u_short *) (ipPacket + sizeof(ipHeader)),
				 ICMP_MINLEN + icmpPayloadSize);
    ((icmp *)(ipPacket + sizeof(ipHeader)))->icmp_cksum = checksum;

    return ipPacket;

}
