static char rcsid[] = "$Id: PctestIpv6.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv6.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv6.cc
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
// Class of IPv6 tests
//

#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <netinet/in.h>

#ifdef NEED_NRL_IPV6_HACK
#include <netinet6/in6.h>
#endif /* NEED_NRL_IPV6_HACK */

#include <netinet/in_systm.h>

#ifdef NEED_NRL_IPV6_HACK
#include <netinet6/ipv6.h>
#include <netinet6/icmpv6.h>
#else
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif /* NEED_NRL_IPV6_HACK */

#include <netinet/udp.h>
#include <arpa/inet.h>

#include "pc.h"
#include "PctestIpv6.h"

//
// PctestIpv6::SetOriginName
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
int PctestIpv6::SetOriginName(char *o)
{

    // If nothing was passed in, then bind a dummy socket to try to 
    // determine the output interface.
    if (o == NULL) {
	int dummySock;
	struct sockaddr_in6 dummyAddr, localAddr;
#ifdef HAVE_SOCKLEN_T
	socklen_t localAddrLength;
#else /* HAVE_SOCKLEN_T */
	size_t localAddrLength;
#endif /* HAVE_SOCKLEN_T */

	// Create socket, then connect to it, and then read out
	// the local socket address with a getsockname call.
	dummySock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (dummySock < 0) {
	    perror("socket");
	    return -1;
	}

	memset((void *) &dummyAddr, 0, sizeof(struct sockaddr_in6));
#ifdef HAVE_SOCKADDR_SA_LEN
	dummyAddr.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_SOCKADDR_SA_LEN */
	dummyAddr.sin6_family = AF_INET6;
	dummyAddr.sin6_port = htons(32768); // port number irrelevant
	memcpy(&dummyAddr.sin6_addr, &targetAddress, 
	       sizeof(struct in6_addr));

	if (connect(dummySock, (sockaddr *) &dummyAddr, 
		    sizeof(struct sockaddr_in6)) < 0) {
	    perror("connect");
	    return -1;
	}
	
	localAddrLength = sizeof(sockaddr_in6);
	memset((void *) &localAddr, 0, sizeof(struct sockaddr_in6));
	if (getsockname(dummySock, (struct sockaddr *) &localAddr,
			&localAddrLength) < 0) {
	    perror("getsockname");
	    return -1;
	}

	// Got the local address, now do a reverse DNS looup
	memcpy(&originAddress, &localAddr.sin6_addr, sizeof(struct in6_addr));
	originName = strdup(GetName((char *) &originAddress));
	if (originName == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for origin hostname.\n");
	    return -1;
	}

	close(dummySock);

    }

    else {
	// Attempt to resolve, if possible.  Instead of using AI_DEFAULT,
	// we want to force the use of IPv6 addresses (no mapped or IPv4
	// addresses, since the test code relies on knowing exactly what
	// protocol is being used on the wire).
	struct addrinfo *host = NULL;
	struct addrinfo hints;
	int ecode;		// resolver error code

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET6;
	hints.ai_flags = AI_CANONNAME;
	ecode = getaddrinfo(o, NULL, &hints, &host);

	// Resolver failed
	if (host == NULL) {
	    fprintf(stderr, "%s: %s\n", o, gai_strerror(ecode));

	    memset((void *) &originAddress, 0, sizeof(struct in6_addr));
	    originName = strdup(o);

	    if (originName == NULL) {
		fprintf(stderr, "Couldn't allocate space for origin hostname.\n");
		return -1;
	    }
	    return -1;
	}

	IF_DEBUG(3, fprintf(stderr, "h_name = %s\n", host->ai_canonname));
	IF_DEBUG(3, fprintf(stderr, "h_length = %d\n", host->ai_addrlen));

	// Get IP address
	memcpy(&originAddress,
	       &((struct sockaddr_in6 *) host->ai_addr)->sin6_addr,
	       sizeof(originAddress));

	// Make a copy of the canonical hostname
	originName = strdup(host->ai_canonname);
	if (originName == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for hostname.\n");
	    return -1;
	}

	freeaddrinfo(host);
    }

    return 0;
}

//
// PctestIpv6::SetTargetName
//
// Input:  target hostname (target)
//
// Output:  success code (negative if error)
//
// Set target name and do protocol-dependent resolving to get a 
// network address.  In case of an error, we're responsible for
// printing some error message.
//
int PctestIpv6::SetTargetName(char *t)
{

    int len;			// temporary buffer length
    struct addrinfo *host = NULL;
    struct addrinfo hints;
    int ecode;			// resolver error code
    extern int Tos;		// Tos parameter (to be used for traffic class)

    // Attempt to resolve, if possible.  Instead of using AI_DEFAULT,
    // we want to force the use of IPv6 addresses (no mapped or IPv4
    // addresses, since the test code relies on knowing exactly what
    // protocol is being used on the wire).
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET6;
    hints.ai_flags = AI_CANONNAME;
    ecode = getaddrinfo(t, NULL, &hints, &host);

    // Resolver failed
    if (host == NULL) {
	fprintf(stderr, "%s: %s\n", t, gai_strerror(ecode));

	memset((void *) &targetAddress, 0, sizeof(struct in6_addr));
	targetName = strdup(t);

	if (targetName == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for target hostname.\n");
	    return -1;
	}
	return -1;
    }

    IF_DEBUG(3, fprintf(stderr, "h_name = %s\n", host->ai_canonname));
    IF_DEBUG(3, fprintf(stderr, "h_length = %d\n", host->ai_addrlen));

    // Get IP address
    memcpy(&targetAddress,
	   &((struct sockaddr_in6 *) host->ai_addr)->sin6_addr,
	   sizeof(targetAddress));

    memset((void *) &targetSocketAddress, 0, sizeof(struct sockaddr_in6));
    // Note:  Only BSD4.3Reno and later have sin_len in struct
    // sockaddr_in, so we need to test for it.
    //
    // Really what we ought to have is a check in autoconf for
    // sockaddr_in6.sin6_len, rather than relying on the (already
    // existing) check for sockaddr.sin_len.  There are two instances
    // in this file.  (On the other hand, any system that has
    // sockaddr.sin_len for IPv4 is almost certainly going to have
    // sockaddr_in6.sin6_len for IPv6, since the socket code is going
    // to have to read both fields with the same semantics.
#ifdef HAVE_SOCKADDR_SA_LEN
    targetSocketAddress.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_SOCKADDR_SA_LEN */
    targetSocketAddress.sin6_family = AF_INET6;
    // Note:  RFC 2553 doesn't define the semantics of sin6_flowinfo,
    // instead punting that that RFC 2460.  We hardcode the fact
    // that flow labels are 20 bits long (note that RFC 1883 used to
    // have 24-bit flow labels).  If we want to support setting a
    // flow label value, we can OR it with the value below.
    targetSocketAddress.sin6_flowinfo = htonl(Tos << 20); 
    targetSocketAddress.sin6_port = htons(0); // set on each test

    memcpy(&targetSocketAddress.sin6_addr,
	   &((struct sockaddr_in6 *) host->ai_addr)->sin6_addr,
           sizeof(struct in6_addr));

    // Make a copy of the canonical hostname, if it exists.
    if (host->ai_canonname) {
	targetName = strdup(host->ai_canonname);
    }
    else {
	fprintf(stderr, "Warning:  couldn't get canonical hostname.\n");
	targetName = strdup(t);
    }
    freeaddrinfo(host);

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
int PctestIpv6::GetSocketIn() {
    struct protoent *icmpProto;
    struct icmp6_filter filt;
    int rc;			// return code
    int on = 1;

    icmpProto = getprotobyname("ipv6-icmp"); // be really anal-retentive
    if (icmpProto == NULL) {
	fprintf(stderr, "Warning: Couldn't determine ICMPv6 protocol number, using 58\n");
	proto = 58;		// instance variable of PctestIpv6
    }
    else {
	proto = icmpProto->p_proto;
    }
    socketIn = socket(PF_INET6, SOCK_RAW, proto);
    if (socketIn < 0) {
	perror("socket");
	return socketIn;
    }

    // ICMPv6 message filtering.
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &filt);
    ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &filt);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
    rc = setsockopt(socketIn, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
    if (rc < 0) {
	perror("setsockopt(ICMP_FILTER)");
	return rc;
    }

    // If the current system supports 2292bis (XXX to become RFC XXX)
    // we'll use its version of the advanced API.
#ifdef IPV6_RECVPKTINFO
    rc = setsockopt(socketIn, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
    if (rc < 0) {
	perror("setsockopt(IPV6_RECVPKTINFO)");
	return rc;
    }
#else
    rc = setsockopt(socketIn, IPPROTO_IPV6, IPV6_PKTINFO, &on, sizeof(on));
    if (rc < 0) {
	perror("setsockopt(IPV6_PKTINFO)");
	return rc;
    }
#endif /* IPV6_RECVPKTINFO */

    return socketIn;

}

//
// PctestIpv6::GetPrintableAddress
//
// Input:  None
//
// Output:  Pointer to ASCII representation of address (in return
// value)
//
char *PctestIpv6::GetPrintableAddress()
{
    return (GetPrintableAddress(&targetAddress));
}

//
// PctestIpv6::GetPrintableAddress
//
// Input:  Pointer to address structure
//
// Output:  Pointer to ASCII representation of address (in return
// value)
//
static char PctestIpv6PrintableAddress[INET6_ADDRSTRLEN];
char *PctestIpv6::GetPrintableAddress(void *a)
{
    return (char *)inet_ntop(AF_INET6, a, PctestIpv6PrintableAddress, INET6_ADDRSTRLEN);
}

//
// PctestIpv6::GetName
//
// Input:  Pointer to address structure
//
// Output:  Pointer to ASCII representation of name (in return
// value)
//
static char PctestIpv6GetName[NI_MAXHOST];
char *PctestIpv6::GetName(void *a)
{

    int error_num;		// return code from library lookup
    struct sockaddr_in6 sa;	// need to build up a socket addr structure

    memset(&sa, 0, sizeof(sockaddr_in6));
#ifdef HAVE_SOCKADDR_SA_LEN
    sa.sin6_len = sizeof(sockaddr_in6);
#endif /* HAVE_SOCKADDR_SA_LEN */
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(0);
    memcpy(&(sa.sin6_addr), a, sizeof(struct in6_addr));

    error_num = getnameinfo((const struct sockaddr *) &sa, 
			    sizeof(struct sockaddr_in6),
			    PctestIpv6GetName, NI_MAXHOST,
			    NULL, 0,
			    0);

    return PctestIpv6GetName;

}

//
// PctestIpv6::GetAdvanceSocketOut
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get output socket suitable for sending advance packets.
//
// NOTE:  Advance sockets (and the implementation of -b) for IPv6 is
// slightly different between IPv6 and IPv4.  For IPv4, we use a
// single raw socket (the same one that is used for the "real" probe
// packets).  This works because we can (need to) construct the
// entire IP packet, starting from the IP header.
//
// With IPv6, we don't control the IP header directly; raw sockets
// do not allow us to do this.  So each socket is associated with
// exactly one transport protocol (i.e. ICMPv6, UDP).  In addition, 
// the ICMPv6 packets are treated specially by the stack, because
// they have their pseudo-header calculated for them.  For these
// reasons, we use a separate socket to send the advance packets
// for IPv6.  This allows us to support -b independent of the actual
// probe packet type.  (The same is not true for IPv4, where -b is
// supported for raw UDP probes but not for regular SOCK_DGRAM-type
// UDP probes).
//
int PctestIpv6::GetAdvanceSocketOut() {

    int rc;
    
    advanceSocketOut = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (advanceSocketOut < 0) {
	perror("socket");
	return advanceSocketOut;
    }
    
    // Make up a socket address structure for the source address
    // and attempt to bind the output socket to it.
    struct sockaddr_in6 originSocketAddress;
    memset((void *) &originSocketAddress, 0, sizeof(struct sockaddr_in6));
    // See comments in PctestIpv6::SetTargetName() about the overloading
    // of HAVE_SOCKADDR_SA_LEN.
#ifdef HAVE_SOCKADDR_SA_LEN
    originSocketAddress.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_SOCKADDR_SA_LEN */
    originSocketAddress.sin6_family = AF_INET6;
    originSocketAddress.sin6_port = htons(0);
    memcpy(&(originSocketAddress.sin6_addr), &originAddress, sizeof(in6_addr));

    rc = bind(advanceSocketOut, (struct sockaddr *) &originSocketAddress, 
	      sizeof(originSocketAddress));
    if (rc < 0) { 
	perror("bind()");
	return rc;
    }

    rc = connect(advanceSocketOut, (struct sockaddr *) &targetSocketAddress,
		 sizeof(targetSocketAddress));
    if (rc < 0) {
	perror("connect");
	return rc;
    }

    // Set TTL.
    unsigned int hops = IPV6_MAXHLIM;
    rc = setsockopt(advanceSocketOut, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *) &hops, sizeof(hops));
    if (rc < 0) {
	perror("setsockopt(IPV6_UNICAST_HOPS)");
	return rc;
    }

    return advanceSocketOut;
}

//
// PctestIpv6::GenerateAdvancePacket
//
// Input:
//
// Output:
//
char *PctestIpv6::GenerateAdvancePacket(TestRecord &tr)
{
    extern unsigned int Mtu;

    // Make up an ICMPv6 packet to send out.  We only need the ICMPv6
    // header and payload, and the kernel will take care of computng
    // the ICMPv6 checksum for us.
    int icmp6PayloadSize = Mtu - sizeof(ip6_hdr) - sizeof(icmp6_hdr);
    struct icmp6_hdr icmp6Header;

    icmp6Header.icmp6_type = ICMP6_ECHO_REPLY;
    icmp6Header.icmp6_code = 0;
    icmp6Header.icmp6_id = htons(icmp6Id);
    icmp6Header.icmp6_seq = htons(icmp6Sequence);

    IF_DEBUG(2, fprintf(stdout, "test size %d, payload size %d\n", tr.size, icmp6PayloadSize));

    // ICMPv6 payload
    char *icmp6Payload;
    icmp6Payload = GeneratePayload(icmp6PayloadSize);
    if (icmp6Payload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return NULL;
    }

    // Build the packet (well, really just the ICMPv6 message)
    // Once again, we don't need to bother with the ICMPv6 checksum;
    // the kernel should deal with it for us.
    char *icmp6Packet;
    int icmp6PacketSize;
    icmp6PacketSize = sizeof(icmp6_hdr) + icmp6PayloadSize;
    icmp6Packet = new char[icmp6PacketSize];
    memcpy(icmp6Packet, &icmp6Header, sizeof(icmp6Header));
    memcpy(icmp6Packet + sizeof(icmp6Header), icmp6Payload, icmp6PayloadSize);

    return icmp6Packet;
}

