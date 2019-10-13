static char rcsid[] = "$Id: PctestIpv4Udp.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv4Udp.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4Udp.cc
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
// Class of IPv4 tests using UDP
//

#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "pc.h"
#include "PctestIpv4Udp.h"
#include "TestRecord.h"

//
// GetSocketOut
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get output socket of an appropriate type, store in socketOut.
//
int PctestIpv4Udp::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET, SOCK_DGRAM, 0);
    if (socketOut < 0) {
	perror("socket");
	return socketOut;
    }
    
#ifdef linux
    // Linux needs SO_BSDCOMPAT enabled on our UDP socket, to avoid
    // getting ICMP errors when we send packets out.
    int bsdcompatOption;
    bsdcompatOption = 1;
    rc = setsockopt(socketOut, SOL_SOCKET, SO_BSDCOMPAT, &bsdcompatOption,
		    sizeof(bsdcompatOption));
    if (rc < 0) {
	perror("setsockopt(SO_BSDCOMPAT)");
	return rc;
    }
#endif /* linux */

    // Make up a socket address structure for the source address
    // and attempt to bind the output socket to it.
    struct sockaddr_in originSocketAddress;
    memset((void *) &originSocketAddress, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SOCKADDR_SA_LEN
    originSocketAddress.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_SOCKADDR_SA_LEN */
    originSocketAddress.sin_family = AF_INET;
    originSocketAddress.sin_port = htons(0);
    memcpy(&(originSocketAddress.sin_addr), &originAddress, sizeof(in_addr));

    rc = bind(socketOut, (struct sockaddr *) &originSocketAddress, 
	      sizeof(originSocketAddress));
    if (rc < 0) { 
	perror("bind()");
	return rc;
    }

    return socketOut;
}

//
// PctestIpv4Udp::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv4Udp::Test(TestRecord &tr)
{
    struct timeval timeout;
    int rc;			// syscall return code
    fd_set readFds;		// reading file descriptors
    int done = 0;

    // Parameters stored as globals
    extern unsigned int Tos;
    extern int Timeout;

    // If the requested sending size is too small, then return an
    // error.  The caller should have figured out the minimum sending
    // size by calling Pctest::GetMinSize().
    if (tr.size < GetMinSize()) {
	return -1;
    }

    // This protocol module doesn't support advance packets
    if (tr.burst > 1) {
	fprintf(stderr, 
		"Protocol module has no support for burst parameter > 1\n");
	return -1;
    }

    // Make up a UDP packet to send out.
    int udpPayloadSize = tr.size - sizeof(ip) - sizeof(udphdr);
    char *udpPayload;
    udpPayload = GeneratePayload(udpPayloadSize);
    if (udpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
    }

    targetSocketAddress.sin_port = htons(destPort++);

    // Set TTL.  We sort of need to do a type conversion on hops, since 
    // it gets plugged into a setsockopt argument.
    rc = setsockopt(socketOut, IPPROTO_IP, IP_TTL, (char *) &tr.hops, sizeof(tr.hops));
    if (rc < 0) {
	perror("setsockopt(IP_TTL)");
	return rc;
    }

    // Set TOS bits
    rc = setsockopt(socketOut, IPPROTO_IP, IP_TOS, (char *) &Tos, sizeof(Tos));
    if (rc < 0) {
	perror("setsockopt(IP_TOS)");
	return rc;
    }

    // Use malloc(3) to allocate (memory-aligned) space for the inbound
    // packet.
    char *icmpPacket;
    icmpPacket = (char *) malloc(IP_MAXPACKET);
    if (icmpPacket == NULL) {
	fprintf(stderr, "Couldn't allocate space for inbound packet\n");
	return -1;
    }

    // Set timeout value and socket select parameters
    timeout.tv_sec = Timeout;
    timeout.tv_usec = 0;
    FD_ZERO(&readFds);
    FD_SET(socketIn, &readFds);

    // Timestamp before 
    gettimeofday(&tvBefore, NULL);

    // Send UDP packet
    rc = sendto(socketOut, udpPayload, udpPayloadSize, 0,
		(struct sockaddr *) &targetSocketAddress,
		sizeof(struct sockaddr_in));
    if (rc < 0) {
	perror("sendto");
	goto exittest;
    }

    // We need to check the socket until we get a valid packet.
    // So we might end up doing this select/read several times.
    do {

	// Select and wait for an ICMP response or a timeout
	rc = select(FD_SETSIZE, &readFds, NULL, NULL, &timeout);
	if (rc < 0) {
	    perror("select");
	    goto exittest;
	}

	// Timestamp after and update test record timestamp fields
	gettimeofday(&tvAfter, NULL);
	tr.tv.tv_sec = tvAfter.tv_sec - tvBefore.tv_sec - syscallTime.tv_sec;
	tr.tv.tv_usec = tvAfter.tv_usec - tvBefore.tv_usec - syscallTime.tv_usec;
	while (tr.tv.tv_usec < 0) {
	    tr.tv.tv_usec += 1000000;
	    tr.tv.tv_sec--;
	}

	// Read response from socket
	if (rc == 1) {
	    IF_DEBUG(2, fprintf(stderr, "Response packet received\n"));

	    rc = read(socketIn, icmpPacket, IP_MAXPACKET);
	    if (rc < 0) {
		perror("read");
		goto exittest;
	    }
	    tr.replsize = rc;

	    // Now parse the packet, doing a little error checking along
	    // the way.  By the end, we'll have ipHeader and icmpHeader
	    // pointing to valid structures within the packet, and
	    // ipHeader2 pointing to the IP header of the generating
	    // IP packet..
	    ip *ipHeader, *ipHeader2;
	    icmp *icmpHeader;
	    udphdr *udpHeader;
	    unsigned int ipHeaderLength, ipHeaderLength2;

	    if (tr.replsize < sizeof(ip)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete IP packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    // Check protocol in IP header
	    ipHeader = (ip *) icmpPacket;
	    if (ipHeader->ip_p != proto) {
		IF_DEBUG(0, fprintf(stderr, "Received unknown protocol %d in (supposedly) ICMP packet\n", ipHeader->ip_p));
		rc = -1;
		goto exittest;
	    }

#ifdef __osf__
	    // Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
	    ipHeaderLength = (ipHeader->ip_vhl & 0x0f) << 2;
#else
	    ipHeaderLength = ipHeader->ip_hl << 2;
#endif /* __osf__ */

	    if (tr.replsize - (0 + ipHeaderLength) < ICMP_MINLEN) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete ICMP packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    icmpHeader = (icmp *) (((char *) ipHeader) + ipHeaderLength);

	    IF_DEBUG(3, fprintf(stderr, "ICMP type = %d, code = %d\n", 
				icmpHeader->icmp_type, icmpHeader->icmp_code));

	    // Check ICMP type.  Most types (such as echo request/reply,
	    // router adverts, etc.) we ignore.
	    if ((icmpHeader->icmp_type != ICMP_TIMXCEED) && 
		(icmpHeader->icmp_type != ICMP_UNREACH)) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet\n"));
		continue;
	    }
	    
	    if (tr.replsize - (0 + ipHeaderLength + ICMP_MINLEN) < 
		sizeof(ip)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner IP packet, %d bytes total\n", tr.replsize));
		continue;
	    }

	    // Check for a valid (to us) IP header within the packet.
	    // For "time exceeded" or "destination unreachable", this
	    // header will be 8 bytes past the ICMP header.
	    ipHeader2 = (ip *) ((char *) icmpHeader + ICMP_MINLEN);

	    // Additional checking here...must be UDP
	    if (ipHeader2->ip_p != IPPROTO_UDP) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet for non-UDP packet\n"));
		continue;
	    }

	    // Align UDP header template.
#ifdef __osf__
	    // Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
	    ipHeaderLength2 = (ipHeader2->ip_vhl & 0x0f) << 2;
#else
	    ipHeaderLength2 = ipHeader2->ip_hl << 2;
#endif /* __osf__ */

	    if (tr.replsize - (0 + ipHeaderLength + ICMP_MINLEN + ipHeaderLength2) < sizeof(udphdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner UDP packet, %d bytes total\n", tr.replsize));
		continue;
	    }

	    udpHeader = (udphdr *) (((char *) ipHeader2) + ipHeaderLength2);

	    // Check destination UDP port number (we don't know the
	    // source) and UDP (header+payload) length
	    if ((udpHeader->uh_dport != targetSocketAddress.sin_port) || 
		(ntohs(udpHeader->uh_ulen) != udpPayloadSize + sizeof(udphdr))) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet for unknown UDP packet\n"));
		continue;
	    }

	    // Fill in return fields
	    tr.icmpSourceAddress = new char[sizeof(in_addr)];
	    memcpy(tr.icmpSourceAddress, &(ipHeader->ip_src), sizeof(in_addr));
	    tr.icmpSourceAddressLength = sizeof(in_addr);

	    tr.result = GetAction(icmpHeader->icmp_type,
				  icmpHeader->icmp_code);

	    done = 1;

	}
	else {

	    IF_DEBUG(2, fprintf(stderr, "Timeout\n"));

	    tr.icmpSourceAddress = new char[sizeof(in_addr)];
	    memset(tr.icmpSourceAddress, 0, sizeof(in_addr));
	    tr.icmpSourceAddressLength = sizeof(in_addr);

	    tr.result = PctestActionTimeout;

	    done = 1;
	}
    } while (!done);

    rc = 0;

  exittest:
    delete [] udpPayload;
    free(icmpPacket);
    return rc;

}

//
// PctestIpv4Udp::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv4Udp::GetMinSize() 
{
    return (sizeof(ip) + sizeof(udphdr) + 4);
}

//
// PctestIpv4Udp::GetAction
//
// Input:  a test record
//
// Output:  action code
//
// Figure out the meaning of a particular combination of ICMPv4 type
// and code values.
//
PctestActionType PctestIpv4Udp::GetAction(int icmpType, int icmpCode) 
{
    if (icmpType == ICMP_TIMXCEED) {
	return PctestActionValid;
    }
    else if ((icmpType == ICMP_UNREACH) &&
	     (icmpCode == ICMP_UNREACH_PORT)) {
	return PctestActionValidLasthop;
    }
    else if ((icmpType == ICMP_UNREACH) &&
	     (icmpCode == ICMP_UNREACH_FILTER_PROHIB)) {
	return PctestActionFiltered;
    }
    else {
	return PctestActionAbort;
    }
}

