static char rcsid[] = "$Id: PctestIpv6Udp.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv6Udp.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv6Udp.cc
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
// Class of IPv6 tests using UDP
//

//
// Solaris needs some "extra stuff" to get msg_control in recvmsg(2)
// according to Erik Nordmark <Erik.Nordmark@eng.sun.com>.  His quick
// fix to do this is:
#ifdef NEED_XOPEN
#define _XOPEN_SOURCE 500
#define __EXTENSIONS__
#endif /* NEED_XOPEN */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
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
#include "PctestIpv6Udp.h"
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
int PctestIpv6Udp::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET6, SOCK_DGRAM, 0);
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

    rc = bind(socketOut, (struct sockaddr *) &originSocketAddress, 
	      sizeof(originSocketAddress));
    if (rc < 0) { 
	perror("bind()");
	return rc;
    }

    // Set up sockets for advance packets
    if (GetAdvanceSocketOut() < 0) {
	return -1;
    }

    return socketOut;
}

//
// PctestIpv6Udp::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv6Udp::Test(TestRecord &tr)
{
    struct timeval timeout;
    int rc;			// syscall return code
    fd_set readFds;		// reading file descriptors
    int done = 0;
    int i;			// generic loop counter

    // Parameters stored as globals
    extern unsigned int Mtu;
    extern int Timeout;

    // If the requested sending size is too small, then return an
    // error.  The caller should have figured out the minimum sending
    // size by calling Pctest::GetMinSize().
    if (tr.size < GetMinSize()) {
	return -1;
    }

    // Make up a UDP packet to send out.
    int udpPayloadSize = tr.size - sizeof(ip6_hdr) - sizeof(udphdr);
    char *udpPayload;
    udpPayload = GeneratePayload(udpPayloadSize);
    if (udpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
    }

    targetSocketAddress.sin6_port = htons(destPort++);

    // Set TTL.
    rc = setsockopt(socketOut, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *) &tr.hops, sizeof(tr.hops));
    if (rc < 0) {
	perror("setsockopt(IPV6_UNICAST_HOPS)");
	return rc;
    }

    // If we need to construct some advance packets, generate 
    // an image of said packet.
    char *advancePacket;
    if (tr.burst - 1 == 0) {
	advancePacket = NULL;
    }
    else {
	advancePacket = GenerateAdvancePacket(tr);
	if (advancePacket == NULL) {
	    return -1;
	}
    }

    // Use malloc(3) to allocate (memory-aligned) space for the inbound
    // packet.
    char *icmp6PacketIn;
    icmp6PacketIn = (char *) malloc(IPV6_MAXPACKET);
    if (icmp6PacketIn == NULL) {
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

    // Send advance packets if necessary
    for (i = 1; i < tr.burst; i++) {
	rc = send(advanceSocketOut, advancePacket, Mtu - sizeof(ip6_hdr), 0);
	if (rc < 0) {
	    perror("send");
	    goto exittest;
	}
    }
    tr.size += (tr.burst - 1) * Mtu;

    // Send UDP packet
    rc = sendto(socketOut, udpPayload, udpPayloadSize, 0,
		(struct sockaddr *) &targetSocketAddress,
		sizeof(struct sockaddr_in6));
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

	    struct msghdr msg;	// msghdr is for recvmsg
	    struct iovec iov[1];
	    int controlsize;

	    // Fill in the message header so we can read all the
	    // metadata from the ICMP packet.  A lot harder than
	    // with ICMPv4 since we had the IP header to work with.
	    msg.msg_name = (char *) &icmpSourceSocketAddress;
	    msg.msg_namelen = sizeof(icmpSourceSocketAddress);
	    iov[0].iov_base = icmp6PacketIn;
	    iov[0].iov_len = IPV6_MAXPACKET;
	    msg.msg_iov = iov;
	    msg.msg_iovlen = 1;

	    // Solaris 8 (which has native IPv6) doesn't define 
            // CMSG_SPACE for now.  According to Erik Nordmark
	    // <Erik.Nordmark@eng.sun.com> it'll be added once
	    // draft-ietf-ipngwg-2292bis becomes an RFC.  Until
	    // then, he has a small hack to fix this, slightly
	    // modified by bmah.
#if (defined(__sun__) || (defined(__sun)))
#ifndef CMSG_SPACE
#define CMSG_SPACE(length) \
        (_CMSG_DATA_ALIGN(sizeof(struct cmsghdr)) + _CMSG_HDR_ALIGN(length))
#endif /* CMSG_SPACE */
#endif /* __sun__ */
	    controlsize = CMSG_SPACE(sizeof(in6_pktinfo));
	    msg.msg_control = new char[controlsize];
	    msg.msg_controllen = controlsize;
	    msg.msg_flags = 0;

	    rc = recvmsg(socketIn, &msg, 0);
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
	    ip6_hdr *ipHeader2;
	    icmp6_hdr *icmpHeader;
	    udphdr *udpHeader;

	    if (tr.replsize - (0) < sizeof(icmp6_hdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete ICMPv6 packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    // Find the ICMPv6 header
	    icmpHeader = (icmp6_hdr *) icmp6PacketIn;
	    IF_DEBUG(3, fprintf(stderr, "ICMPv6 type = %d, code = %d\n", 
				icmpHeader->icmp6_type, icmpHeader->icmp6_code));

	    // Check ICMPv6 type.  Note that we already set up ICMPv6
	    // message filtering in PctestIpv6::GetSocketIn(), which
	    // should catch most messages we don't want.  This check
	    // handles the case of messages that pchar in general is
	    // interested in, but this particular test is not.  We may
	    // want to rethink this in the future, perhaps by making
	    // ICMPv6 filtering dependent on the test protocol in use..
	    if ((icmpHeader->icmp6_type != ICMP6_TIME_EXCEEDED) && 
		(icmpHeader->icmp6_type != ICMP6_DST_UNREACH)) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet\n"));
		goto donepacket;
	    }
	    
	    if (tr.replsize - (0 + sizeof(icmp6_hdr)) < 
		sizeof(ip6_hdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner IPv6 packet, %d bytes total\n", tr.replsize));
		goto donepacket;
	    }

	    // Check for a valid (to us) IP header within the packet.
	    // For "time exceeded" or "destination unreachable", this
	    // header will be just past the ICMPv6 header.
	    ipHeader2 = (ip6_hdr *) ((char *) icmpHeader + sizeof(icmp6_hdr));

	    // Note:  We can look for a UDP header immediately following
	    // the inner IPv6 header because we know (or at least we
	    // think we know) that the original packet went out with no
	    // extension headers.  If that's not true, this test will fail.
	    // If we happen to be a situation where we need to do this,
	    // then we have to insert a parser to skip over the extension
	    // headers right here.
	    if (ipHeader2->ip6_nxt != IPPROTO_UDP) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet for non-UDP\n"));
		goto donepacket;
	    }

	    // Check to see if we got enough for a complete UDP header.
	    // RFC 2463 says that we should get back as much of the
	    // packet that will fit in an MTU.
	    if (tr.replsize - (0 + sizeof(icmp6_hdr) + sizeof(ip6_hdr)) <
		sizeof(udphdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner UDP packet, %d bytes total\n", tr.replsize));
		goto donepacket;
	    }

	    // Align UDP header template.
	    udpHeader = (udphdr *) (((char *) ipHeader2) + sizeof(ip6_hdr));

	    // Check destination UDP port number (we don't know the
	    // source) and UDP (header+payload) length
	    if ((udpHeader->uh_dport != targetSocketAddress.sin6_port) || 
		(ntohs(udpHeader->uh_ulen) != udpPayloadSize + sizeof(udphdr))) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet for unknown UDP packet\n"));
		goto donepacket;
	    }

	    // Fill in return fields
	    tr.icmpSourceAddress = new char[sizeof(in6_addr)];

	    memcpy(tr.icmpSourceAddress, &icmpSourceSocketAddress.sin6_addr, sizeof(in6_addr));
	    tr.icmpSourceAddressLength = sizeof(in6_addr);

	    tr.result = GetAction(icmpHeader->icmp6_type,
				  icmpHeader->icmp6_code);

	    done = 1;

	  donepacket:
	    if (msg.msg_control) {
		delete [] (char *) msg.msg_control;
		msg.msg_control = NULL;
	    }
	    
	}
	else {

	    IF_DEBUG(2, fprintf(stderr, "Timeout\n"));

	    tr.icmpSourceAddress = new char[sizeof(in6_addr)];
	    memset(tr.icmpSourceAddress, 0, sizeof(in6_addr));
	    tr.icmpSourceAddressLength = sizeof(in6_addr);

	    tr.result = PctestActionType::PctestActionTimeout;

	    done = 1;
	}

    } while (!done);

    rc = 0;

  exittest:
    delete [] udpPayload;
    free(icmp6PacketIn);
    return rc;

}

//
// PctestIpv6Udp::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv6Udp::GetMinSize() 
{
    return (sizeof(ip6_hdr) + sizeof(udphdr) + 4);
}

//
// PctestIpv6Udp::GetAction
//
// Input:  a test record
//
// Output:  action code
//
// Figure out the meaning of a particular combination of ICMPv6 type
// and code values.
//
PctestActionType PctestIpv6Udp::GetAction(int icmpType, int icmpCode)
{
    if (icmpType == ICMP6_TIME_EXCEEDED) {
	return PctestActionType::PctestActionValid;
    }
    else if ((icmpType == ICMP6_DST_UNREACH) &&
	     (icmpCode == ICMP6_DST_UNREACH_NOPORT)) {
	return PctestActionType::PctestActionValidLasthop;
    }
    else if ((icmpType == ICMP6_DST_UNREACH) &&
	     (icmpCode == ICMP6_DST_UNREACH_ADMIN)) {
	return PctestActionType::PctestActionFiltered;
    }
    else {
	return PctestActionType::PctestActionAbort;
    }
}
