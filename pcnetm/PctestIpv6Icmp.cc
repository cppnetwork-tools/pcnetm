static char rcsid[] = "$Id: PctestIpv6Icmp.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv6Icmp.cc 1082 2005-02-12 19:40:04Z bmah $
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
// Class of IPv6 tests using ICMP
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

#include <arpa/inet.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif /* HAVE_PCAP */

#include "pc.h"
#include "PctestIpv6Icmp.h"
#include "TestRecord.h"

//
// PctestIpv6Icmp::PctestIpv6Icmp
//
PctestIpv6Icmp::PctestIpv6Icmp() { 
    extern bool PcapFlag;

#ifdef HAVE_PCAP
    if (PcapFlag) {
	// Initialize packet filter
	if (pcap_compile(pc, &fp, "icmp6", 1, maskp) < 0) {
	    fprintf(stderr, "pcap_compile failed\n");
	    exit(1);
	}
    
	if (pcap_setfilter(pc, &fp) < 0) {
	    fprintf(stderr, "pcap_setfilter failed\n");
	    exit(1);
	}
    }
#endif /* HAVE_PCAP */
};

//
// PctestIpv6Icmp::GetSocketOut
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get output socket of an appropriate type, store it in socketOut.
//
int PctestIpv6Icmp::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (socketOut < 0) {
	perror("socket");
	return socketOut;
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

    rc = bind(socketOut, (struct sockaddr *) &originSocketAddress, 
	      sizeof(originSocketAddress));
    if (rc < 0) { 
	perror("bind()");
	return rc;
    }

    // Bind remote side of socket
    rc = connect(socketOut, (struct sockaddr *) &targetSocketAddress,
		 sizeof(targetSocketAddress));
    if (rc < 0) {
	perror("connect");
	return rc;
    }

    // Set up sockets for advance packets
    if (GetAdvanceSocketOut() < 0) {
	return -1;
    }

    return socketOut;
}

//
// PctestIpv6Icmp::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv6Icmp::Test(TestRecord &tr)
{
    struct timeval timeout;
    int rc;			// syscall return code
    fd_set readFds;		// reading file descriptors
    int done = 0;
    int i;			// generic loop counter

    // Parameters stored as globals
    extern unsigned int Mtu;
    extern bool PcapFlag;
    extern int Timeout;

    // If the requested sending size is too small, then return an
    // error.  The caller should have figured out the minimum sending
    // size by calling Pctest::GetMinSize().
    if (tr.size < GetMinSize()) {
	return -1;
    }

    // Make up an ICMPv6 packet to send out.  We only need the ICMPv6
    // header and payload, and the kernel will take care of computng
    // the ICMPv6 checksum for us.
    int icmp6PayloadSize = tr.size - sizeof(ip6_hdr) - sizeof(icmp6_hdr);
    struct icmp6_hdr icmp6Header;

    icmp6Header.icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6Header.icmp6_code = 0;
    icmp6Header.icmp6_id = htons(icmp6Id);
    icmp6Header.icmp6_seq = htons(icmp6Sequence);

    IF_DEBUG(2, fprintf(stdout, "test size %d, payload size %d\n", tr.size, icmp6PayloadSize));

    // ICMPv6 payload
    char *icmp6Payload;
    icmp6Payload = GeneratePayload(icmp6PayloadSize);
    if (icmp6Payload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
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

#ifdef HAVE_PCAP
    if (!PcapFlag) {
#endif /* HAVE_PCAP */
    // Set timeout value and socket select parameters
    timeout.tv_sec = Timeout;
    timeout.tv_usec = 0;
    FD_ZERO(&readFds);
    FD_SET(socketIn, &readFds);
#ifdef HAVE_PCAP
    }
#endif /* HAVE_PCAP */

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

    // Send packet
    rc = send(socketOut, icmp6Packet, icmp6PacketSize, 0);
    if (rc < 0) {
	perror("sendto");
	goto exittest;
    }

    // We need to check the socket until we get a valid packet.
    // So we might end up doing this select/read several times.
    do {

#ifdef HAVE_PCAP
	if (PcapFlag) {
	    // Wait for a packet.  Only take in one packet at a time.
	    rc = pcap_dispatch(pc, 1, callback, (u_char *) this);
	    if (rc < 0) {
		fprintf(stderr, "pcap_dispatch failed\n");
		goto exittest;
	    }
	    
	    // The callback will handle our after- timestamp if
	    // we get a packet, but if the read timeout fired first,
	    // we'll need to do a timestamp here to be sure that tvAfter
	    // has a valid value in it.
	    if (rc == 0) {
		gettimeofday(&tvAfter, NULL);
	    }
	}
	else {
#endif /* HAVE_PCAP */
	// Select and wait for an ICMP response or a timeout
	rc = select(FD_SETSIZE, &readFds, NULL, NULL, &timeout);
	if (rc < 0) {
	    perror("select");
	    goto exittest;
	}

	// Timestamp after and update test record timestamp fields
	gettimeofday(&tvAfter, NULL);
#ifdef HAVE_PCAP
	}
#endif /* HAVE_PCAP */

	tr.tv.tv_sec = tvAfter.tv_sec - tvBefore.tv_sec - syscallTime.tv_sec;
	tr.tv.tv_usec = tvAfter.tv_usec - tvBefore.tv_usec - syscallTime.tv_usec;
	while (tr.tv.tv_usec < 0) {
	    tr.tv.tv_usec += 1000000;
	    tr.tv.tv_sec--;
	}

	// Read response from socket
	if (rc == 1) {
	    struct msghdr msg;	// msghdr is for recvmsg
	    struct iovec iov[1];
	    int controlsize;

	    IF_DEBUG(2, fprintf(stderr, "Response packet received\n"));
	    memset(&msg, 0, sizeof(struct msghdr));

#ifdef HAVE_PCAP
	    if (PcapFlag) {
		struct ip6_hdr *ipv6Header;

		ipv6Header = (struct ip6_hdr *) packet;

		// Chase down the headers to get to the ICMPv6 header
		// Make tr.replsize and icmp6PacketIn only cover
		// the ICMPv6 header.

		// XXX This isn't the right way to do it, because there might
		// be some extension headers between the IPv6 header
		// and the ICMPv6 header.
		if (ipv6Header->ip6_nxt != IPPROTO_ICMPV6) {
		    IF_DEBUG(2, fprintf(stderr, "Ignoring packet\n"));
		    goto donepacket;
		}
		memcpy(icmp6PacketIn, packet + sizeof(ip6_hdr), packetLength - sizeof(ip6_hdr));
		tr.replsize = packetLength - sizeof(ip6_hdr);

		// Fill in icmpSourceSocketAddress from the IPv6
		// header.
		memcpy(&icmpSourceSocketAddress.sin6_addr,
		       &(ipv6Header->ip6_src),
		       sizeof(in6_addr));
		icmpSourceSocketAddress.sin6_family = AF_INET6;
#ifdef HAVE_SOCKADDR_SA_LEN
		icmpSourceSocketAddress.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_SOCKADDR_SA_LEN */

	    }
	    else {
#endif /* HAVE_PCAP */

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
#ifdef HAVE_PCAP
	    }
#endif /* HAVE_PCAP */

	    // Now parse the packet, doing a little error checking along
	    // the way.  By the end, we'll have ipHeader and icmpHeader
	    // pointing to valid structures within the packet, and
	    // ipHeader2 pointing to the IP header of the generating
	    // IP packet..
	    ip6_hdr *ip6Header;
	    icmp6_hdr *icmp6HeaderIn, *icmp6HeaderIn2;

	    if (tr.replsize - (0) < sizeof(icmp6_hdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete ICMPv6 packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    // Find the ICMPv6 header
	    icmp6HeaderIn = (icmp6_hdr *) icmp6PacketIn;
	    IF_DEBUG(3, fprintf(stderr, "ICMPv6 type = %d, code = %d\n", 
				icmp6HeaderIn->icmp6_type, icmp6HeaderIn->icmp6_code));

	    // Check ICMPv6 type.  See this code in
	    // PctestIpv6Udp::Test for some commentary on a more graceful
	    // way to deal with this whole issue of what type/codes we
	    // want to take.
	    if ((icmp6HeaderIn->icmp6_type != ICMP6_TIME_EXCEEDED) && 
		(icmp6HeaderIn->icmp6_type != ICMP6_DST_UNREACH) &&
		(icmp6HeaderIn->icmp6_type != ICMP6_ECHO_REPLY)) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet\n"));
		goto donepacket;
	    }
	    
	    // Is it an echo reply?  If so, check to see if it's 
	    // ours.  Note no ntoh() conversions needed here because 
	    // we're just comparing fields in two "on-the-wire" packets.
	    if (icmp6HeaderIn->icmp6_type == ICMP6_ECHO_REPLY) {
		if ((icmp6HeaderIn->icmp6_id != icmp6Header.icmp6_id) ||
		    (icmp6HeaderIn->icmp6_seq != icmp6Header.icmp6_seq)) {
		    IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet with mismatched id/seq\n"));
		    goto donepacket;
		}

		// It's ours; fill in return fields.
		goto acceptpacket;
	    }

	    if (tr.replsize - (0 + sizeof(icmp6_hdr)) < 
		sizeof(ip6_hdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner IPv6 packet, %d bytes total\n", tr.replsize));
		goto donepacket;
	    }

	    // Check for a valid (to us) IP header within the packet.
	    // For "time exceeded" or "destination unreachable", this
	    // header will be just past the ICMPv6 header.
	    ip6Header = (ip6_hdr *) ((char *) icmp6HeaderIn + sizeof(icmp6_hdr));

	    // Note:  We can look for an ICMPv6 header immediately following
	    // the inner IPv6 header because we know (or at least we
	    // think we know) that the original packet went out with no
	    // extension headers.  If that's not true, this test will fail.
	    // If we happen to be a situation where we need to do this,
	    // then we have to insert a parser to skip over the extension
	    // headers right here.
	    if (ip6Header->ip6_nxt != IPPROTO_ICMP) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet for non-ICMPv6\n"));
		goto donepacket;
	    }

	    // Check to see if we got enough for a complete ICMP header.
	    // RFC 2463 says that we should get back as much of the
	    // packet that will fit in an MTU.
	    if (tr.replsize - (0 + sizeof(icmp6_hdr) + sizeof(ip6_hdr)) <
		sizeof(icmp6_hdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner ICMPv6 packet, %d bytes total\n", tr.replsize));
		goto donepacket;
	    }

	    // Align ICMP header template.
	    icmp6HeaderIn2 = (icmp6_hdr *) (((char *) ip6Header) + sizeof(ip6_hdr));

	    // Check ID and sequence number of the inner packet to be sure
	    // it matches the one we sent out.
	    if ((icmp6HeaderIn2->icmp6_id != icmp6Header.icmp6_id) ||
		(icmp6HeaderIn2->icmp6_id != icmp6Header.icmp6_id)) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet for unknown ICMPv6 packet\n"));
		goto donepacket;
	    }

	  acceptpacket:
	    // Fill in return fields
	    tr.icmpSourceAddress = new char[sizeof(in6_addr)];

	    memcpy(tr.icmpSourceAddress, &icmpSourceSocketAddress.sin6_addr, sizeof(in6_addr));
	    tr.icmpSourceAddressLength = sizeof(in6_addr);

	    tr.result = GetAction(icmp6HeaderIn->icmp6_type,
				  icmp6HeaderIn->icmp6_code);

	    done = 1;

	  donepacket:
	    if (msg.msg_control) {
		delete [] (char *) msg.msg_control;
		msg.msg_control = NULL;
	    }
	    
	}
	else if (tr.tv.tv_sec >= Timeout) {

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
    delete [] icmp6Payload;
    delete [] icmp6Packet;
    free(icmp6PacketIn);
    return rc;

}

//
// PctestIpv6Icmp::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv6Icmp::GetMinSize() 
{
    return (sizeof(ip6_hdr) + sizeof(icmp6_hdr) + 4);
}

//
// PctestIpv6Icmp::GetAction
//
// Input:  a test record
//
// Output:  action code
//
// Figure out the meaning of a particular combination of ICMPv6 type
// and code values.
//
PctestActionType PctestIpv6Icmp::GetAction(int icmp6_type, int icmp6_code)
{
    if (icmp6_type == ICMP6_TIME_EXCEEDED) {
	return PctestActionType::PctestActionValid;
    }
    else if (icmp6_type == ICMP6_ECHO_REPLY) {
	return PctestActionType::PctestActionValidLasthop;
    }
    else if ((icmp6_type == ICMP6_DST_UNREACH) &&
	     (icmp6_code == ICMP6_DST_UNREACH_ADMIN)) {
	return PctestActionType::PctestActionFiltered;
    }
    else {
	return PctestActionType::PctestActionAbort;
    }
}
