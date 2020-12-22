static char rcsid[] = "$Id: PctestIpv6Tcp.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv6Tcp.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv6Tcp.cc
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
// Class of IPv6 tests using TCP
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

#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif /* HAVE_PCAP */

#include "pc.h"
#include "PctestIpv6Tcp.h"
#include "TestRecord.h"

//
// PctestIpv6Tcp::PctestIpv6Tcp
//
PctestIpv6Tcp::PctestIpv6Tcp(int p) { 
    extern bool PcapFlag;

#ifdef HAVE_PCAP
    if (PcapFlag) {
	// Initialize packet filter
	if (pcap_compile(pc, &fp, "(ip6 and tcp) or (ip6 and icmp6)", 1, maskp) < 0) {
	    fprintf(stderr, "pcap_compile failed\n");
	    exit(1);
	}
    
	if (pcap_setfilter(pc, &fp) < 0) {
	    fprintf(stderr, "pcap_setfilter failed\n");
	    exit(1);
	}
    }
    else {
#endif /* HAVE_PCAP */
	fprintf(stderr, "ipv6tcp probes require libpcap functionality\n");
	exit(1);
#ifdef HAVE_PCAP
    }
#endif /* HAVE_PCAP */
};

//
// PctestIpv6Tcp::GetSocketOut
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get output socket of an appropriate type, store it in socketOut.
//
int PctestIpv6Tcp::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
    if (socketOut < 0) {
	perror("socket");
	return socketOut;
    }
    
    // Turn on checksum computation
    int checksumOffset;
    checksumOffset = 16;	// voodoo constant:  how far into the
				// packet does the TCP checksum live?
    rc = setsockopt(socketOut, IPPROTO_IPV6, IPV6_CHECKSUM, &checksumOffset,
		    sizeof(checksumOffset));
    if (rc < 0) {
	perror("setsockopt(IPV6_CHECKSUM)");
	return rc;
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
// PctestIpv6Tcp::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv6Tcp::Test(TestRecord &tr)
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

#ifdef HAVE_PCAP
    if (PcapFlag) {

    // If the requested sending size is too small, then return an
    // error.  The caller should have figured out the minimum sending
    // size by calling Pctest::GetMinSize().
    if (tr.size < GetMinSize()) {
	return -1;
    }

    // Make up a TCP segment to send out.
    int tcpPayloadSize = tr.size - sizeof(ip6_hdr) - sizeof(icmp6_hdr);
    struct tcphdr tcpHeader;

    // Fill in TCP header fields, see PctestIpv4Tcp::Test() for
    // commentary.
    memset(&tcpHeader, 0, sizeof(tcpHeader));
    tcpHeader.th_sport = htons(30003);
    tcpHeader.th_dport = htons(destPort++);
    tcpHeader.th_seq = htons(0);
    tcpHeader.th_ack = htons(0);
#ifdef __osf__
    // Tru64 <netinet/tcp.h> does not declare th_off if __STDC__ == 1
    tcpHeader.th_xoff = (sizeof(tcphdr)/4)<<4;
		// header length words with no options
		// shifted by 4 bits to cover unused field
#else
    tcpHeader.th_off = sizeof(tcphdr)/4; // header length words with no options
#endif	/* __osf__ */
    tcpHeader.th_flags = TH_FIN | TH_ACK;
    tcpHeader.th_win = htons(1);
    tcpHeader.th_sum = 0;
    tcpHeader.th_urp = htons(0);

    IF_DEBUG(2, fprintf(stdout, "test size %d, payload size %d\n", tr.size, tcpPayloadSize));

    // TCP payload
    char *tcpPayload;
    tcpPayload = GeneratePayload(tcpPayloadSize);
    if (tcpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
    }

    // Build the packet (well, really just the TCP segment)
    char *tcpPacket;
    int tcpPacketSize;
    tcpPacketSize = sizeof(tcphdr) + tcpPayloadSize;
    tcpPacket = new char[tcpPacketSize];
    memcpy(tcpPacket, &tcpHeader, sizeof(tcpHeader));
    memcpy(tcpPacket + sizeof(tcpHeader), tcpPayload, tcpPayloadSize);

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
    rc = send(socketOut, tcpPacket, tcpPacketSize, 0);
    if (rc < 0) {
	perror("sendto");
	goto exittest;
    }

    // We need to check the socket until we get a valid packet.
    // So we might end up doing this select/read several times.
    do {

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

	tr.tv.tv_sec = tvAfter.tv_sec - tvBefore.tv_sec - syscallTime.tv_sec;
	tr.tv.tv_usec = tvAfter.tv_usec - tvBefore.tv_usec - syscallTime.tv_usec;
	while (tr.tv.tv_usec < 0) {
	    tr.tv.tv_usec += 1000000;
	    tr.tv.tv_sec--;
	}

	// Read response
	if (rc == 1) {
	    IF_DEBUG(2, fprintf(stderr, "Response packet received\n"));

	    struct ip6_hdr *ipv6HeaderIn;

	    ipv6HeaderIn = (struct ip6_hdr *) packet;

	    if ((ipv6HeaderIn->ip6_nxt != IPPROTO_ICMPV6) &&
		(ipv6HeaderIn->ip6_nxt != IPPROTO_TCP)) {
		IF_DEBUG(2, fprintf(stderr, "Ignoring non-ICMPv6, non-TCP packet\n"));
		continue;
	    }
	    memcpy(icmp6PacketIn, packet + sizeof(ip6_hdr), packetLength - sizeof(ip6_hdr));
	    tr.replsize = packetLength - sizeof(ip6_hdr);
	    
	    // Fill in icmpSourceSocketAddress from the IPv6
	    // header.
	    memcpy(&icmpSourceSocketAddress.sin6_addr,
		   &(ipv6HeaderIn->ip6_src),
		   sizeof(in6_addr));
	    icmpSourceSocketAddress.sin6_family = AF_INET6;
#ifdef HAVE_SOCKADDR_SA_LEN
	    icmpSourceSocketAddress.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_SOCKADDR_SA_LEN */
	    
	    // Parse the packet and error-check
	    icmp6_hdr *icmp6HeaderIn, *icmp6HeaderIn2;

	    // Check protocol
	    if ((ipv6HeaderIn->ip6_nxt != proto) &&
		(ipv6HeaderIn->ip6_nxt != IPPROTO_TCP)) {
		IF_DEBUG(0, fprintf(stderr, "Received unknown protocol %d in (supposedly) ICMPv6 or TCP packet\n", ipv6HeaderIn->ip6_nxt));
		rc = -1;
		goto exittest;
	    }

	    // See if it was an ICMPv6 message
	    if (ipv6HeaderIn->ip6_nxt == proto) {

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
		    (icmp6HeaderIn->icmp6_type != ICMP6_DST_UNREACH)) {
		    IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet\n"));
		    continue;
		}
		
		// Check the inner packet contained within the ICMP payload
		if (tr.replsize - (0 + sizeof(icmp6_hdr)) < 
		    sizeof(ip6_hdr)) {
		    IF_DEBUG(3, fprintf(stderr, "Received incomplete inner IPv6 packet, %d bytes total\n", tr.replsize));
		    continue;
		}
		
		// Check for a valid (to us) IP header within the packet.
		// For "time exceeded" or "destination unreachable", this
		// header will be just past the ICMPv6 header.
		ipv6HeaderIn = (ip6_hdr *) ((char *) icmp6HeaderIn + sizeof(icmp6_hdr));
		
		// Look for TCP header immediately following the inner
		// IPv6 header.  See PctestIpv6Icmp::Test for commentary
		// on the lack of extension headers.
		if (ipv6HeaderIn->ip6_nxt != IPPROTO_TCP) {
		    IF_DEBUG(3, fprintf(stderr, "Ignoring ICMPv6 packet for non-TCP\n"));
		    continue;
		}

		// Check to see if we got enough for a complete TCP header.
		if (tr.replsize - (0 + sizeof(icmp6_hdr) + sizeof(ip6_hdr)) <
		    sizeof(tcphdr)) {
		    IF_DEBUG(3, fprintf(stderr, "Received incomplete inner TCP header, %d bytes total\n", tr.replsize));
		    continue;
		}
		
		// Align ICMP header template.
		tcphdr *tcpHeaderIn;
		tcpHeaderIn = (tcphdr *) (((char *) ipv6HeaderIn) + sizeof(ip6_hdr));
		
		// XXX Check IPv6 addresses and port numbers to match what we
		// sent out.
		if ((memcmp(&(ipv6HeaderIn->ip6_src), &(originAddress), sizeof(struct in6_addr))) ||
		    (memcmp(&(ipv6HeaderIn->ip6_dst), &(targetAddress), sizeof(struct in6_addr))) ||
		    (tcpHeaderIn->th_dport != tcpHeader.th_dport) ||
		    (tcpHeaderIn->th_sport != tcpHeader.th_sport)) {
		    IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet referring to unknown TCP connection\n"));
		    continue;
		}
		
		// Fill in return fields
		tr.icmpSourceAddress = new char[sizeof(in6_addr)];
		
		memcpy(tr.icmpSourceAddress, &icmpSourceSocketAddress.sin6_addr, sizeof(in6_addr));
		tr.icmpSourceAddressLength = sizeof(in6_addr);
		
		tr.result = GetAction(icmp6HeaderIn->icmp6_type,
				      icmp6HeaderIn->icmp6_code);
		
		done = 1;
	    }
	    
	    // See if we got back a TCP packet
	    else if (ipv6HeaderIn->ip6_nxt == IPPROTO_TCP) {

		tcphdr *tcpHeaderIn;
		tcpHeaderIn = (tcphdr *) (((char *) ipv6HeaderIn) + sizeof(ip6_hdr));

		if ((memcmp(&(ipv6HeaderIn->ip6_src), &(targetAddress), sizeof(struct in6_addr))) ||
		    (memcmp(&(ipv6HeaderIn->ip6_dst), &(originAddress), sizeof(struct in6_addr))) ||
		    (tcpHeaderIn->th_dport != tcpHeader.th_sport) ||
		    (tcpHeaderIn->th_sport != tcpHeader.th_dport)) {
		    IF_DEBUG(3, fprintf(stderr, "Ignoring TCP packet for unknown connection\n"));
		    continue;
		}

		// Fill in return fields
		tr.icmpSourceAddress = new char[sizeof(in6_addr)];
		memcpy(tr.icmpSourceAddress, &(ipv6HeaderIn->ip6_src), sizeof(in6_addr));
		tr.icmpSourceAddressLength = sizeof(in6_addr);
		tr.result = PctestActionType::PctestActionValidLasthop;
		done = 1;
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
    delete [] tcpPayload;
    delete [] tcpPacket;
    free(icmp6PacketIn);
    return rc;
    }
    else {
#endif /* HAVE_PCAP */
	fprintf(stderr, "ipv6tcp probes require libpcap functionality");
	exit(1);
#ifdef HAVE_PCAP
    }
#endif /* HAVE_PCAP */
}

//
// PctestIpv6Tcp::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv6Tcp::GetMinSize() 
{
    return (sizeof(ip6_hdr) + sizeof(tcphdr) + 4);
}

//
// PctestIpv6Tcp::GetAction
//
// Input:  a test record
//
// Output:  action code
//
// Figure out the meaning of a particular combination of ICMPv6 type
// and code values.
//
PctestActionType PctestIpv6Tcp::GetAction(int icmp6_type, int icmp6_code)
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
