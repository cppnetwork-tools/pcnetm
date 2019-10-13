static char rcsid[] = "$Id: PctestIpv4Raw.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv4Raw.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4Raw.cc
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
// Class of IPv4 tests using raw sockets to send UDP probes
//

#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif /* HAVE_PCAP */

#include "pc.h"
#include "PctestIpv4Raw.h"
#include "TestRecord.h"

extern unsigned Mtu;

//
// PctestIpv4Raw::PctestIpv4Raw
//
PctestIpv4Raw::PctestIpv4Raw(int p) { 
    extern bool PcapFlag;

#ifdef HAVE_PCAP
    if (PcapFlag) {
	// Initialize packet filter
	// 
	// XXX Note that we will see both inbound and outbound packets
	// with this filter rule.  We *could* write up a new rule 
	// to add a src host predicate.  XXX
	if (pcap_compile(pc, &fp, "ip proto \\icmp", 1, maskp) < 0) {
	    fprintf(stderr, "pcap_compile failed\n");
	    exit(1);
	}
    
	if (pcap_setfilter(pc, &fp) < 0) {
	    fprintf(stderr, "pcap_setfilter failed\n");
	    exit(1);
	}
    }
#endif /* HAVE_PCAP */
}

//
// GetSocketOut
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get output socket of an appropriate type, and store its FD in socketOut.
//
int PctestIpv4Raw::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (socketOut < 0) {
	perror("socket");
	return socketOut;
    }
    
    int hdrinclOption;
    hdrinclOption = 1;
    rc = setsockopt(socketOut, IPPROTO_IP, IP_HDRINCL, 
		    (const char *) &hdrinclOption,
		    sizeof(hdrinclOption));
    if (rc < 0) {
	perror("setsockopt(IP_HDRINCL)");
	return rc;
    }

    // Bind remote side of socket 
    // (note that we need to have had PctestIpv4::SetTargetName()
    // called first!
    rc = connect(socketOut, (struct sockaddr *) &targetSocketAddress,
		 sizeof(struct sockaddr_in));
    if (rc < 0) {
	perror("connect");
	return rc;
    }

#ifdef linux
    // Linux needs SO_BSDCOMPAT enabled on our UDP socket, to avoid
    // getting ICMP errors when we send packets out.
    int bsdcompatOption;
    bsdcompatOption = 1;
    rc = setsockopt(socketOut, SOL_SOCKET, SO_BSDCOMPAT, 
		    (const char *) &bsdcompatOption,
		    sizeof(bsdcompatOption));
    if (rc < 0) {
	perror("setsockopt(SO_BSDCOMPAT)");
	return rc;
    }
#endif /* linux */

    return socketOut;
}

//
// PctestIpv4Raw::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv4Raw::Test(TestRecord &tr)
{
    struct timeval timeout;
    int rc;			// syscall return code
    fd_set readFds;		// reading file descriptors
    int done = 0;
    int i;			// generic loop counter

    // Parameters stored as globals
    extern bool PcapFlag;
    extern unsigned int Tos;
    extern int Timeout;

    // If the requested sending size is too small or too large, 
    // then return an error.  The caller should have figured out the 
    // minimum sending size by calling Pctest::GetMinSize().
    if ((tr.size < GetMinSize()) || (tr.size > IP_MAXPACKET)) {
	return -1;
    }

    // Make up a UDP packet to send out.  Start with an IP header.
    // See Section 25.3 of UNIX Network Programming, Second Edition,
    // for why we need to twiddle the byte-orders of some fields but
    // not others, depending on what OS we run.
    struct ip ipHeader;
    memset(&ipHeader, 0, sizeof(ipHeader));
#ifdef __osf__
    // Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
    ipHeader.ip_vhl = (sizeof(ip) >> 2) | (4 << 4);
#else    
    ipHeader.ip_hl = sizeof(ip) >> 2;
    ipHeader.ip_v = 4;
#endif /* __osf__ */
    ipHeader.ip_tos = Tos;
#ifdef linux
    ipHeader.ip_len = htons(tr.size);
#else
    ipHeader.ip_len = tr.size;
#endif /* linux */
    ipHeader.ip_id = htons(0);
#ifdef linux
    ipHeader.ip_off = htons(IP_DF);
#else
    ipHeader.ip_off = IP_DF;
#endif /* linux */
    ipHeader.ip_ttl = tr.hops;
    ipHeader.ip_p = IPPROTO_UDP;
    ipHeader.ip_sum = 0;
    memcpy(&(ipHeader.ip_src), &originAddress, sizeof(struct in_addr));
    memcpy(&(ipHeader.ip_dst), &(targetSocketAddress.sin_addr), sizeof(struct in_addr));

    // Make up UDP header;
    int udpPayloadSize = tr.size - sizeof(ip) - sizeof(udphdr);
    struct udphdr udpHeader;
    memset(&udpHeader, 0, sizeof(udpHeader));
    udpHeader.uh_sport = htons(30003); //XXX
    udpHeader.uh_dport = htons(destPort++);
    udpHeader.uh_ulen = htons(udpPayloadSize + sizeof(udpHeader));
    udpHeader.uh_sum = htons(0); // Let the UDP checksum be 0

    // UDP payload
    char *udpPayload;
    udpPayload = GeneratePayload(udpPayloadSize);
    if (udpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
    }

    // Build the packet now.
    char *ipPacket;
    int ipPacketSize;
    ipPacketSize = sizeof(ip) + sizeof(udphdr) + udpPayloadSize;
    ipPacket = new char[ipPacketSize];
    memcpy(ipPacket, &ipHeader, sizeof(ipHeader));
    memcpy(ipPacket + sizeof(ipHeader), &udpHeader, sizeof(udpHeader));
    memcpy(ipPacket + sizeof(ipHeader) + sizeof(udpHeader),
	   udpPayload, udpPayloadSize);

    // Compute UDP checksum.  We're going to build this up part by part,
    // starting with the different components of the pseudo-header,
    // and then doing the UDP header and payload as a single block.
    // The idea for this comes from the libnet code, basically we build the
    // checksum for the pseudo-header without actually having to
    // store it anywhere.  Not real efficient but it should be OK for
    // our purposes.
    //
    // We note that the UDP checksum routine returns the 1s complement
    // of the 1s complement sum; we need to unroll this to do some
    // other manipulations before actually storing it.
    // We assemble some components to the checksum, and then re-do
    // the checksum carry and complement operations.
    u_int checksum;
    checksum = (u_short) ~InCksum((u_short *) &(ipHeader.ip_src), 
				  2 * sizeof(struct in_addr));
    checksum += (u_short) htons(IPPROTO_UDP) + 
		(u_short) htons(sizeof(udpHeader) + udpPayloadSize);
    checksum += (u_short) ~InCksum((u_short *) (ipPacket + sizeof(ipHeader)),
				   sizeof(udpHeader) + udpPayloadSize);
    while (checksum >> 16) {
	checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    ((udphdr *)(ipPacket + sizeof(ipHeader)))->uh_sum = ~checksum;

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
    char *icmpPacket;
    icmpPacket = (char *) malloc(IP_MAXPACKET);
    if (icmpPacket == NULL) {
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
	rc = send(socketOut, advancePacket, Mtu, 0);
	if (rc < 0) {
	    perror("send");
	    goto exittest;
	}
    }
    tr.size += (tr.burst - 1) * Mtu;

    // Send UDP packet
    rc = send(socketOut, ipPacket, ipPacketSize, 0);
    if (rc < 0) {
	perror("send");
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
	    IF_DEBUG(2, fprintf(stderr, "Response packet received\n"));

#ifdef HAVE_PCAP
	    if (PcapFlag) {
		memcpy(icmpPacket, packet, packetLength);
		tr.replsize = packetLength;
	    }
	    else {
#endif /* HAVE_PCAP */
	    rc = read(socketIn, icmpPacket, IP_MAXPACKET);
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
	    ip *ipHeaderIn, *ipHeaderIn2;
	    icmp *icmpHeaderIn;
	    udphdr *udpHeaderIn;
	    unsigned int ipHeaderLength, ipHeaderLength2;

	    if (tr.replsize < sizeof(ip)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete IP packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    // Check protocol in IP header
	    ipHeaderIn = (ip *) icmpPacket;
	    if (ipHeaderIn->ip_p != proto) {
		IF_DEBUG(0, fprintf(stderr, "Received unknown protocol %d in (supposedly) ICMP packet\n", ipHeaderIn->ip_p));
		rc = -1;
		goto exittest;
	    }

#ifdef __osf__
	    // Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
	    ipHeaderLength = (ipHeaderIn->ip_vhl & 0x0f) << 2;
#else
	    ipHeaderLength = ipHeaderIn->ip_hl << 2;
#endif /* __osf__ */

	    if (tr.replsize - (0 + ipHeaderLength) < ICMP_MINLEN) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete ICMP packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    icmpHeaderIn = (icmp *) (((char *) ipHeaderIn) + ipHeaderLength);

	    IF_DEBUG(3, fprintf(stderr, "ICMP type = %d, code = %d\n", 
				icmpHeaderIn->icmp_type, icmpHeaderIn->icmp_code));

	    // Check ICMP type.  Most types (such as echo request/reply,
	    // router adverts, etc.) we ignore.
	    if ((icmpHeaderIn->icmp_type != ICMP_TIMXCEED) && 
		(icmpHeaderIn->icmp_type != ICMP_UNREACH)) {
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
	    ipHeaderIn2 = (ip *) ((char *) icmpHeaderIn + 8);

	    // Additional checking here...must be UDP
	    if (ipHeaderIn2->ip_p != IPPROTO_UDP) {
		IF_DEBUG(3, fprintf(stderr, "ignoring icmp packet for non-udp\n"));
		continue;
	    }

	    // Align UDP header template.
#ifdef __osf__
	    // Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
	    ipHeaderLength2 = (ipHeaderIn2->ip_vhl & 0x0f) << 2;
#else
	    ipHeaderLength2 = ipHeaderIn2->ip_hl << 2;
#endif /* __osf__ */

	    if (tr.replsize - (0 + ipHeaderLength + ICMP_MINLEN + ipHeaderLength2) < sizeof(udphdr)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner UDP packet, %d bytes total\n", tr.replsize));
		continue;
	    }

	    udpHeaderIn = (udphdr *) (((char *) ipHeaderIn2) + ipHeaderLength2);

	    // Check destination UDP port number (we don't know the
	    // source) and UDP (header+payload) length
	    if ((udpHeaderIn->uh_dport != udpHeader.uh_dport) || 
		(ntohs(udpHeaderIn->uh_ulen) != udpPayloadSize + sizeof(udphdr))) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet for unknown UDP packet\n"));
		continue;
	    }

	    // Fill in return fields
	    tr.icmpSourceAddress = new char[sizeof(in_addr)];
	    memcpy(tr.icmpSourceAddress, &(ipHeaderIn->ip_src), sizeof(in_addr));
	    tr.icmpSourceAddressLength = sizeof(in_addr);

	    tr.result = GetAction(icmpHeaderIn->icmp_type, 
				  icmpHeaderIn->icmp_code);

	    done = 1;

	}
	else if (tr.tv.tv_sec >= Timeout) {
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
    if (advancePacket) {
	delete [] advancePacket;
    }
    delete [] udpPayload;
    delete [] ipPacket;
    free(icmpPacket);
    return rc;

}

