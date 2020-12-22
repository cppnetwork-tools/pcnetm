static char rcsid[] = "$Id: PctestIpv4Tcp.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv4Tcp.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4Tcp.cc
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
// Class of IPv4 tests using TCP
//

#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif /* HAVE_PCAP */

#include "pc.h"
#include "PctestIpv4Tcp.h"
#include "TestRecord.h"

//
// PctestIpv4Tcp::PctestIpv4Tcp
//
PctestIpv4Tcp::PctestIpv4Tcp(int p)
{
    extern bool PcapFlag;

#ifdef HAVE_PCAP
    if (PcapFlag) {
	// Initialize packet filter
	if (pcap_compile(pc, &fp, "(ip proto \\tcp) or (ip proto \\icmp)", 1, maskp) < 0) {
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
    fprintf(stderr, "ipv4tcp probes require libpcap functionality\n");
    exit(1);
#ifdef HAVE_PCAP
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
// Get output socket of an appropriate type and store its FD in socketOut.
//
int PctestIpv4Tcp::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
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

    rc = connect(socketOut, (struct sockaddr *) &targetSocketAddress,
		 sizeof(struct sockaddr_in));
    if (rc < 0) {
	perror("connect");
	return rc;
    }

    return socketOut;
}

//
// PctestIpv4Tcp::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv4Tcp::Test(TestRecord &tr)
{
    struct timeval timeout;
    int rc;			// syscall return code
    fd_set readFds;		// reading file descriptors
    int done = 0;
    int i;			// loop counter for advance packets

    // Parameters stored as globals
    extern bool PcapFlag;
    extern unsigned int Tos;
    extern unsigned int Mtu;
    extern int Timeout;

#ifdef HAVE_PCAP
    if (PcapFlag) {

    // If the requested sending size is too small or too large, 
    // then return an error.  The caller should have figured out the 
    // minimum sending size by calling Pctest::GetMinSize().
    if ((tr.size < GetMinSize()) || (tr.size > IP_MAXPACKET)) {
	return -1;
    }

    // Make up a TCP packet to send out.  Start with an IP header.
    // See Section 25.3 of UNIX Network Programming, Second Edition,
    // for why we need to twiddle the byte-orders of some fields but
    // not others, depending on what OS we run.
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
    ipHeader.ip_len = tr.size;
#endif /* linux */
    ipHeader.ip_id = htons(0);
#ifdef linux
    ipHeader.ip_off = htons(IP_DF);
#else
    ipHeader.ip_off = IP_DF;
#endif /* linux */
    ipHeader.ip_ttl = tr.hops;
    ipHeader.ip_p = IPPROTO_TCP;
    ipHeader.ip_sum = 0;
    memcpy(&(ipHeader.ip_src), &(originAddress), sizeof(struct in_addr));
    memcpy(&(ipHeader.ip_dst), &(targetSocketAddress.sin_addr), sizeof(struct in_addr));

    // Make up TCP header.
    int tcpPayloadSize = tr.size - sizeof(ip) - sizeof(tcphdr);
    struct tcphdr tcpHeader;

    memset(&tcpHeader, 0, sizeof(tcpHeader));
    tcpHeader.th_sport = htons(30003); //XXX
    tcpHeader.th_dport = htons(destPort++);
    tcpHeader.th_seq = htons(0); // sequence number irrelevant
    tcpHeader.th_ack = htons(0); // acknowledgement irrelevant
#ifdef __osf__
    // Tru64 <netinet/tcp.h> does not declare th_off if __STDC__ == 1
    tcpHeader.th_xoff = (sizeof(tcphdr)/4)<<4;
		// header length words with no options
		// shifted by 4 bits to cover unused field
#else
    tcpHeader.th_off = sizeof(tcphdr)/4; // header length words with no options
#endif	/* __osf__ */
    tcpHeader.th_flags = TH_FIN | TH_ACK; // need to figure out right flags
    tcpHeader.th_win = htons(1); // window advert probably irrelevent
    tcpHeader.th_sum = 0;	// XXX need to generate checksum
    tcpHeader.th_urp = htons(0); // no urgent pointer

    // TCP payload
    char *tcpPayload;
    tcpPayload = GeneratePayload(tcpPayloadSize);
    if (tcpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
    }

    // Build the packet now.
    char *ipPacket;
    int ipPacketSize;
    ipPacketSize = sizeof(ip) + sizeof(tcphdr) + tcpPayloadSize;
    ipPacket = new char[ipPacketSize];
    memcpy(ipPacket, &ipHeader, sizeof(ipHeader));
    memcpy(ipPacket + sizeof(ipHeader), &tcpHeader, sizeof(tcpHeader));
    memcpy(ipPacket + sizeof(ipHeader) + sizeof(tcpHeader),
	   tcpPayload, tcpPayloadSize);

    // Compute TCP checksum.  For comments, see PctestIpv4Raw::Test().
    u_int checksum;
    checksum = (u_short) ~InCksum((u_short *) &(ipHeader.ip_src), 
				  2 * sizeof(struct in_addr));
    checksum += (u_short) htons(IPPROTO_TCP) + 
		(u_short) htons(sizeof(tcpHeader) + tcpPayloadSize);
    checksum += (u_short) ~InCksum((u_short *) (ipPacket + sizeof(ipHeader)),
				   sizeof(tcpHeader) + tcpPayloadSize);
    while (checksum >> 16) {
	checksum = (checksum & 0xffff) + (checksum >> 16);
    }
    ((tcphdr *)(ipPacket + sizeof(ipHeader)))->th_sum = ~checksum;

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

    // Send TCP packet
    rc = send(socketOut, ipPacket, ipPacketSize, 0);
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

	// Read response from socket
	if (rc == 1) {
	    IF_DEBUG(2, fprintf(stderr, "response packet received\n"));

	    memcpy(icmpPacket, packet, packetLength);
	    tr.replsize = packetLength;

	    // Now parse the packet, doing a little error checking along
	    // the way.  By the end, we'll have ipHeader and icmpHeader
	    // pointing to valid structures within the packet, and
	    // ipHeader2 pointing to the IP header of the generating
	    // IP packet..
	    ip *ipHeaderIn, *ipHeaderIn2;
	    icmp *icmpHeaderIn;
	    tcphdr *tcpHeaderIn;

	    // Check protocol in IP header
	    ipHeaderIn = (ip *) icmpPacket;
	    if ((ipHeaderIn->ip_p != proto) && 
		(ipHeaderIn->ip_p != IPPROTO_TCP)) {
		IF_DEBUG(0, fprintf(stderr, "Received unknown protocol %d in (supposedly) ICMP or TCP packet\n", ipHeaderIn->ip_p));
		rc = -1;
		goto exittest;
	    }

	    if (ipHeaderIn->ip_p == proto) {

#ifdef __osf__
		// Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
		icmpHeaderIn = (icmp *) (((char *) ipHeaderIn) +
					 ((ipHeaderIn->ip_vhl & 0x0f) << 2));
#else
		icmpHeaderIn = (icmp *) (((char *) ipHeaderIn) + (ipHeaderIn->ip_hl << 2));
#endif /* __osf__ */
		IF_DEBUG(3, fprintf(stderr, "icmp type = %d, code = %d\n", 
				    icmpHeaderIn->icmp_type, icmpHeaderIn->icmp_code));
		
		// Check ICMP type.  Most types (such as echo request/reply,
		// router adverts, etc.) we ignore.
		if ((icmpHeaderIn->icmp_type != ICMP_TIMXCEED) && 
		    (icmpHeaderIn->icmp_type != ICMP_UNREACH)) {
		    IF_DEBUG(3, fprintf(stderr, "ignoring icmp packet\n"));
		    continue;
		}
		
		// Check for a valid (to us) IP header within the packet.
		// For "time exceeded" or "destination unreachable", this
		// header will be 8 bytes past the ICMP header.
		ipHeaderIn2 = (ip *) ((char *) icmpHeaderIn + 8);
		
		// Check to be sure that we have enough of the packet to hold
		// a valid IP header? XXX
		
		// Additional checking here...must be TCP
		if (ipHeaderIn2->ip_p != IPPROTO_TCP) {
		    IF_DEBUG(3, fprintf(stderr, "ignoring icmp packet for non-tcp\n"));
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
	    else if (ipHeaderIn->ip_p == IPPROTO_TCP) {
		// Align TCP header template, check port numbers and
		// payload length for us. XXX
#ifdef __osf__
		// Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
		tcpHeaderIn = (tcphdr *) (((char *) ipHeaderIn) +
					  ((ipHeaderIn->ip_vhl & 0x0f) << 2));
#else
		tcpHeaderIn = (tcphdr *) (((char *) ipHeaderIn) + (ipHeaderIn->ip_hl << 2));
#endif /* __osf__ */
		
		// Check destination TCP port number (we don't know the
		// source) and TCP (header+payload) length
		// fprintf(stderr, "%d %d %d %d\n",
		// ntohs(tcpHeaderIn->th_dport), ntohs(tcpHeaderIn->th_sport), 
		// ntohs(tcpHeader.th_sport), ntohs(tcpHeader.th_dport));

		if ((tcpHeaderIn->th_dport != tcpHeader.th_sport) || 
		    (tcpHeaderIn->th_sport != tcpHeader.th_dport)) {
		    IF_DEBUG(3, fprintf(stderr, "ignoring tcp packet for unknown tcp packet\n"));
		    continue;
		}
		
		// Fill in return fields
		tr.icmpSourceAddress = new char[sizeof(in_addr)];
		memcpy(tr.icmpSourceAddress, &(ipHeaderIn->ip_src), sizeof(in_addr));
		tr.icmpSourceAddressLength = sizeof(in_addr);
		
		tr.result = PctestActionValidLasthop;

		done = 1;
	    }
	}

	// If we didn't get a packet yet, see if we've waited too long
	else if (tr.tv.tv_sec >= Timeout) {
	    IF_DEBUG(2, fprintf(stderr, "timeout\n"));

	    tr.icmpSourceAddress = new char[sizeof(in_addr)];
	    memset(tr.icmpSourceAddress, 0, sizeof(in_addr));
	    tr.icmpSourceAddressLength = sizeof(in_addr);

	    tr.result = PctestActionTimeout;

	    done = 1;
	}
    } while (!done);

    rc = 0;

  exittest:
    delete [] tcpPayload;
    delete [] ipPacket;
    free(icmpPacket);
    return rc;
    }
    else {
#endif /* HAVE_PCAP */    
    fprintf(stderr, "ipv4tcp probes require libpcap functionality\n");
    exit(1);
#ifdef HAVE_PCAP
    }
#endif /* HAVE_PCAP */
}

//
// PctestIpv4Tcp::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv4Tcp::GetMinSize() 
{
    return (sizeof(ip) + sizeof(tcphdr) + 4);
}

//
// PctestIpv4Tcp::GetAction
//
// Input:  a test record
//
// Output:  action code
//
// Figure out the meaning of a particular combination of ICMPv4 type
// and code values.
//
PctestActionType PctestIpv4Tcp::GetAction(int icmpType, int icmpCode) 
{
    if (icmpType == ICMP_TIMXCEED) {
	return PctestActionType::PctestActionValid;
    }
    else if ((icmpType == ICMP_UNREACH) &&
	     (icmpCode == ICMP_UNREACH_PORT)) {
	return PctestActionType::PctestActionValidLasthop;
    }
    else if ((icmpType == ICMP_UNREACH) &&
	     (icmpCode == ICMP_UNREACH_FILTER_PROHIB)) {
	return PctestActionType::PctestActionFiltered;
    }
    else {
	return PctestActionType::PctestActionAbort;
    }
}
