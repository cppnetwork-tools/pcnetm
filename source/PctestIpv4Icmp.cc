static char rcsid[] = "$Id: PctestIpv4Icmp.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv4Icmp.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4Icmp.cc
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
// Class of IPv4 tests using ICMP
//

#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif /* HAVE_PCAP */

#include "pc.h"
#include "PctestIpv4Icmp.h"
#include "TestRecord.h"

extern unsigned int Mtu;

//
// PctestIpv4Icmp::PctestIpv4Icmp
//
PctestIpv4Icmp::PctestIpv4Icmp()
{
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
// Get output socket of an appropriate type, store it in socketOut.
//
int PctestIpv4Icmp::GetSocketOut() {

    int rc;
    
    socketOut = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
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

    return socketOut;
}

//
// PctestIpv4Icmp::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates an error.
//
int PctestIpv4Icmp::Test(TestRecord &tr)
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

    // Make up a ICMP packet to send out.  Start with an IP header.
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
    ipHeader.ip_p = IPPROTO_ICMP;
    ipHeader.ip_sum = 0;
    memcpy(&(ipHeader.ip_src), &(originAddress), sizeof(struct in_addr));
    memcpy(&(ipHeader.ip_dst), &(targetSocketAddress.sin_addr), sizeof(struct in_addr));

    // Make up ICMP header.
    int icmpPayloadSize = tr.size - sizeof(ip) - ICMP_MINLEN;
				// need to hardcode size of headers for an ICMP
				// echo request packet, because the associated
				// structure is variable-sized.
    struct icmp icmpHeader;

    icmpHeader.icmp_type = ICMP_ECHO;
    icmpHeader.icmp_code = 0;
    icmpHeader.icmp_cksum = htons(0); // compute checksum
    icmpHeader.icmp_id = htons(icmpId);
    icmpHeader.icmp_seq = htons(icmpSequence++);

    IF_DEBUG(2, fprintf(stdout, "test size %d, payload size %d\n", tr.size, icmpPayloadSize));

    // ICMP payload
    char *icmpPayload;
    icmpPayload = GeneratePayload(icmpPayloadSize);
    if (icmpPayload == NULL) {
	fprintf(stderr, "Couldn't allocate space for payload\n");
	return -1;
    }

    // Build the packet now.
    char *ipPacket;
    int ipPacketSize;
    ipPacketSize = sizeof(ip) + ICMP_MINLEN + icmpPayloadSize;
    ipPacket = new char[ipPacketSize];
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

    // Send ICMP packet
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
	    // IP packet.
	    ip *ipHeaderIn, *ipHeaderIn2;
	    icmp *icmpHeaderIn, *icmpHeaderIn2;
	    unsigned int ipHeaderLength, ipHeaderLength2;

	    if (tr.replsize < sizeof(ip)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete IP packet of %d bytes\n", tr.replsize));
		continue;
	    }

	    // Check protocol in IP header
	    ipHeaderIn = (ip *) icmpPacket;
	    if (ipHeaderIn->ip_p != proto) {
		IF_DEBUG(0, fprintf(stderr, "Received unknown protocol %d in (supposedly) icmp packet\n", ipHeaderIn->ip_p));
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

	    IF_DEBUG(3, fprintf(stderr, "icmp type = %d, code = %d\n", 
				icmpHeaderIn->icmp_type, icmpHeaderIn->icmp_code));

	    // Check ICMP type.  Most types (such as echo request/reply,
	    // router adverts, etc.) we ignore.
	    if ((icmpHeaderIn->icmp_type != ICMP_TIMXCEED) && 
		(icmpHeaderIn->icmp_type != ICMP_UNREACH) &&
		(icmpHeaderIn->icmp_type != ICMP_ECHOREPLY)) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet\n"));
		continue;
	    }
	    
	    // Is it an echo reply?  If so, see if it's a reply to
	    // something we might have sent.
	    if (icmpHeaderIn->icmp_type == ICMP_ECHOREPLY) {
		if ((icmpHeaderIn->icmp_id != icmpHeader.icmp_id) ||
		    (icmpHeaderIn->icmp_seq != icmpHeader.icmp_seq)) {
		    IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet with mismatched id/seq\n"));
		    continue;
		}

		tr.icmpSourceAddress = new char[sizeof(in_addr)];
		memcpy(tr.icmpSourceAddress, &(ipHeaderIn->ip_src), sizeof(in_addr));
		tr.icmpSourceAddressLength = sizeof(in_addr);

		tr.result = GetAction(icmpHeaderIn->icmp_type,
				      icmpHeaderIn->icmp_code);

		done = 1;
		continue;
	    }

	    if (tr.replsize - (0 + ipHeaderLength + ICMP_MINLEN) < 
		sizeof(ip)) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner IP packet, %d bytes total\n", tr.replsize));
		continue;
	    }

	    // Check for a valid (to us) IP header within the packet.
	    // For "time exceeded" or "destination unreachable", this
	    // header will be right after the ICMP header.
	    ipHeaderIn2 = (ip *) ((char *) icmpHeaderIn + ICMP_MINLEN);

	    // Additional checking here...must be ICMP
	    if (ipHeaderIn2->ip_p != IPPROTO_ICMP) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring ICMP packet for non-ICMP\n"));
		continue;
	    }

	    // Align ICMP header template.
#ifdef __osf__
	    // Tru64 <netinet/ip.h> doesn't declar ip_hl if __STDC__ == 1
	    ipHeaderLength2 = (ipHeaderIn2->ip_vhl & 0x0f) << 2;
#else
	    ipHeaderLength2 = ipHeaderIn2->ip_hl << 2;
#endif /* __osf__ */

	    if (tr.replsize - (0 + ipHeaderLength + ICMP_MINLEN + ipHeaderLength2) < ICMP_MINLEN) {
		IF_DEBUG(3, fprintf(stderr, "Received incomplete inner ICMP packet, %d bytes total\n", tr.replsize));
		continue;
	    }
	    icmpHeaderIn2 = (icmp *) (((char *) ipHeaderIn2) + ipHeaderLength2);

	    if ((icmpHeaderIn2->icmp_id != icmpHeader.icmp_id) ||
		(icmpHeaderIn2->icmp_seq != icmpHeader.icmp_seq)) {
		IF_DEBUG(3, fprintf(stderr, "Ignoring inner ICMP packet with mismatched id/seq\n"));
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

	// If we didn't get a packet yet, see if we've waited too long
	else if (tr.tv.tv_sec >= Timeout) {
	    IF_DEBUG(2, fprintf(stderr, "Timeout\n"));

	    tr.icmpSourceAddress = new char[sizeof(in_addr)];
	    memset(tr.icmpSourceAddress, 0, sizeof(in_addr));
	    tr.icmpSourceAddressLength = sizeof(in_addr);

	    tr.result = PctestActionType::PctestActionTimeout;

	    done = 1;
	}
    } while (!done);

    rc = 0;

  exittest:
    if (advancePacket) {
	delete [] advancePacket;
    }
    delete [] icmpPayload;
    delete [] ipPacket;
    free(icmpPacket);
    return rc;

}

//
// PctestIpv4Icmp::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv4Icmp::GetMinSize() 
{
    return (sizeof(ip) + ICMP_MINLEN + 4); // need to hardcode size of an ICMP
				// echo request packet, because the associated
				// structure is variable-sized.
}

//
// PctestIpv4Icmp::GetAction
//
// Input:  a test record
//
// Output:  action code
//
// Figure out the meaning of a particular combination of ICMPv4 type
// and code values.
//
PctestActionType PctestIpv4Icmp::GetAction(int icmpType, int icmpCode) 
{
    if (icmpType == ICMP_TIMXCEED) {
	return PctestActionType::PctestActionValid;
    }
    else if (icmpType == ICMP_ECHOREPLY) {
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
