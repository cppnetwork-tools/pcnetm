// -*- c++ -*-
// $Id: pc.h 1082 2005-02-12 19:40:04Z bmah $
//
// pc.h
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
// Global definitions, macros, and so forth
//

#ifndef PC_H
#define PC_H

// Debugging macros
extern int DebugLevel;
#define IF_DEBUG(level, action) if (DebugLevel >= level) { action; }

// bool type might not be available everywhere
#if (SIZEOF_BOOL == 0)
typedef enum {false, true} bool;
#endif /* SIZEOF_BOOL */

// Mode types
typedef enum {
    ModeNone,
    ModePchar,
    ModeTrout
} ModeType;

// Network protocol types
typedef enum {
    NetworkProtocolNone,
    NetworkProtocolIpv4Udp,
    NetworkProtocolIpv4Raw,
    NetworkProtocolIpv4Tcp,
    NetworkProtocolIpv4Icmp,
    NetworkProtocolIpv4File
#ifdef HAVE_IPV6
    ,
    NetworkProtocolIpv6Icmp,
    NetworkProtocolIpv6Udp,
    NetworkProtocolIpv6File,
    NetworkProtocolIpv6Tcp
#endif /* HAVE_IPV6 */
} NetworkProtocolType;

// Analysis types
typedef enum {
    AnalysisNone,
    AnalysisLeastSquares,
    AnalysisKendall,
    AnalysisLeastMedianSquares,
    AnalysisLeastMedianSquaresIntegers
} AnalysisType;

// Gap types
typedef enum {
    GapNone,
    GapFixed,
    GapExponential
} GapType;

// Linux networking compatability macros.  For some unfathomable
// reason, Linux systems seem to have named many of their networking
// constants differently than those used by virtually every other
// sockets API implementation.  We try to bring it in line with
// the more widely-used sockets API standards here.
#ifdef linux

// UDP
#define	uh_sport		source
#define	uh_dport		dest
#define	uh_ulen			len
#define uh_sum			check

#endif /* linux */

// Make sure we have a definition for the maximum IP packet size.
// Apparently some Linux systems don't have this defined.
#ifndef IP_MAXPACKET
#define IP_MAXPACKET		65535
#endif /* IP_MAXPACKET */

// Ditto for IPv6 maximum packet size.
#ifndef IPV6_MAXPACKET
#define IPV6_MAXPACKET		65535
#endif /* IPV6_MAXPACKET */

// Some systems might not have MAXTTL
#ifndef MAXTTL
#define MAXTTL			255
#endif /* MAXTTL */

// Some systems might not have IPV6_MAXHLIM.  This is intended for Linux
// systems (observed on RH 7.1), but might be applicable elsewhere.
// NRL-derived IPv6 systems have this constant defined below.
#ifndef IPV6_MAXHLIM
#ifndef NEED_NRL_IPV6_HACK
#define IPV6_MAXHLIM 255
#endif /* NEED_NRL_IPV6_HACK */
#endif /* IPV6_MAXHLIM */

// Define ICMP unreachable codes that might not be otherwise
// available.  (Solaris 2.5.1 and 2.6 have this problem.)
#define ICMP_UNREACH_FILTER_PROHIB	13

// Solaris 2.5.1 (and earlier?) for some reason is lacking the 
// prototype for random(3).  We give them one.
//
// It turns out that Linux glibc2 needs this too, since a mutually
// incompatible set of preprocessor defines is necessary to get
// the headers to define both BSD-style network structures 
// and the random(3) prototype.  So we punt on this and roll our
// own.
#ifdef NEED_RANDOM_PROTO
extern "C" {
    long random(void);
    void srandom(unsigned int);
}
#endif /* NEED_RANDOM_PROTO */

// NRL IPv6 stack hacks.  Basically, they define data structures,
// constants, etc. with different names than KAME (and, apparently,
// the API RFCs).  Some of these we can take care of with some
// preprocessor definitions; others require some different headers.
#ifdef NEED_NRL_IPV6_HACK
#define ip6_hdr		ipv6hdr
#define ip6_nxt		ipv6_nextheader

#define IPV6_MAXHLIM	IPV6_HOPLIMIT

#define icmp6_hdr	icmpv6hdr
#define icmp6_type	icmpv6_type
#define icmp6_code	icmpv6_code
#define icmp6_id	icmpv6_id
#define icmp6_seq	icmpv6_seq

#define ICMP6_ECHO_REQUEST		ICMPV6_ECHO_REQUEST
#define ICMP6_ECHO_REPLY		ICMPV6_ECHO_REPLY
#define ICMP6_TIME_EXCEEDED		ICMPV6_TIME_EXCEEDED
#define ICMP6_DST_UNREACH		ICMPV6_DST_UNREACH
#define ICMP6_DST_UNREACH_ADMIN		ICMPV6_UNREACH_ADMIN
#define ICMP6_DST_UNREACH_NOPORT	ICMPV6_UNREACH_PORT

#define icmp6_filter			icmpv6_filter
#define ICMP6_FILTER		 	ICMPV6_FILTER
#define ICMP6_FILTER_SETBLOCKALL	ICMPV6_FILTER_SETBLOCKALL
#define ICMP6_FILTER_SETPASS		ICMPV6_FILTER_SETPASS
#endif /* NEED_NRL_IPV6_HACK */

#endif /* PC_H */

