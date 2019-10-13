static char rcsid[] = "$Id: main.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: main.cc 1082 2005-02-12 19:40:04Z bmah $
//
// main.cc
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
// Main driver program
//

#include <stdio.h>

#ifdef STDC_HEADERS
#include <stdlib.h>
#else
extern "C" {
    double atof(const char *);
    long random(void);
}
#endif /* STDC_HEADERS */

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <sys/types.h>
#include <time.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "pc.h"
#include "Pctest.h"
#include "PctestIpv4Udp.h"
#include "PctestIpv4Raw.h"
#include "PctestIpv4Tcp.h"
#include "PctestIpv4Icmp.h"
#include "PctestIpv4File.h"
#ifdef HAVE_IPV6
#include "PctestIpv6Icmp.h"
#include "PctestIpv6Tcp.h"
#include "PctestIpv6Udp.h"
#include "PctestIpv6File.h"
#endif /* HAVE_IPV6 */
#include "ResultTable.h"
#include "TestRecord.h"
#ifdef HAVE_SNMP
#include "GetIfInfo.h"
#endif /* HAVE_SNMP */

//
// Forward declarations
//
void DoPchar(Pctest *pct);
void DoTrout(Pctest *pct);
#ifdef HAVE_SNMP
void PrintIfInfo(const GetIfInfo *);
#endif /* HAVE_SNMP */

//
// Default values
//
AnalysisType Analysis = AnalysisLeastSquares;
unsigned int Burst = 1;
bool ChangeFlag = false;
bool PcapFlag = false;
int DebugLevel = 0;
double Gap = 0.25;
GapType GapDist = GapFixed;
unsigned int Hops = 30;
char *Interface = NULL;
unsigned int Increment = 32;
char *OriginHost = NULL;
ModeType Mode = ModePchar;
unsigned int Mtu = 1500;
NetworkProtocolType NetworkProtocol = NetworkProtocolNone;
int NumericFlag = 0;
unsigned int Port = 32768;
char *ReadFilename = NULL;
int QuietFlag = 0;
unsigned int Repetitions = 32;
#ifdef HAVE_SNMP
bool SnmpFlag = false;
#endif /* HAVE_SNMP */
unsigned int StartHop = 1;
unsigned int Timeout = 3;
unsigned int Tos = 0x0;
int VerboseFlag = 0;
char *WriteFilename = NULL;
char *TargetHost = NULL;

//
// Globals
//
ResultTable **PartialResults;
ResultTable **PartialMins;
const int MaxAddressesPerHop = 10;
const int MaxSocketAddressLength = 255;
#ifdef HAVE_PCAP
char PcapErrBuf[PCAP_ERRBUF_SIZE];
#endif /* HAVE_PCAP */

//
// Version
//
// Input:  None
//
// Output:  None
//
// Print version/copyright/build information
//
void VersionInfo()
{
    extern char *Version, *Copyright, *Build, *DFlags;

    fprintf(stderr, "%s\n", Version);
    fprintf(stderr, "%s\n", Copyright);
    fprintf(stderr, "%s\n", Build);
    fprintf(stderr, "Compilation flags: %s\n", DFlags);

}

//
// Usage
//
// Input:  program name (argv0)
//
// Output:  None
//
// Print out invocation information
//
void Usage(char *argv0) {
    fprintf(stderr, "Usage: %s [-a analysis] [-b burst] [-c] "
#ifdef HAVE_PCAP
"[-C] "
#endif /* HAVE_PCAP */
"[-d debuglevel] [-g gap] [-G gaptype] [-h] [-H hops] "
#ifdef HAVE_PCAP
"[-i interface] "
#endif /* HAVE_PCAP */
"[-I increment] [-m mtu] [-n] [-p protocol] [-P port] [-q] [-R reps] [-s hop] "
#ifdef HAVE_SNMP
"[-S] "
#endif /* HAVE_SNMP */
"[-t timeout] [-T tos] [-v] [-V] [-w file] -r file | host]\n", argv0);
    fprintf(stderr, "\t-a analysis\tSet analysis type (default is lsq)\n");
    fprintf(stderr, "\t\t\tlsq\tLeast sum of squares linear fit\n");
    fprintf(stderr, "\t\t\tkendall\tLinear fit using Kendall's test statistic\n");
    fprintf(stderr, "\t\t\tlms\tLeast median of squares linear fit\n");
    fprintf(stderr, "\t\t\tlmsint\tLeast median of squares linear fit (integer computations)\n");
    fprintf(stderr, "\t-b\t\tBurst size (default = %d)\n", Burst);
    fprintf(stderr, "\t-c\t\tIgnore route changes\n");
#ifdef HAVE_PCAP
    fprintf(stderr, "\t-C\t\tUse pcap packet capture facilities\n");
#endif /* HAVE_PCAP */
    fprintf(stderr, "\t-d debuglevel\tSet debugging output level\n");
    fprintf(stderr, "\t-g gap\t\tInter-test gap in seconds (default = %0.2f)\n", Gap);
    fprintf(stderr, "\t-G gaptype\tInter-test gap type (default is fixed)\n");
    fprintf(stderr, "\t\t\tfixed\tFixed gap\n");
    fprintf(stderr, "\t\t\texp\tExponentially distributed random\n");
    fprintf(stderr, "\t-H hops\t\tMaximum number of hops (default = %d)\n", Hops);
    fprintf(stderr, "\t-h\t\tPrint this help information\n");
#ifdef HAVE_PCAP
    fprintf(stderr, "\t-i interface\tpcap interface\n");
#endif /* HAVE_PCAP */
    fprintf(stderr, "\t-I increment\tPacket size increment (default = %d)\n", Increment);
    fprintf(stderr, "\t-l host\t\tSet origin address of probes (defaults to hostname)\n");
    fprintf(stderr, "\t-m mtu\t\tMaximum packet size to check (default = %d)\n", Mtu);
    fprintf(stderr, "\t-M mode\t\tOperational mode (defaults to pchar)\n");
    fprintf(stderr, "\t\t\tpchar\tPath characterization\n");
    fprintf(stderr, "\t\t\ttrout\tTiny traceroute\n");
    fprintf(stderr, "\t-n\t\tDon't resolve addresses to hostnames\n");
    fprintf(stderr, "\t-p protocol\tNetwork protocol (default is ipv4udp)\n");
    fprintf(stderr, "\t\t\tipv4udp\t\tUDP over IPv4\n");
    fprintf(stderr, "\t\t\tipv4raw\t\tUDP over IPv4 (raw sockets)\n");
#ifdef HAVE_PCAP
    fprintf(stderr, "\t\t\tipv4tcp\t\tTCP over IPv4 (raw sockets)\n");
#endif /* HAVE_PCAP */
    fprintf(stderr, "\t\t\tipv4icmp\tICMP over IPv4 (raw sockets)\n");
#ifdef HAVE_IPV6    
    fprintf(stderr, "\t\t\tipv6icmp\tICMPv6 over IPv6 (raw sockets)\n");
    fprintf(stderr, "\t\t\tipv6tcp\t\tTCP over IPv6\n");
    fprintf(stderr, "\t\t\tipv6udp\t\tUDP over IPv6\n");
#endif /* HAVE_IPV6 */
    fprintf(stderr, "\t-P port\t\tStarting port number (default = %d)\n", Port);
    fprintf(stderr, "\t-q\t\tQuiet output\n");
    fprintf(stderr, "\t-r file\t\tRead data from a file (- for stdin)\n");
    fprintf(stderr, "\t-R reps\t\tRepetitions per hop (default = %d)\n", Repetitions);
    fprintf(stderr, "\t-s hop\t\tStarting hop number (default = %d)\n", StartHop);
#ifdef HAVE_SNMP
    fprintf(stderr, "\t-S\t\tDo SNMP queries per-hop\n");
#endif /* HAVE_SNMP */
    fprintf(stderr, "\t-t timeout\tICMP timeout in seconds (default = %d)\n", Timeout);
    fprintf(stderr, "\t-T tos\t\tSet IP type-of-service field (default = %d)\n", Tos);
    fprintf(stderr, "\t-v\t\tVerbose output\n");
    fprintf(stderr, "\t-V\t\tPrint version information\n");
    fprintf(stderr, "\t-w file\t\tWrite data to a file (- for stdout)\n");
    fprintf(stderr, "\n");
}

//
// GetAddressFamily
//
// Input:  None
//
// Output:  String describing the address family for the tracefile
// named by ReadFilename.
//
// Open, scan, and close ReadFilename for an "addresses" line
// and return the parameter associated with that line.
// We use this to figure out what kind of a PctestIpv?File
// object we need.
//
char *GetAddressFamily()
{

    FILE *f;			// file structure
    const unsigned int buflen = 1024; // maximum line length
    char buf[buflen];		// line buffer
    char *s;			// return value from fgets
    char *af = NULL;		// address family string
    bool done = false;

    // If the user didn't supply us with a command-line filename,
    // it's an error.
    if (!ReadFilename) {
	fprintf(stderr, "No filename specified for -r\n");
	return NULL;
    }

    // Try to open the file
    f = fopen(ReadFilename, "r");
    if (!f) {
	perror("fopen");
	return NULL;
    }

    // Loop until finished
    while (!done) {

	s = fgets(buf, buflen, f);

	// See if we're done...
	if (!s) {
	    if (ferror(f)) {
		// error condition
		perror("fgets");
		exit(1);
	    }
	    done = true;
	}
	else {
	    // Process a line.  This is a simplified version of the
	    // parser in PctestIpv4File::SetTargetName().
	    //
	    if (strncasecmp(s, "addresses ", 10) == 0) {
		af = strdup(s+10);
		done = true;
	    }
	}
    }

    // Done with file
    fclose(f);
    f = NULL;

    // Return the string we found after "addresses ", if any.
    return af;

}

//
// GetPrintableNetworkProtocol
//
// Input:  Network protocol
//
// Output:  ASCII representation of network protocol name.
//
char *GetPrintableNetworkProtocol(NetworkProtocolType np)
{
    switch (np) {
    case (NetworkProtocolIpv4Udp): 
	return("UDP/IPv4");
	break;
    case (NetworkProtocolIpv4Raw): 
	return("UDP/IPv4 (raw sockets)");
	break;
    case (NetworkProtocolIpv4Tcp):
	return("TCP/IPv4 (raw sockets)");
	break;
    case (NetworkProtocolIpv4Icmp):
	return("ICMP/IPv4 (raw sockets)");
	break;
    case (NetworkProtocolIpv4File): 
	return("IPv4 save file");
	break;
#ifdef HAVE_IPV6
    case (NetworkProtocolIpv6Icmp): 
	return("ICMPv6/IPv6");
	break;
    case (NetworkProtocolIpv6Tcp): 
	return("TCP/IPv6");
	break;
    case (NetworkProtocolIpv6Udp): 
	return("UDP/IPv6");
	break;
    case (NetworkProtocolIpv6File): 
	return("IPv6 save file");
	break;
#endif /* HAVE_IPV6 */
    default:
	return("unknown network protocol");
	break;
    }
}

//
// main
//
int main(int argc, char **argv)
{

    int c;			// getopt
    Pctest *pct = NULL;		// test structure

    // Parse command-line arguments using getopt
    while ((c = getopt(argc, argv, "a:b:cCd:g:G:hH:i:I:l:m:M:np:P:qR:r:s:St:T:vVw:")) != -1) {

	// Check for the different command-line flags we accept
	switch (c) {

	// a: set analysis type
	case 'a': {
	    if (strcasecmp(optarg, "lsq") == 0) {
		Analysis = AnalysisLeastSquares;
	    }
	    else if (strcasecmp(optarg, "kendall") == 0) {
		Analysis = AnalysisKendall;
	    }
	    else if (strcasecmp(optarg, "lms") == 0) {
		Analysis = AnalysisLeastMedianSquares;
	    }
	    else if (strcasecmp(optarg, "lmsint") == 0) {
		Analysis = AnalysisLeastMedianSquaresIntegers;
	    }
	    else {
		fprintf(stderr, "Invalid analysis type: %s\n", optarg);
		Usage(argv[0]);
		exit(1);
	    }
	    break;
	}

	// b: burst size
	case 'b': {
	    Burst = atoi(optarg);
	    if (Burst < 1) {
		fprintf(stderr, "Warning: burst size %d too small; resetting to 1\n");
		Burst = 1;
	    }
	    break;
	}

	// c: ignore route changes
	case 'c': {
	    ChangeFlag = true;
	    break;
	}

	// C: Use pcap packet capture facilities
	case 'C': {
#ifdef HAVE_PCAP	    
	    PcapFlag = true;
	    break;
#else
	    fprintf(stderr, "pcap unavailable in this build");
	    Usage(argv[0]);
	    exit(1);
#endif /* HAVE_PCAP */
	}

	// d: set debugging level
	case 'd': {
	    DebugLevel = atoi(optarg);
	    break;
	}

	// g: inter-test gap
	case 'g': {
	    Gap = atof(optarg);
	    break;
	}

	// G: set gap type
	case 'G': {
	    if (strcasecmp(optarg, "fixed") == 0) {
		GapDist = GapFixed;
	    }
	    else if (strcasecmp(optarg, "exp") == 0) {
		GapDist = GapExponential;
	    }
	    else {
		fprintf(stderr, "Invalid gap type: %s\n", optarg);
		Usage(argv[0]);
		exit(1);
	    }
	    break;
	}

	// h: print help info and usage
	case 'h': {
	    Usage(argv[0]);
	    exit(0);
	    break;
	};

	// H: Maximum hops
	case 'H': {
	    Hops = atoi(optarg);
	    if (Hops > 255) {
		fprintf(stdout, "Warning: Maximum hops %d too large, resetting to 30\n", Hops);
		Hops = 30;
	    }
	    break;
	}

	case 'i': {
#ifdef HAVE_PCAP
	    Interface = strdup(optarg);
	    if (Interface == NULL) {
		fprintf(stderr, "Couldn't allocate space for interface name\n");
		exit(1);
	    }
	    break;
#else
	    fprintf(stderr, "pcap unavailable in this build");
	    Usage(argv[0]);
	    exit(1);
#endif /* HAVE_PCAP */
	}

	// I: set packet size increment
	case 'I': {
	    Increment = atoi(optarg);
	    break;
	}

	// l: set local origin of probes
	case 'l': {
	    OriginHost = strdup(optarg);
	    if (OriginHost == NULL) {
		fprintf(stderr, "Couldn't allocate space for origin hostname\n");
		exit(1);
	    }
	    break;
	}

	// m: MTU size
	case 'm': {
	    Mtu = atoi(optarg);
	    if (!Mtu) {
		fprintf(stderr, "Mtu argument must be positive (was %d)\n", Mtu);
		exit(1);
	    }
	    break;
	}

	case 'M': {
	    if ((strcasecmp(optarg, "pchar") == 0) ||
	        (strcasecmp(optarg, "pathchar") == 0)) {
		Mode = ModePchar;
	    }
	    else if (strcasecmp(optarg, "trout") == 0) {
		Mode = ModeTrout;
	    }
	    else {
		fprintf(stderr, "Invalid operational mode %s\n", optarg);
		Usage(argv[0]);
		exit(1);
	    }
	    break;
	}

	// n: don't resolve addresses to hostnames
	case 'n': {
	    NumericFlag = 1;
	    break;
	}

	// p: Network protocol
	case 'p': {
	    if (strcasecmp(optarg, "ipv4udp") == 0) {
		NetworkProtocol = NetworkProtocolIpv4Udp;
	    }
	    else if (strcasecmp(optarg, "ipv4raw") == 0) {
		NetworkProtocol = NetworkProtocolIpv4Raw;
	    }
#ifdef HAVE_PCAP
	    else if (strcasecmp(optarg, "ipv4tcp") == 0) {
		NetworkProtocol = NetworkProtocolIpv4Tcp;
	    }
#endif /* HAVE_PCAP */
	    else if (strcasecmp(optarg, "ipv4icmp") == 0) {
		NetworkProtocol = NetworkProtocolIpv4Icmp;
	    }
#ifdef HAVE_IPV6
	    else if (strcasecmp(optarg, "ipv6icmp") == 0) {
		NetworkProtocol = NetworkProtocolIpv6Icmp;
	    }
	    else if (strcasecmp(optarg, "ipv6tcp") == 0) {
		NetworkProtocol = NetworkProtocolIpv6Tcp;
	    }
	    else if (strcasecmp(optarg, "ipv6udp") == 0) {
		NetworkProtocol = NetworkProtocolIpv6Udp;
	    }
#endif /* HAVE_IPV6 */
	    else {
		fprintf(stderr, "Invalid network protocol: %s\n", optarg);
		Usage(argv[0]);
		exit(1);
	    }
	    break;
	}

	// P: starting port number
	case 'P': {
	    Port = atoi(optarg);
	    break;
	}

	// q: quiet output
	case 'q': {
	    QuietFlag = 1;
	    VerboseFlag = 0;
	    break;
	}

	// r: read from file
	case 'r': {
	    ReadFilename = strdup(optarg);
	    if (ReadFilename == NULL) {
		fprintf(stderr, "Couldn't allocate space for statistics filename\n");
		exit(1);
	    }
	    if (WriteFilename) {
		fprintf(stderr, "Warning: both -r and -w specified\n");
	    }
	    break;
	}

	// R: Repetitions per hop
	case 'R': {
	    Repetitions = atoi(optarg);
	    break;
	}

	// s: Starting hop number
	case 's': {
	    StartHop = atoi(optarg);
	    if (StartHop < 1) {
		fprintf(stdout, "Warning: starting hop %d too small, resetting to 1\n", StartHop);
		StartHop = 1;
	    }
	    break;
	}

	// S: Enable SNMP queries
	case 'S': {
#ifdef HAVE_SNMP
	    SnmpFlag = true;
	    break;
#else
	    fprintf(stderr, "SNMP unavailable in this build");
	    Usage(argv[0]);
	    exit(1);
#endif /* HAVE_SNMP */
	}

	// t: ICMP timeout
	case 't': {
	    Timeout = atoi(optarg);
	    if (Timeout < 1) {
		fprintf(stdout, "Warning: timeout value %d too small, resetting to 1\n", Timeout);
		Timeout = 1;
	    }
	    break;
	}

	// T: IP TOS
	case 'T': {
	    Tos = atoi(optarg);
	    break;
	}

	// v: verbose
	case 'v': {
	    VerboseFlag = 1;
	    QuietFlag = 0;
	    break;
	}

	// V: version information
	case 'V': {
	    VersionInfo();
	    exit(0);
	}

	// w: write statistics to file
	case 'w': {
	    WriteFilename = strdup(optarg);
	    if (WriteFilename == NULL) {
		fprintf(stderr, "Couldn't allocate space for statistics filename\n");
		exit(1);
	    }
	    if (ReadFilename) {
		fprintf(stderr, "Warning: both -r and -w specified\n");
	    }
	    break;
	}

	// ? indicates an unrecognized option
	case '?': {
	    Usage(argv[0]);
	    exit(1);
	    break;
	}

	// Didn't know how to handle this case
	default: {
	    fprintf(stderr, "Received valid, but unknown flag %c\n", c);
	    exit(1);
	}

	}
	
    }

    // If we're not reading from a file, we need to get a target host
    // name, which should be the last word on the command line.
    if (!ReadFilename) {
	if (optind != (argc - 1)) {
	    Usage(argv[0]);
	    exit(1);
	}
    }
    TargetHost = argv[optind];
    IF_DEBUG(1, fprintf(stderr, "TargetHost %s\n", TargetHost));

    // Other initialization before we go off to deal with protocol-
    // dependent things:  Weakly seed process random number generator.
    srandom(time(NULL));

    // Initialize a test structure.  Note that reading from a file
    // is a special case.
    if (ReadFilename) {
	
	char *af;

#ifdef WITH_SUID
	// If we're running SUID root, then we drop privileges
	// here.  We don't want to read random files in the
	// filesystem, and the main reason we needed superuser 
	// in the first place (raw sockets) doesn't apply.
	setuid(getuid());
#endif /* WITH_SUID */

	// We need to read the file first to figure out what address
	// family it describes.
	af = GetAddressFamily();

	if (!af) {
	    fprintf(stderr, "Nonexistent address family in tracefile\n");
	    exit(1);
	}
	else {
	    if (strcmp(af, "AF_INET\n") == 0) {
		NetworkProtocol = NetworkProtocolIpv4File;
		pct = new PctestIpv4File();
	    }
#ifdef HAVE_IPV6
	    else if (strcmp(af, "AF_INET6\n") == 0) {
		NetworkProtocol = NetworkProtocolIpv6File;
		pct = new PctestIpv6File();
	    }
#endif /* HAVE_IPV6 */
	    else {
		fprintf(stderr, "Unknown address family %s in tracefile\n", af);
		exit(1);
	    }
	    free(af);
	}


    }
    else {

	// If the user didn't specify a protocol, we have to figure
	// out a default.  For IPv4-only, this trivial.
	if (NetworkProtocol == NetworkProtocolNone) {
#ifdef HAVE_IPV6
	    // IPv6 available, so we need to do a little work here.
	    // We want to resolve the hostname and figure out what
	    // address family comes back first in the response.
	    // Presumably if we have IPv6 available, we can do
	    // getaddrinfo().
	    struct addrinfo *host = NULL;
	    struct addrinfo hints;
	    int error_num;

	    // Setup for getaddrinfo() taken from PctestIpv6::SetTargetName()
	    memset(&hints, 0, sizeof(hints));
	    error_num = getaddrinfo(TargetHost, NULL, &hints, &host);
	    if (host == NULL) {

		// An error here implies there's going to be an error
		// later, so we might as well blow up now.
		fprintf(stderr, "%s: %s\n", TargetHost, gai_strerror(error_num));
		exit(1);

	    }

	    // See which protocol family came back first from the
	    // resolver query.  We'll use that to determine the
	    // default protocol to use.
	    switch (host->ai_family) {

	    case (AF_INET):
		NetworkProtocol = NetworkProtocolIpv4Udp;
		IF_DEBUG(1, fprintf(stderr, "Default protocol UDP/IPv4\n"));
		break;

	    case (AF_INET6):
		NetworkProtocol = NetworkProtocolIpv6Udp;
		IF_DEBUG(1, fprintf(stderr, "Default protocol UDP/IPv6\n"));
		break;

	    default:

		// We don't know what this protocol family is.  Really
		// there's a better way to handle this.  We should 
		// traverse the linked list of host->ai_next until
		// we find a host->ai_family that we *do* recognize,
		// and then use that, and only snarl at the user if
		// we ran down the entire chain without finding
		// something.  Get the simple and dumb behavior
		// working first.
		fprintf(stderr, "%s: Unknown protocol family default\n",
			TargetHost);
		exit(1);
		break;

	    }

	    freeaddrinfo(host);

#else
	    // IPv4 only, so use UDP/IPv4
	    NetworkProtocol = NetworkProtocolIpv4Udp;
	    IF_DEBUG(1, fprintf(stderr, "Default protocol UDP/IPv4\n"));
#endif /* HAVE_IPV6 */	    
	}

	// Normal case is to make a new protocol-dependent structure
	switch (NetworkProtocol) {
	case (NetworkProtocolIpv4Udp):
	    pct = new PctestIpv4Udp(Port);
	    break;
	case (NetworkProtocolIpv4Raw):
	    pct = new PctestIpv4Raw(Port);
	    break;
	case (NetworkProtocolIpv4Tcp):
	    pct = new PctestIpv4Tcp(Port);
	    break;
	case (NetworkProtocolIpv4Icmp):
	    pct = new PctestIpv4Icmp();
	    break;
#ifdef HAVE_IPV6
	case (NetworkProtocolIpv6Icmp):
	    pct = new PctestIpv6Icmp();
	    break;
	case (NetworkProtocolIpv6Tcp):
	    pct = new PctestIpv6Tcp(Port);
	    break;
	case (NetworkProtocolIpv6Udp):
	    pct = new PctestIpv6Udp(Port);
	    break;
#endif /* HAVE_IPV6 */
	default:
	    fprintf(stderr, "Unknown protocol type...exiting...\n");
	    exit(1);
	}
    }

    // Having figured out what the address family is, do the necessary
    // name resolution to determine the source and destination of
    // our probe packets.
    if (pct->SetTargetName(TargetHost) < 0) {
	exit(1);
    }
    if (pct->SetOriginName(OriginHost) < 0) {
	exit(1);
    }

    // Get sockets
    if (pct->GetSocketOut() < 0) {
	exit(1);
    }
    if (pct->GetSocketIn() < 0) {
	exit(1);
    }

#ifdef WITH_SUID
    // If we were running SUID root, then drop privileges here
    // (assuming we didn't do this already).  It's not so great to
    // run this far into the program with superuser privileges.
    // At least we give them up in any case before we write to
    // output files.
    setuid(getuid());
#endif /* WITH_SUID */

    // With all arguments parsed, determine which set of tests
    // to run and go do it.
    switch (Mode) {

    case (ModePchar):
	DoPchar(pct);
	break;

    case (ModeTrout):
	DoTrout(pct);
	break;

    default:
	fprintf(stderr, "Unknown mode type...exiting...\n");
	exit(1);
    }

    // Stick a fork in us, we're done.
    exit(0);
}

//
// DoPchar
//
// Input:  Pctest structure controlling the type of tests to run.
//
// Output:  None.
//
// Run the original path characterization measurement and analysis
// algorithm.
//
void DoPchar(Pctest *pct) 
{
    int i, j, k, l, m;		// universal loop counters
    FILE *df = NULL;		// output file 

    // Generate set of packet sizes to test.  We'll test packets
    // from Increment to the maximum multiple of Increment that
    // that will still fit in Mtu bytes.  We weakly randomize
    // the packet sizes (we just don't want a sequence of
    // packet sizes that is *too* predictable).
    //
    // Note that if increment is small (in particular, if it's
    // smaller than a UDP/IP header), the protocol-specific code
    // will refuse to generate packets smaller than the minimum
    // possible.
    int testsPerRep = Mtu/Increment;
    int *packetSize = new int[testsPerRep];
    for (i = 0; i < testsPerRep; i++) {
	packetSize[i] = Increment * (i+1);
    }
    for (i = 0; i < testsPerRep; i++) {
	int swapIndex = random() % testsPerRep;
	int temp;
	temp = packetSize[i];
	packetSize[i] = packetSize[swapIndex];
	packetSize[swapIndex] = temp;
    }
    for (i = 0; i < testsPerRep; i++) {
	IF_DEBUG(3, fprintf(stderr, "packetsize[%d] = %d\n", i, packetSize[i]));
    }

    typedef ResultTable *ResultTablePtr;
    PartialResults = (ResultTable **) calloc(Hops, sizeof(ResultTable *));
    PartialMins = (ResultTable **) calloc(Hops, sizeof(ResultTable *));
    for (i = 0; i < Hops; i++) {
	PartialResults[i] = NULL;
	PartialMins[i] = NULL;
    }

    //
    // Start output
    //
    if (!QuietFlag) {
	fprintf(stdout, "pchar to %s (%s) using %s\n", pct->GetTargetName(), 
		pct->GetPrintableAddress(),
		GetPrintableNetworkProtocol(NetworkProtocol));
	if (PcapFlag) {
	    fprintf(stdout, "Using pcap capture on %s\n", Interface);
	}
	else {
	    fprintf(stdout, "Using raw socket input\n");
	}
	fprintf(stdout, "Packet size increments from %d to %d by %d\n", 
		pct->GetMinSize(), Mtu, Increment);
	fprintf(stdout, "%d test(s) per repetition\n", testsPerRep);
	fprintf(stdout, "%d repetition(s) per hop\n", Repetitions);
    }

    //
    // If we're probing a real host (as opposed to reading a trace),
    // do a few pings (using whatever protocol we have selected) to
    // try to see if the destination host is really up or not.
    //
    if (!ReadFilename) {
	int rc;			// syscall return code
	TestRecord *tr = new TestRecord; // dummy test record
	int timeouts;		// number of timeouts received so far
	int maxtimeouts = 3;	// we'll make three tries to "ping"
	
	timeouts = 0;
	
	tr->burst = 1;		// only need one packet for pings
	tr->size = 128;		// what packet size is best here?
	if (tr->size < pct->GetMinSize()) {
	    tr->size = pct->GetMinSize();
	}
	
	while (timeouts < maxtimeouts) {
	    tr->hops = MAXTTL;
	
	    rc = pct->Test(*tr);
	
	    // Exit if there was an error.
	    if (rc < 0) {
		exit(1);
	    }
	    
	    if (tr->result == PctestActionTimeout) {
		timeouts++;
	    }
	    else {
		break;
	    }
	}

        // If we didn't get a response to
	// our initial pings, then warn about this fact.  
	if (timeouts >= maxtimeouts) {
	    fprintf(stdout, 
		    "Warning: target host did not respond to initial test.\n");
	}

	delete tr;

    }

    // Print first-hop output line.  Prior versions
    // of this code were more complex because they used the returned
    // ICMP packets to figure out the source address.  But now we
    // have that information up-front.
    if (!QuietFlag) {
	fprintf(stdout, "%2d: %s ", StartHop - 1, 
		pct->GetPrintableAddress(pct->GetOriginAddress()));
	if (NumericFlag) {
	    fprintf(stdout, "(%s)", 
		    pct->GetPrintableAddress(pct->GetOriginAddress()));
	}
	else {
	    fprintf(stdout, "(%s)", pct->GetOriginName());
	}
	fprintf(stdout, "\n");
#ifdef HAVE_SNMP
	if (!ReadFilename && SnmpFlag) {
	    GetIfInfo *gifp;
	    gifp = new GetIfInfo(pct->GetOriginAddress(), pct);
	    PrintIfInfo(gifp);
	    delete gifp;
	}
#endif /* HAVE_SNMP */
    }

    // Initialize statistics save file and write some stuff out
    if (WriteFilename) {

	if (strcmp(WriteFilename, "-") == 0) {
	    df = stdout;
	}
	else {
	    df = fopen(WriteFilename, "w");
	    if (df == NULL) {
		perror("fopen");
		exit(1);
	    }
	}

	// Write initial parameters to the file
	fprintf(df, "addresses %s\n", pct->GetAddressFamilyString());
	fprintf(df, "targethost %s\n", pct->GetTargetName());
	fprintf(df, "src %s\n", pct->GetPrintableAddress(pct->GetOriginAddress()));
	fprintf(df, "dest %s\n", pct->GetPrintableAddress());
	fprintf(df, "hops %d\n", Hops);
	fprintf(df, "burst %d\n", Burst);
	fprintf(df, "minsize %d\n", pct->GetMinSize());
	fprintf(df, "increment %d\n", Increment);
	fprintf(df, "mtu %d\n", Mtu);
	fprintf(df, "burst %d\n", Burst);
	fprintf(df, "repetitions %d\n", Repetitions);
	fprintf(df, "starthop %d\n", StartHop);
    }

    //
    // Begin testing.  We increment the hop number, iterating over
    // the different packet sizes we have available.  (Really, we
    // keep the hop number minus StartHop, and add it back before printing,
    // since the internal data structures we use start from zero.)
    //
    bool firstProbe = true;	// first probe flag
    struct timeval timeFirst, timeLast;	// time of first and last probes
    bool lastHopFlag = true;	// *could* be the last hop
    double aCumulativeLast = 0.0,
	   bCumulativeLast = 0.0,
	   r2CumulativeLast = 0.0;
    double minBandwidth = -1.0; // minimum bandwidth found so far
    double queueingTime = 0.0;	// total queueing time seen so far
    int queueingBytes = 0;	// total queued bytes estimated so far

    char *checkAddress[MaxAddressesPerHop];
    int checkAddressLength[MaxAddressesPerHop];
    for (i = 0; i < MaxAddressesPerHop; i++) {
	checkAddress[i] = new char[MaxSocketAddressLength];
	if (checkAddress[i] == NULL) {
	    fprintf(stderr, "Couldn't allocate space for route change detection\n");
	    exit(1);
	}
    }

    for (i = 0; i < Hops; i++) {

	int packetsLost = 0;
	int packetsSent = 0;

	unsigned addressesSeen = 0; // for detecting routing changes
	bool realTimestamp = false;	// set true once we've received 
				// real timestamp that didn't need
				// adjustments

	PctestActionType pcta;

	// Initialize statistics structure
	PartialResults[i] = new ResultTable(Increment, Mtu, Burst, 
					    Repetitions);
	lastHopFlag = true;

	// Run the correct number of repetitions and iterate over the
	// packet sizes.
	for (j = 0; j < Repetitions; j++) {
	    for (k = 0; k < testsPerRep; k++) {
		for (m = 1; m < Burst + 1; m++) {

		int rc;		// syscall return code
		double rtt;
		TestRecord *tr;	// test record for this test

		// Let the user know what we're doing
		if (VerboseFlag) {
		    fprintf(stderr, 
			    "    hop %2d  rep %3d  burst %2d  size %5d\r", 
			    i+StartHop, j, m, packetSize[k]);
		}

		// Set up variables for a test
		tr = new TestRecord;
		tr->burst = m;
		tr->size = packetSize[k];
		if (tr->size < pct->GetMinSize()) {
		    // Skip this test if the packet size is too small
		    // for this protocol.
		    delete tr;
		    continue;
		}
		tr->hops = i+StartHop;
		gettimeofday(&tr->tvstart, NULL);

		rc = pct->Test(*tr);
		packetsSent++;
		if (rc < 0) {
		    exit(1);
		}

		// Update start and end timestamps for this session
		if (firstProbe) {
		    timeFirst.tv_sec = tr->tvstart.tv_sec;
		    timeFirst.tv_usec = tr->tvstart.tv_usec;
		    firstProbe = false;
		}
		timeLast.tv_sec = tr->tvstart.tv_sec;
		timeLast.tv_usec = tr->tvstart.tv_usec;

		// Write to disk if requested
		if (WriteFilename) {
		    fprintf(df, "%s\n", tr->htoa(pct));
		}

		// Check for a timeout.  If we got one, then increment
		// the appropriate counter and keep going.
		if (tr->result == PctestActionTimeout) {
		    packetsLost++;
		    delete tr;
		    continue;
		}

		// Process the results we got back.
		rtt = tr->tv.tv_sec + (tr->tv.tv_usec/1000000.0);

		// Hack for OSF from Jeffrey Mogul <mogul@pa.dec.com>.
		// Tweak null timestamps upwards, but keep track of whether
		// we've had to do this for every timestamp on a hop or
		// whether or not we've gotten a real one.
		if (rtt == 0.0) {
		    rtt = 0.0000001;
		}
		else {
		    realTimestamp = true;
		}

		IF_DEBUG(2, fprintf(stderr, "bytes = %d, rtt = %f, ip_src = %s, replbytes = %d\n", tr->size, rtt, pct->GetPrintableAddress(tr->icmpSourceAddress), tr->replsize));

		// See if we've seen this address before or not.  If so, 
		// record it for posterity.
		for (l = 0; l < addressesSeen; l++) {
		    if ((checkAddressLength[l] == 
			 tr->icmpSourceAddressLength) && 
			(memcmp(tr->icmpSourceAddress, checkAddress[l], 
				checkAddressLength[l]) == 0)) {
			break;
		    }
		}
		if (l == addressesSeen) {
		    if (addressesSeen == 1) {
			if (!QuietFlag) {
			    fprintf(stdout, "Route change detected\n");
			}
			if ((!ChangeFlag) && (ReadFilename)) {
			    exit(1);
			}
		    }
		    if (addressesSeen < MaxAddressesPerHop) {
			memcpy(checkAddress[addressesSeen],
			       tr->icmpSourceAddress,
			       tr->icmpSourceAddressLength);
			checkAddressLength[addressesSeen] = 
			    tr->icmpSourceAddressLength;
			addressesSeen++;
		    }
		}

		// Have the Pctest subclass figure out what the ICMP
		// type and code fields meant (they're kind of protocol-
		// independent).
		pcta = tr->result;

		// If we received a valid (to us) ICMP message, then
		// attempt to store timing information.
		if ((pcta == PctestActionValid) || 
		    (pcta == PctestActionValidLasthop)) {

		    if ((PartialResults[i]->put(
			tr->size + tr->replsize, rtt)) < 0) {
			fprintf(stderr, "Couldn't store result\n");
			abort();
		    }
		}
		else if (pcta == PctestActionFiltered) {

		    // We hit a firewall or something that's going
		    // to mess with our packets.  Give up now.
		    fprintf(stderr, "ICMP: packet filtered\n");
		    lastHopFlag = true;
		    goto endreps;

		}
		else {
		    // With certain types/codes returned by ICMP, we're also
		    // in trouble.  It'd be nice if the protocol-dependent
		    // packet processing threw away everything except
		    // time exceeded and port-unreachable.
		    fprintf(stderr, "Unexpected response to probe\n");
		}

		// If ICMP type was time exceeded, we know this is *not*
		// the last hop.
		if (pcta != PctestActionValidLasthop) {
		    lastHopFlag = false;
		}

		// If we're not reading from a file, we need to set
		// the delay between network packets (otherwise, this
		// is kind of silly)
		if (!ReadFilename) {

		    // Initialize inter-test gap and other structures
		    struct timeval tvGap;

		    if (GapDist == GapFixed) {
		    
			tvGap.tv_sec = (long) Gap;
			tvGap.tv_usec = (long) ((Gap - ((long) Gap)) * 1000000.0);
		    
		    }
		    else if (GapDist == GapExponential) {

			// Generate exponentially distributed random
			// value with a mean of Gap.
			long u;
			double udub;
			const double maxudub = pow(2.0, 31.0); // 2^31
			double x;

			u = random();
			udub = ((double) u / maxudub);
			x = - Gap * log(udub);

			IF_DEBUG(2, fprintf(stderr, "main:  exponential gap %f\n", x));

			tvGap.tv_sec = (long) x;
			tvGap.tv_usec = (long) ((x - ((long) x)) * 1000000.0);

		    }
		    else {

			fprintf(stderr, "Unknown gap type\n");
			exit(1);

		    }

		    // Delay for some amount of time.
		    rc = select(0, NULL, NULL, NULL, &tvGap);
		    if (rc < 0) {
			perror("select");
		    }
		}
		delete tr;
		}
	    }
	}

endreps:
	// If we weren't in quiet mode, then clear the line we were on
	if (VerboseFlag) {
	    fprintf(stdout, "%80s\r", "");
	}
	
	// If every timestamp got tweaked (on an OSF machine with low
	// clock resolution, running on a fast link, perhaps), then
	// print a warning to this effect.
	if ((!realTimestamp) && (packetsSent > packetsLost)) {
	    fprintf(stdout, "Warning:  No non-zero timestamps measured, bumping up to 0.0000001\n");
	}

	// Per-hop processing and statistics.
	PartialMins[i] = PartialResults[i]->getMin();
	
	double aCumulative, bCumulative, r2Cumulative, aHop, bHop;
	double sa, sb;
	double bLower, bUpper;

	// Get cumulative delay and bandwidth
	if (Analysis == AnalysisLeastSquares) {
	    PartialMins[i]->slr(aCumulative, bCumulative, r2Cumulative, sa, sb);
	}
	else if (Analysis == AnalysisKendall) {
	    PartialMins[i]->tau(aCumulative, bCumulative, bLower, bUpper);
	}
	else if (Analysis == AnalysisLeastMedianSquares) {
	    PartialMins[i]->lms(aCumulative, bCumulative, r2Cumulative);
	}
	else if (Analysis == AnalysisLeastMedianSquaresIntegers) {
	    PartialMins[i]->lmsint(aCumulative, bCumulative, r2Cumulative);
	}
	else {
	    fprintf(stderr, "Unknown statistical analysis type, exiting...\n");
	    exit(1);
	}

	// Figure the per-hop delay and bandwidth.  This computation's
	// correctness relies on aCumulativeLast and bCumulativeLast
	// being initialized to 0.0.
	if (bCumulative > 0.0) {
	    aHop = aCumulative - aCumulativeLast;
	    bHop = bCumulative - bCumulativeLast;
	}
	else {
	    aHop = 0.0;
	    bHop = 0.0;
	}

	// Update our idea of the minimum bandwidth found so far.
	// Clearly we only take into account hop bandwidths that
	// make some sense (positive).
	double hopBandwidth;
	if (bHop != 0.0) {
	    hopBandwidth = (1.0/bHop) * 8.0 / 1000.0;
	}
	else {
	    hopBandwidth = 0.0;
	}

	if (((minBandwidth < 0.0) || (minBandwidth > hopBandwidth)) &&
	    (hopBandwidth > 0.0)) {
	    minBandwidth = hopBandwidth;
	}

	// Compute queueing time statistic(s)
	double qTime;		// estimate of queueing time along path
	double qTimeHop;	// estimate of queueing time this hop
	int qBytes;		// estimate of bytes queued along path
	qTime = PartialResults[i]->queueing();
	qTimeHop = qTime - queueingTime;
	if ((hopBandwidth > 0.0) && (qTimeHop >= 0.0)) {
	    qBytes = (int) (qTimeHop * (1.0/bHop));
	}
	else {
	    qBytes = 0;
	}
	queueingTime = qTime;
	queueingBytes += qBytes;

	// Per-hop output
	if (!QuietFlag) {

	    fprintf(stdout, "    Partial loss:      %d / %d (%d%%)\n", packetsLost, packetsSent, packetsLost * 100 / packetsSent);

	    if (Analysis == AnalysisLeastSquares) {
		fprintf(stdout, "    Partial char:      rtt = %f ms, (b = %f ms/B), r2 = %f\n", aCumulative*1000.0, bCumulative*1000.0, r2Cumulative);

		fprintf(stdout, "                       stddev rtt = %f, stddev b = %f\n", sa * 1000.0, sb * 1000.0);
	    }
	    else if (Analysis == AnalysisKendall) {
		fprintf(stdout, "    Partial char:      rtt = %f ms, (b = %f ms/B)\n", aCumulative*1000.0, bCumulative*1000.0);

		fprintf(stdout, "                       90%% confidence interval is [%f,%f] ms/B\n", bLower * 1000.0, bUpper * 1000.0);
	    }
	    else if ((Analysis == AnalysisLeastMedianSquares) ||
		     (Analysis == AnalysisLeastMedianSquaresIntegers)) {
		fprintf(stdout, "    Partial char:      rtt = %f ms, (b = %f ms/B), r2 = %f\n", aCumulative*1000.0, bCumulative*1000.0, r2Cumulative);
	    }
	    else {
		fprintf(stderr, "Unknown statistical analysis type, exiting...\n");
		exit(1);
	    }

	    fprintf(stdout, "    Partial queueing:  avg = %f ms (%d bytes)\n", qTime, queueingBytes);

	    // Hop characterististics don't make any sense for the first
	    // hop if we start with hop > 1
	    if ((i > 0) || (StartHop == 1)) {
		fprintf(stdout, "    Hop char:          rtt = ");
		if (aHop >= 0.0) {
		    fprintf(stdout, "%f", aHop*1000.0);
		}
		else {
		    fprintf(stdout, "--.---");
		}
		fprintf(stdout, " ms, bw = ");
		if (hopBandwidth >= 0.0) {
		    fprintf(stdout, "%f", hopBandwidth);
		}
		else {
		    fprintf(stdout, "--.---");
		}
		fprintf(stdout, " Kbps\n");

		fprintf(stdout, "    Hop queueing:      avg = %f ms (%d bytes)\n", qTimeHop, qBytes);

	    }

	    if (addressesSeen > 0) {
		for (m = 0; m < addressesSeen; m++) {
		    fprintf(stdout, "%2d: %s ", i+StartHop, 
			    pct->GetPrintableAddress(checkAddress[m]));
		    if (NumericFlag) {
			fprintf(stdout, "(%s)\n", pct->GetPrintableAddress(checkAddress[m]));
		    }
		    else {
			fprintf(stdout, "(%s)\n", pct->GetName(checkAddress[m]));
		    }
#ifdef HAVE_SNMP
		    if (!ReadFilename && SnmpFlag) {
			GetIfInfo *gifp;
			gifp = new GetIfInfo(checkAddress[m], pct);
			PrintIfInfo(gifp);
			delete gifp;
		    }
#endif /* HAVE_SNMP */
		}
	    }
	    else {
		fprintf(stdout, "%2d: no probe responses\n", i+StartHop);
		lastHopFlag = false;
	    }
	}

	// Update inter-hop state
	aCumulativeLast = aCumulative;
	bCumulativeLast = bCumulative;
	r2CumulativeLast = r2Cumulative;

	// If all ICMP messages received were "port unreachable", then
	// we're done.
	if (lastHopFlag) {
	    break;
	}

    }

    int pathLength = i + StartHop;

    // End-of-run processing
    if (!QuietFlag) {

	if (lastHopFlag) {
//	    fprintf(stdout, "    Partial loss:      %d / %d (%d%%)\n", packetsLost, packetsSent, packetsLost * 100 / packetsSent);

	    double aPath, bPath, r2Path, qPath;
	    double saPath, sbPath;
	    double bLowerPath, bUpperPath;

	    if (Analysis == AnalysisLeastSquares) {
		PartialMins[i]->slr(aPath, bPath, r2Path, saPath, sbPath);
	    }
	    else if (Analysis == AnalysisKendall) {
		PartialMins[i]->tau(aPath, bPath, bLowerPath, bUpperPath);
	    }
	    else if (Analysis == AnalysisLeastMedianSquares) {
		PartialMins[i]->lms(aPath, bPath, r2Path);
	    }
	    else if (Analysis == AnalysisLeastMedianSquaresIntegers) {
		PartialMins[i]->lmsint(aPath, bPath, r2Path);
	    }
	    else {
		fprintf(stderr, "Unknown statistical analysis type, exiting...\n");
		exit(1);
	    }

	    qPath = PartialResults[i]->queueing();
	    
	    fprintf(stdout, "    Path length:       %d hops\n", pathLength);
	
	    if (Analysis == AnalysisLeastSquares) {
		fprintf(stdout, "    Path char:         rtt = %f ms r2 = %f\n", aPath*1000.0, r2Path);
	    }
	    else if (Analysis == AnalysisKendall) {
		fprintf(stdout, "    Path char:         rtt = %f ms\n", aPath*1000.0);
	    }
	    else if ((Analysis == AnalysisLeastMedianSquares) ||
		     (Analysis == AnalysisLeastMedianSquaresIntegers)) {
		fprintf(stdout, "    Path char:         rtt = %f ms, r2 = %f\n", aPath*1000.0, r2Path);
	    }
	    else {
		fprintf(stderr, "Unknown statistical analysis type, exiting...\n");
		exit(1);
	    }
	    
	    if (minBandwidth > 0.0) {
		fprintf(stdout, "    Path bottleneck:   %f Kbps\n", minBandwidth);
		fprintf(stdout, "    Path pipe:         %d bytes\n", (int) (aPath * (minBandwidth * 1000.0 / 8.0)));
	    }

	    fprintf(stdout, "    Path queueing:     average = %f ms (%d bytes)\n", qPath, queueingBytes);
	}
	else {
	    fprintf(stdout, "    End of path not reached after %d hops\n", pathLength);
	}

	// We don't know for sure that a time_t is the same size as 
	// one of the members of a struct timeval.  So to make ctime(3)
	// happy, we'll grab the value we want out of the timeval and
	// put it in a real time_t before calling.
	time_t temptime;

	temptime = timeFirst.tv_sec;
	fprintf(stdout, "    Start time:        %s", ctime(&temptime));

	temptime = timeLast.tv_sec;
	fprintf(stdout, "    End time:          %s", ctime(&temptime));
    }

    //
    // Free memory, close files, etc.
    //
    for (i = 0; i < MaxAddressesPerHop; i++) {
	delete [] checkAddress[i];
	checkAddress[i] = NULL;
    }
    if (WriteFilename) {
	fclose(df);
    }
}

//
// DoTrout
//
// Input:  Pctest structure controlling the type of tests to run.
//
// Output:  None.
//
// Run a tiny traceroute (intended for use as a part of a larger
// measurement infrastructure).
//
void DoTrout(Pctest *pct)
{
    int i;			// universal loop counters
    FILE *df = NULL;		// output file 

    //
    // Some of the original pchar parameters may need adjusting...
    Repetitions = 1;		// force repetitions to 1

    //
    // Start output
    //
    if (!QuietFlag) {
	fprintf(stdout, "trout to %s (%s) using %s\n", pct->GetTargetName(), 
		pct->GetPrintableAddress(), 
		GetPrintableNetworkProtocol(NetworkProtocol));
	fprintf(stdout, "Packet size increments from %d to %d by %d\n", 
		pct->GetMinSize(), Mtu, Increment);
    }

    // Print first-hop output line.
    if (!QuietFlag) {
	fprintf(stdout, "%2d: %s ", StartHop - 1, 
		pct->GetPrintableAddress(pct->GetOriginAddress()));
	if (NumericFlag) {
	    fprintf(stdout, "(%s)", 
		    pct->GetPrintableAddress(pct->GetOriginAddress()));
	}
	else {
	    fprintf(stdout, "(%s)", pct->GetOriginName());
	}
	fprintf(stdout, "\n");
#ifdef HAVE_SNMP
	if (!ReadFilename && SnmpFlag) {
	    GetIfInfo *gifp;
	    gifp = new GetIfInfo(pct->GetOriginAddress(), pct);
	    PrintIfInfo(gifp);
	    delete gifp;
	}
#endif /* HAVE_SNMP */
    }

    // Initialize statistics save file and write some stuff out
    if (WriteFilename) {

	if (strcmp(WriteFilename, "-") == 0) {
	    df = stdout;
	}
	else {
	    df = fopen(WriteFilename, "w");
	    if (df == NULL) {
		perror("fopen");
		exit(1);
	    }
	}

	// Write initial parameters to the file
	fprintf(df, "addresses %s\n", pct->GetAddressFamilyString());
	fprintf(df, "targethost %s\n", pct->GetTargetName());
	fprintf(df, "src %s\n", pct->GetPrintableAddress(pct->GetOriginAddress()));
	fprintf(df, "dest %s\n", pct->GetPrintableAddress());
	fprintf(df, "hops %d\n", Hops);
	fprintf(df, "minsize %d\n", pct->GetMinSize());
	fprintf(df, "increment %d\n", Increment);
	fprintf(df, "mtu %d\n", Mtu);
	fprintf(df, "repetitions %d\n", Repetitions);
	fprintf(df, "starthop %d\n", StartHop);
    }

    //
    // Begin testing.  We increment the hop number, iterating over
    // the different packet sizes we have available.  (Really, we
    // keep the hop number minus StartHop, and add it back before printing,
    // since the internal data structures we use start from zero.)
    //
    bool lastHopFlag;		// *could* be the last hop
    int packetsLost = 0;
    int packetsSent = 0;

    for (i = 0; i < Hops; i++) {

	unsigned int packetSize;
	PctestActionType pcta;

	lastHopFlag = true;

	int rc;		// syscall return code
	double rtt;
	TestRecord *tr;	// test record for this test

	// Generate packet size
	packetSize = Increment * (random() % (Mtu/Increment));
	if (packetSize < pct->GetMinSize()) {
	    packetSize = pct->GetMinSize();
	}

	// Let the user know what we're doing
	if (VerboseFlag) {
	    fprintf(stderr, "    hop %2d  size %5d\r", 
		    i+StartHop, packetSize);
	}

	// Set up variables for a test
	tr = new TestRecord;
	tr->burst = 1;
	tr->size = packetSize;
	tr->hops = i+StartHop;
	gettimeofday(&tr->tvstart, NULL);
	tr->tv.tv_sec = 255;
	tr->tv.tv_usec = 0;
	tr->replsize = 0;
	
	rc = pct->Test(*tr);
	packetsSent++;
	if (rc < 0) {
	    exit(1);
	}

	// Write to disk if requested.
	if (WriteFilename) {
	    fprintf(df, "%s\n", tr->htoa(pct));
	}

	// Check for a timeout.  If we got one, then increment
	// the appropriate counter and keep going.
	if (tr->result == PctestActionTimeout) {
	    packetsLost++;
	    delete tr;
	    continue;
	    // XXX Do we want to retry this probe?
	}

	// Process the results we got back.
	rtt = tr->tv.tv_sec + (tr->tv.tv_usec/1000000.0);

	IF_DEBUG(2, fprintf(stderr, "bytes = %d, rtt = %f, ip_src = %s, replbytes = %d\n", tr->size, rtt, pct->GetPrintableAddress(tr->icmpSourceAddress), tr->replsize));
	
	// Have the Pctest subclass figure out what the ICMP
	// type and code fields meant (they're kind of protocol-
	// independent).
	pcta = tr->result;

	// If we received a valid (to us) ICMP message, then
	// attempt to store timing information.
	if ((pcta == PctestActionValid) || 
	    (pcta == PctestActionValidLasthop)) {
	  // XXX Do we write out something here?
	}
	else if (pcta == PctestActionFiltered) {

	    // We hit a firewall or something that's going
	    // to mess with our packets.  Give up now.
	    fprintf(stderr, "ICMP: packet filtered\n");
	    lastHopFlag = true;
	    goto endreps;
	    
	}
	else {
	    // With certain types/codes returned by ICMP, we're also
	    // in trouble.  It'd be nice if the protocol-dependent
	    // packet processing threw away everything except
	    // time exceeded and port-unreachable.
	    fprintf(stderr, "Unexpected response to probe\n");
	    abort();
	}

	// If ICMP type was time exceeded, we know this is *not*
	// the last hop.
	if (pcta != PctestActionValidLasthop) {
	    lastHopFlag = false;
	}

	// Delay between packets
	struct timeval tvGap;
	    
	if (GapDist == GapFixed) {
	    
	    tvGap.tv_sec = (long) Gap;
	    tvGap.tv_usec = (long) ((Gap - ((long) Gap)) * 1000000.0);
	    
	}
	else if (GapDist == GapExponential) {
	    
	    // Generate exponentially distributed random
	    // value with a mean of Gap.
	    long u;
	    double udub;
	    const double maxudub = pow(2.0, 31.0); // 2^31
	    double x;
	    
	    u = random();
	    udub = ((double) u / maxudub);
	    x = - Gap * log(udub);
	    
	    IF_DEBUG(2, fprintf(stderr, "main:  exponential gap %f\n", x));
	    
	    tvGap.tv_sec = (long) x;
	    tvGap.tv_usec = (long) ((x - ((long) x)) * 1000000.0);
	    
	}
	else {
	    
	    fprintf(stderr, "Unknown gap type\n");
	    exit(1);
	    
	}
	
	// Delay for some amount of time.
	rc = select(0, NULL, NULL, NULL, &tvGap);
	if (rc < 0) {
	    perror("select");
	}
	
endreps:
	// If we weren't in quiet mode, then clear the line we were on
	if (VerboseFlag) {
	    fprintf(stdout, "%80s\r", "");
	}
	
	// Per-hop output
	if (!QuietFlag) {
	    fprintf(stdout, "%2d: %s ", i + StartHop, 
		    pct->GetPrintableAddress(tr->icmpSourceAddress));
	    if (NumericFlag) {
		fprintf(stdout, "(%s)", 
			pct->GetPrintableAddress(tr->icmpSourceAddress));
	    }
	    else {
		fprintf(stdout, "(%s)", pct->GetName(tr->icmpSourceAddress));
	    }
	    fprintf(stdout, " %d -> %d bytes: %0.3f ms\n", 
		    tr->size, tr->replsize, rtt * 1000.0);
	}
	
#ifdef HAVE_SNMP
	if (!ReadFilename && SnmpFlag) {
	    GetIfInfo *gifp;
	    gifp = new GetIfInfo(tr->icmpSourceAddress, pct);
	    PrintIfInfo(gifp);
	    delete gifp;
	}
#endif /* HAVE_SNMP */
	
	delete tr;

	// If all ICMP messages received were "port unreachable", then
	// we're done.
	if (lastHopFlag) {
	    break;
	}
    }
    
    // End-of-run processing
    if (!QuietFlag) {
    }

    if (WriteFilename) {
	fclose(df);
    }
}

#ifdef HAVE_SNMP
//
// PrintIfInfo
//
void PrintIfInfo(const GetIfInfo *gifp)
{
    if (gifp == NULL) {
	return;
    }

    fprintf(stdout, "    Description:       %s\n", gifp->GetDescription());
    fprintf(stdout, "    Name:              %s\n", gifp->GetName());
    fprintf(stdout, "    Contact:           %s\n", gifp->GetContact());
    fprintf(stdout, "    Location:          %s\n", gifp->GetLocation());
    fprintf(stdout, "    IfDescription:     %s\n", gifp->GetIfDescription());
    fprintf(stdout, "    Interface:         type = %s(%lu)\n",
	    gifp->GetIfTypeString(), gifp->GetIfType());
    fprintf(stdout, "                       speed = %lu bps, MTU = %lu\n",
	    gifp->GetIfSpeed(), gifp->GetIfMtu());
    fflush(stdout);
}
#endif /* HAVE_SNMP */
