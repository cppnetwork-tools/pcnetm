static char rcsid[] = "$Id: PctestIpv4File.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: PctestIpv4File.cc 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4File.cc
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
// Class of IPv4 tests reading test data from previously-saved results
//

#include <sys/types.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include "pc.h"
#include "PctestIpv4File.h"
#include "TestRecord.h"

extern unsigned int Mtu;

//
// PctestIpv4File::GetSocketOut
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Get output socket of an appropriate type, but for us it's a no-op.
//
int PctestIpv4File::GetSocketOut() {

    return 0;

}

//
// PctestIpv4File::GetSocketIn
//
// Input:  None
//
// Output:  In return value, returns socket number.
//
// Override the superclass behavior...we don't use sockets.
//
int PctestIpv4File::GetSocketIn() {

    return 0;

}

//
// PctestIpv4File::SetOriginName
//
// Input:  ignored
//
// Output:  success code (negative if an error)
//
// This method exists primarily to override PctestIpv4::SetOriginName
// to prevent it from overwriting the originAddress and originName
// members, which were set when the trace file was read using 
// PctestIpv4File::SetTargetName.  All we need to do here is a 
// name lookup.
//
int PctestIpv4File::SetOriginName(char *t) {
    struct hostent *host;	// resolver hostname entry

    originName = strdup(GetName((char *) &originAddress));
    if (originName == NULL) {
	fprintf(stderr, "Couldn't allocate memory for origin hostname.\n");
	return -1;
    }
}

//
// PctestIpv4File::SetTargetName
//
// Input:  ignored
//
// Output:  success code (negative if error)
//
// For protocols that actually send packets on the network,
// do name resolution on the target host.  For this case, however,
// we read in the savefile, for later use by PctestIpv4File::Test.
// As with the other, similar routine(s), we're responsible for
// printing any error messages that come up, since they're likely
// to be domain-specific.
//
int PctestIpv4File::SetTargetName(char *t)
{

    extern unsigned int Burst;	// maximum burst size
    extern unsigned int Hops;	// number of hops
    extern unsigned int Increment; // packet size increment
    extern unsigned int Mtu;	// transfer MTU
    extern char *ReadFilename;	// user-supplied filename
    extern unsigned int Repetitions; // number of repetitions per packet size
    extern unsigned int StartHop; // starting hop number
    extern int VerboseFlag;	// -v from command-line

    bool done = false;		// done reading?
    int linenum = 1;		// line number
    const unsigned int buflen = 1024; // maximum line length
    char buf[buflen];		// line buffer
    char *s;			// return value from fgets
    TestRecord *tr;		// test record read from file
    TestRecord *trstail = NULL;       

    // If the user didn't supply us with a command-line filename,
    // it's an error.
    if (!ReadFilename) {
	fprintf(stderr, "No filename specified for -r\n");
	return -1;
    }

    // Try to open the file
    f = fopen(ReadFilename, "r");
    if (!f) {
	perror("fopen");
	return -1;
    }

    // Loop until finished
    while (!done) {

	s = fgets(buf, buflen, f);

	// See if we're done...
	if (!s) {
	    if (ferror(f)) {
		// error condition
		perror("fgets");
	    }
	    done = true;
	    goto doneline;
	}

	// Process a line.  We're going to make a very simple parser
	// here and in TestRecord::atoh().
	//
	char *cur;

	// First, throw out all blank (or almost blank) lines...
	for (cur = s; *cur != '\0'; cur++) {
	    if (!isspace(*cur)) {
		break;
	    }
	}
	if (*cur == '\0') {
	    goto doneline;
	}

	// Then, look for comment lines
	if (*s == '#') {
	    goto doneline;
	}

	if (strncasecmp(s, "probe ", 6) == 0) {
	    tr = TestRecord::atoh(s, this);

	    if (tr == NULL) {
		return -1;
	    }

	    tr->used = false;

	    // Try to keep the SLL in the same order that we read stuff.
	    // To do this efficiently means we need to (temporarily)
	    // keep a tail pointer.
	    if (trstail) {
		trstail->next = tr;
		trstail = tr;
		tr->next = NULL;
	    }
	    else {
		trs = tr;
		trstail = tr;
		tr->next = NULL;
	    }
	}

	else if (strncasecmp(s, "src ", 4) == 0) {
	    char t[128];
	    sscanf(s, "src %127s", t);
	    originAddress.s_addr = inet_addr(t);
	}

	else if (strncasecmp(s, "dest ", 5) == 0) {
	    char t[128];
	    sscanf(s, "dest %127s", t);
	    targetAddress.s_addr = inet_addr(t);
	}

	else if (strncasecmp(s, "burst ", 6) == 0) {
	    sscanf(s, "burst %d", &Burst);
	}

	else if (strncasecmp(s, "minsize ", 8) == 0) {
	    sscanf(s, "minsize %d", &minsize);
	}

	// hops:
	else if (strncasecmp(s, "hops ", 5) == 0) {
	    sscanf(s, "hops %d", &Hops);
	}

	else if (strncasecmp(s, "increment ", 10) == 0) {
	    sscanf(s, "increment %d", &Increment);
	}

	else if (strncasecmp(s, "mtu ", 4) == 0) {
	    sscanf(s, "mtu %d", &Mtu);
	}

	else if (strncasecmp(s, "repetitions ", 12) == 0) {
	    sscanf(s, "repetitions %d", &Repetitions);
	}

	else if (strncasecmp(s, "starthop ", 9) == 0) {
	    sscanf(s, "starthop %d", &StartHop);
	}

	else if (strncasecmp(s, "targethost ", 11) == 0) {
	    char t[128];
	    sscanf(s, "targethost %127s", t);
	    PctestIpv4::SetTargetName(t);
	}

	else if (strncasecmp(s, "addresses ", 10) == 0) {
	    // Ignore lines that look like this; we already parsed
	    // them to select this object.
	}

	// We can semi-quietly ignore everything else from this point.
	// If we're in verbose mode, we can yell about it.
	else if (VerboseFlag) {
	    fprintf(stderr, "warning: ignoring line %s", s);
	}

      doneline:
	linenum++;

    }

    // Done with file
    fclose(f);
    f = NULL;

    return 0;

}

//
// PctestIpv4File::Test
//
// Input:
//
// Output:
//
// A negative icmpCode indicates a timeout.
//
int PctestIpv4File::Test(TestRecord &tr)
{

    TestRecord *cur;

    // Loop through our set of TestRecords that we've already read
    // in, find the first one that matches both the hops and size,
    // and isn't used yet.
    for (cur = trs; cur; cur = cur->next) {

	if ((!cur->used) && (cur->size == tr.size + ((tr.burst - 1) * Mtu)) && 
	    (cur->hops == tr.hops)) {

	    // Found one!  Now copy everything over from our TestRecord
	    // into the object provided by the caller.
	    tr.tvstart.tv_sec = cur->tvstart.tv_sec;
	    tr.tvstart.tv_usec = cur->tvstart.tv_usec;
	    tr.tv.tv_sec = cur->tv.tv_sec;
	    tr.tv.tv_usec = cur->tv.tv_usec;
	    
	    tr.icmpSourceAddress = new char[sizeof(in_addr)];
	    memcpy(tr.icmpSourceAddress, cur->icmpSourceAddress, sizeof(in_addr));
	    tr.icmpSourceAddressLength = sizeof(in_addr);

	    tr.size = cur->size;
	    tr.replsize = cur->replsize;
	    tr.result = cur->result;

	    cur->used = true;
	    return 0;

	}

    }

    // Error exit
    fprintf(stderr, "Couldn't find enough records\n");
    return -1;

}

//
// PctestIpv4File::GetMinSize
//
// Input:  None
//
// Output:  Minimum packet size possible for this protocol (in return
// value).
//
unsigned int PctestIpv4File::GetMinSize() 
{
    return (minsize);
}

