// -*- c++ -*-
//
// $Id: PctestIpv4File.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4File.h
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
// Header class for IPv4 tests reading previously saved data from a file.
//

#ifndef PCTESTIPV4FILE_H
#define PCTESTIPV4FILE_H

#if HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if STDC_HEADERS
#include <string.h>
#endif /* STDC_HEADERS */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "pc.h"
#include "PctestIpv4.h"

class PctestIpv4File : public PctestIpv4 {

  public:

    PctestIpv4File() { 
	PctestIpv4File(0);
    };
    PctestIpv4File(int p) { 
	f = NULL;
	trs = NULL;
    };
    virtual ~PctestIpv4File() { 
	if (f) {
	    fclose(f);
	}
    };

    virtual int SetOriginName(char *t);
    virtual int SetTargetName(char *t);
    virtual int GetSocketOut();
    virtual int GetSocketIn();
    virtual int Test(TestRecord &tr);
    virtual unsigned int GetMinSize();
   
  protected:

    FILE *f;
    TestRecord *trs;		// SLL of records read from the file
    u_int minsize;		// minimum packet size

};

#endif /* PCTESTIPV4FILE_H */
