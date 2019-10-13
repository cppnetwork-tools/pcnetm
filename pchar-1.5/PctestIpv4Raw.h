// -*- c++ -*-
//
// $Id: PctestIpv4Raw.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4Raw.h
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
// Header class for IPv4 tests using raw sockets to send UDP probes.
//

#ifndef PCTESTIPV4RAW_H
#define PCTESTIPV4RAW_H

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
#include "PctestIpv4Udp.h"

class PctestIpv4Raw : public PctestIpv4Udp {

  public:

    PctestIpv4Raw() { 
    };
    PctestIpv4Raw(int p);
    virtual ~PctestIpv4Raw() { 
    };

    virtual int GetSocketOut();
    virtual int Test(TestRecord &tr);
    
  protected:

};

#endif /* PCTESTIPV4RAW_H */
