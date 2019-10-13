// -*- c++ -*-
//
// $Id: PctestIpv6Udp.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv6Udp.h
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
// Header class for IPv6 tests using UDP
//

#ifndef PCTESTIPV6UDP_H
#define PCTESTIPV6UDP_H

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if defined(STDC_HEADERS)
#include <string.h>
#endif /* STDC_HEADERS */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef NEED_NRL_IPV6_HACK
#include <netinet6/in6.h>
#endif /* NEED_NRL_IPV6_HACK */

#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "pc.h"
#include "PctestIpv6.h"

class PctestIpv6Udp : public PctestIpv6 {

  public:

    PctestIpv6Udp() { 
    };
    PctestIpv6Udp(int p) { 
    };
    virtual ~PctestIpv6Udp() { 
    };

    virtual int GetSocketOut();
    virtual int Test(TestRecord &tr);
    virtual unsigned int GetMinSize();
    virtual PctestActionType GetAction(int icmpType, int icmpCode);
   
  protected:

};

#endif /* PCTESTIPV6UDP_H */
