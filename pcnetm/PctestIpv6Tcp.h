// -*- c++ -*-
//
// $Id: PctestIpv6Tcp.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv6Tcp.h
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
// Header for class of IPv6 tests using TCP
//

#ifndef PCTESTIPV6TCP_H
#define PCTESTIPV6TCP_H

#if HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#if STDC_HEADERS
#include <string.h>
#endif /* STDC_HEADERS */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef NEED_NRL_IPV6_HACK
#include <netinet6/in6.h>
#endif /* NEED_NRL_IPV6_HACK */

#if HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include "pc.h"
#include "PctestIpv6.h"

class PctestIpv6Tcp : public PctestIpv6 {

  public:

    PctestIpv6Tcp() { 
    };
    PctestIpv6Tcp(int p);
    virtual ~PctestIpv6Tcp() { 
    };

    virtual int GetSocketOut();
    virtual int Test(TestRecord &tr);
    virtual unsigned int GetMinSize();
    virtual PctestActionType GetAction(int icmpType, int icmpCode);
   
  protected:

};

#endif /* PCTESTIPV6TCP_H */
