// -*- c++ -*-
//
// $Id: PctestIpv4Tcp.h 1082 2005-02-12 19:40:04Z bmah $
//
// PctestIpv4Tcp.h
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
// Header for class of IPv4 tests using TCP
//

#ifndef PCTESTIPV4TCP_H
#define PCTESTIPV4TCP_H

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

class PctestIpv4Tcp : public PctestIpv4 {

  public:

    PctestIpv4Tcp() { 
    };
    PctestIpv4Tcp(int p);
    virtual ~PctestIpv4Tcp() { 
    };

    virtual int GetSocketOut();
    virtual int Test(TestRecord &tr);
    virtual unsigned int GetMinSize();
    virtual PctestActionType GetAction(int icmpType, int icmpCode);
   
  protected:

};

#endif /* PCTESTIPV4TCP_H */
