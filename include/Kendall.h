// -*- c++ -*-
//
// $Id: Kendall.h 1082 2005-02-12 19:40:04Z bmah $
//
// Kendall.h
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

typedef enum {
    KendallP900,
    KendallP950,
    KendallP975,
    KendallP990,
    KendallP995,
    KendallPMax
} KendallPType;

typedef struct {
    unsigned int n;
    unsigned int value[KendallPMax];
} KendallLine;

class Kendall {

  public:
    static unsigned int T(unsigned int n, KendallPType p);

  private:
    static KendallLine table[];

};

