static char rcsid[] = "$Id: Kendall.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: Kendall.cc 1082 2005-02-12 19:40:04Z bmah $
//
// Kendall.cc
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

#include "pc.h"
#include "Kendall.h"

// Quantiles of the Kendall test statistic T, as taken
// from Appendix A11 of W. J. Conover, "Practical
// Nonparametric Statistics", Third Edition, John Wiley &
// Sons, 1999.
KendallLine Kendall::table[] = {
{ 4, { 4, 4, 6, 6, 6 } },
{ 5, { 6, 6, 8, 8, 10 } },
{ 6, { 7, 9, 11, 11, 13 } },
{ 7, { 9, 11, 13, 15, 17 } },
{ 8, { 10, 14, 16, 18, 20 } },
{ 9, { 12, 16, 18, 22, 24 } },
{ 10, { 15, 19, 21, 25, 27 } },
{ 11, { 17, 21, 25, 29, 31 } },
{ 12, { 18, 24, 28, 34, 36 } },
{ 13, { 22, 26, 32, 38, 42 } },
{ 14, { 23, 31, 35, 41, 45 } },
{ 15, { 27, 33, 39, 47, 51 } },
{ 16, { 28, 36, 44, 50, 56 } },
{ 17, { 32, 40, 48, 56, 62 } },
{ 19, { 37, 47, 55, 65, 73 } },
{ 20, { 40, 50, 60, 70, 78 } },
{ 21, { 42, 54, 64, 78, 84 } },
{ 22, { 45, 59, 69, 81, 89 } },
{ 23, { 49, 63, 73, 87, 97 } },
{ 24, { 52, 66, 78, 92, 102 } },
{ 25, { 56, 70, 84, 98, 108 } },
{ 26, { 59, 75, 89, 105, 115 } },
{ 27, { 61, 79, 93, 111, 123 } },
{ 28, { 66, 84, 98, 116, 128 } },
{ 29, { 68, 88, 104, 124, 136 } },
{ 30, { 76, 93, 109, 129, 143 } },
{ 31, { 75, 97, 115, 135, 149 } },
{ 32, { 80, 102, 120, 142, 158 } },
{ 33, { 84, 106, 126, 150, 164 } },
{ 34, { 87, 111, 131, 155, 173 } },
{ 35, { 91, 115, 137, 163, 179 } },
{ 36, { 97, 120, 114, 170, 188 } },
{ 37, { 98, 126, 150, 176, 198 } },
{ 38, { 103, 131, 155, 183, 203 } },
{ 39, { 107, 137, 161, 191, 211 } },
{ 40, { 110, 143, 168, 198, 220 } },
{ 41, { 114, 143, 174, 206, 228 } },
{ 42, { 119, 151, 181, 213, 235 } },
{ 43, { 123, 157, 187, 221, 245 } },
{ 44, { 128, 162, 194, 228, 252 } },
{ 45, { 132, 168, 200, 236, 262 } },
{ 46, { 135, 173, 207, 245, 271 } },
{ 47, { 141, 179, 213, 254, 279 } },
{ 48, { 144, 186, 220, 260, 288 } },
{ 49, { 150, 190, 228, 268, 296 } },
{ 50, { 153, 197, 233, 277, 305 } },
{ 51, { 159, 203, 241, 285, 315 } },
{ 52, { 162, 208, 248, 294, 324 } },
{ 53, { 168, 214, 256, 302, 334 } },
{ 54, { 173, 221, 263, 311, 343 } },
{ 55, { 177, 227, 269, 319, 353 } },
{ 56, { 182, 232, 276, 328, 362 } },
{ 57, { 186, 240, 284, 336, 372 } },
{ 58, { 191, 245, 291, 345, 381 } },
{ 59, { 197, 251, 299, 355, 391 } },
{ 60, { 202, 258, 306, 364, 402 } },
};

//
// Kendall::T
//
// Input:
//
// Output:
//
// For a given n and percentile, return the quantile of the
// Kendall's T test statistic.  0 is returned for a failed
// lookup, where no value could be determined or computed.
//
unsigned int Kendall::T(unsigned int n, KendallPType p) {

    int i;

    // Basically, just a fancy table lookup
    for (i = 0; i < sizeof(table)/sizeof(KendallLine); i++) {

	if (table[i].n == n) {
	    return table[i].value[(int) p];
	}

    }
    return 0;

}
