static char rcsid[] = "$Id: ResultTable.cc 1082 2005-02-12 19:40:04Z bmah $";
//
// $Id: ResultTable.cc 1082 2005-02-12 19:40:04Z bmah $
//
// ResultTable.cc
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
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "pc.h"
#include "ResultTable.h"
#include "Kendall.h"

//
// Constructor
//
// Input:  Table parameters (i, m, b, r)
//
// Output:  None
//
ResultTable::ResultTable(unsigned int inc, unsigned int m, unsigned int b, 
			 unsigned int r) : 
    increment(inc), mtu(m), repetitions(r), burst(b), columns((burst+1)*mtu+1)
// Note the initialization of the columns member; we want to be
// able to hold the largest possible response packet.  (burst+1)*MTU should
// work unless the user sets MTU to something small (then add one because 
// packet sizes begin with 1, not 0).
{
    
    int i;
    
    // Stupid typedef hack for SparcWorks C++ compilier, which apparently
    // can't handle "new (footype *)[bar]".  We're trying to do:
    // data = new (double *) [columns];
    typedef double *DoublePtr;
    data = new (double *[columns]);
    if (data == NULL) {
	fprintf(stderr, "Couldn't allocate data array for a ResultTable\n");
	exit(1);
    }

    used = new int[columns];
    if (used == NULL) {
	fprintf(stderr, "Couldn't allocate used array for a ResultTable\n");
	exit(1);
    }

    for (i = 0; i < columns; i++) {
	data[i] = NULL;
	used[i] = 0;
    }

    // Invalidate result caches
    cacheSlrValid = false;
    cacheTauValid = false;
    cacheLmsValid = false;
    cacheQueueingValid = false;
}

//
// ResultTable::~ResultTable
//
// Input:  None
//
// Output  None
//
ResultTable::~ResultTable() {
    int i;

    for (i = 0; i < columns; i++) {
	if (data[i]) {
	    delete [] data[i];
	    data[i] = NULL;
	}
    }
    delete data;
    delete used;
}

//
// ResultTable::put
//
// Input:  size, time pair
//
// Output:  Success code in return value (negative if an error)
//
// Insert a new result into the table.
//
int ResultTable::put(int size, double time) {
    int offset;

    // Is the offset within the proper range for the table?
    offset = size2column(size);
    if ((offset < 0) || (offset >= columns)) {
	fprintf(stderr, "Size %d out of bounds [0,%d)\n", offset, columns);
	return -1;
    }
    
    // Any room left for more results in this column?
    if (used[offset] == repetitions) {
	fprintf(stderr, 
		"Too many repetitions for this size (%d >= %d)\n", 
		used[offset], repetitions);
	return -1;
    }

    // Need to allocate more memory to hold this column?
    if (data[offset] == NULL) {
	data[offset] = new double[repetitions];
	if (data[offset] == NULL) {
	    fprintf(stderr, "Couldn't allocate memory for new column\n");
	    return -1;
	}
    }

    // Store data
    data[offset][used[offset]] = time;
    (used[offset])++;
    return 0;

    // Invalidate result caches
    cacheSlrValid = false;
    cacheTauValid = false;
    cacheQueueingValid = false;
}

//
// ResultTable::getMin
//
// Input:  none
//
// Output:  Pointer to a new ResultTable (NULL if an error)
//
// Return a new ResultTable, which contains the minimum values
// of each packet size test.
//
ResultTable *ResultTable::getMin() {

    // Get new ResultTable, but we only need room for one
    // "repetition".
    ResultTable *t2 = new ResultTable(increment, mtu, burst, 1);
    if (t2 == NULL) {
	return NULL;
    }

    // Iterate over columns (packet sizes)
    int i;
    for (i = 0; i < columns; i++) {

	// If any values, then find the minimum and store it.
	if (used[i]) {
	    int j;
	    double min = data[i][0];
	    for (j = 1; j < used[i]; j++) {
		if (data[i][j] < min) {
		    min = data[i][j];
		}
	    }

	    if (t2->put(column2size(i), min) < 0) {
		return NULL;
	    }
	}
    }
    return t2;

}

//
// ResultTable::queueing
//
// Input:  None
//
// Output:  Average queueing delay for this dataset (in return
// value).  If there are no data points in this table, the result
// is 0.0.
//
// Compute average (?) queueing delay for this dataset.
// Found by computing, for each column, the difference from the column
// minimum.
//
// XXX we might want some better statistics too, such as getting
// a confidence interval.
//
double ResultTable::queueing()
{

    // If we've cached a queueing figure, then just return it.
    if (cacheQueueingValid) {
	return cacheQueueing;
	IF_DEBUG(1, fprintf(stderr, "ResultTable::queueing(): cache hit\n"));
    }

    // Results not valid, need to compute them.
    else {
	int i, j;
	double sigmaY = 0.0;
	int n = 0;

    // Loop over columns
	for (i = 0; i < columns; i++) {

	    // Only the ones with data points
	    if (used[i] > 0) {

		double min;
		double y;

		// Find the minimum data point for this column
		min = data[i][0];
		for (j = 1; j < used[i]; j++) {
		    if (data[i][j] < min) {
			min = data[i][j];
		    }
		}

		// Now compute the difference between each data
		// point and the minimum and add it to the sum.
		//
		// NB:  There are faster ways to get this result,
		// but we do it this way so that we can get access
		// to the individual data points, for example to
		// compute some other statistics on them.
		for (j = 0; j < used[i]; j++) {
		    y = data[i][j] - min;
		    sigmaY += y;
		    n++;
		}
	    }
	}
	if (n > 0) {
	    cacheQueueing = sigmaY / n;
	}
	else {
	    cacheQueueing = 0.0;
	}
	cacheQueueingValid = true;
	return cacheQueueing;
    }
}

//
// ResultTable::slr
//
// Input:  None
//
// Output:  SLR parameters (a and b, where a is the linear constant
// and b is the X coeffecient), coefficient of determination R2,
// standard deviation of parameters sb and sb.
//
// Compute simple linear regression for all data points, based on
// a least-squares algorithm as described by
// text in Chapter 14 of "The Art of Computer Systems Performance
// Analysis", R. Jain, 1991.
//
void ResultTable::slr(double &a, double &b, double &R2, double &sa, double &sb)
{

    // If cached results valid, use them
    if (cacheSlrValid) {
	a = cacheSlrA;
	b = cacheSlrB;
	R2 = cacheSlrR2;
	sa = cacheSlrSA;
	sb = cacheSlrSB;

	IF_DEBUG(1, fprintf(stderr, "ResultTable::slr(): cache hit\n"));

	return;
    }

    // Compute results
    else {
	double sigmaX = 0.0, sigmaY = 0.0, 
	    sigmaXY = 0.0, 
	    sigmaX2 = 0.0, sigmaY2 = 0.0;
	double Xbar, Ybar;
	double b0, b1;
	double SSY, SS0, SST, SSE, SSR;
	double se;
	int n = 0;
	int i, j;
   
	// Iterate over columns
	for (i = 0; i < columns; i++) {

	    // Iterate over points within a column
	    for (j = 0; j < used[i]; j++) {

		double X = (double) column2size(i);
		double Y = data[i][j];

		sigmaX += X;
		sigmaY += Y;
		sigmaXY += (X*Y);
		sigmaX2 += (X*X);
		sigmaY2 += (Y*Y);
		n++;
	    }
	
	}

	// We need at least three datapoints.  If we don't have that
	// many, return something that, while bogus, at least makes a
	// little sense, to avoid getting divide-by-zero situations.
	if (n == 0) {
	    a = 0.0;
	    b = 0.0;
	    R2 = 0.0;
	    sa = 0.0;
	    sb = 0.0;
	    return;
	}

	Xbar = sigmaX / n;
	Ybar = sigmaY / n;

	// b1 = b, b0 = a
	b1 = (sigmaXY - (n * Xbar * Ybar)) / (sigmaX2 - (n * Xbar * Xbar));
	b0 = Ybar - b1 * Xbar;
    
	// Compute variation
	SSY = sigmaY2;
	SS0 = n * (Ybar * Ybar);
	SST = SSY - SS0;
	SSE = sigmaY2 - (b0 * sigmaY) - (b1 * sigmaXY);
	SSR = SST - SSE;

	// Compute regression parameters
	a = b0;
	b = b1;

	// Compute coefficient of determination
	R2 = SSR/SST;

	// Compute standard deviation of errors
	se = sqrt(SSE/(n-2));

	// Compute Standard deviation of parameters
	sa = se * sqrt( (1/n) + ((Xbar * Xbar) / 
				 (sigmaX2 - (n * Xbar * Xbar))));
	sb = se / sqrt( sigmaX2 - (n * Xbar * Xbar));
	

	// Cache results for later
	cacheSlrA = a;
	cacheSlrB = b;
	cacheSlrR2 = R2;
	cacheSlrSA = sa;
	cacheSlrSB = sb;
	cacheSlrValid = true;
    }
}

//
// ResultTable::tau
//
// Input:  None
//
// Output:  Linear regression parameters (a and b, where a is the
// linear constant and b is the X coeffecient), width of XXX% confidence
// interval for b.
//
// Compute linear fit based on Kendall's tau statistic, as described
// in "Practical Nonparametric Statistics", Third Edition, W. J. Conover, 
// 1999, p. 335.
//
void ResultTable::tau(double &a, double &b, double &blower, double &bupper)
{

    // Check for valid, cached results
    if (cacheTauValid) {
    }
    else {
	unsigned int maxSlopes;	// maximum number of slopes to compute
	unsigned int numSlopes;	// actual number of slopes found
	unsigned int maxValues;	// max values in the table?
	unsigned int numValues;	// how many values in the table?
	int i;			// universal loop counter
	unsigned int xcol, xitem, ycol, yitem;
	
	// Compute number of slopes we might need to work with
	maxSlopes = 0;
	maxValues = 0;
	for (i = 0; i < columns; i++) {
	    maxValues += used[i];
	}

	// If less than two values we can't compute a regression,
	// so give up.
	if (maxValues < 2) {
	    a = 0.0;
	    b = 0.0;
	    blower = 0.0;
	    bupper = 0.0;
	    return;
	}

	maxSlopes = maxValues * (maxValues - 1) / 2;
	
	double *slopes;
	slopes = new double[maxSlopes];
	if (slopes == NULL) {
	    fprintf(stderr, 
		    "Couldn't allocate slopes array for a ResultTable\n");
	    exit(1);
	}

	double *xvalues, *yvalues;
	xvalues = new double[maxValues];
	if (xvalues == NULL) {
	    fprintf(stderr, 
		    "Couldn't allocate xvalues array for a ResultTable\n");
	    exit(1);
	}

	yvalues = new double[maxValues];
	if (yvalues == NULL) {
	    fprintf(stderr, 
		    "Couldn't allocate yvalues array for a ResultTable\n");
	    exit(1);
	}

	// Compute all the slopes.  Basically, we try to treat the
	// maxSlopes datapoints as being in a single, 1-D array,
	// rather than being in a set of 1-D arrays of variable
	// sizes.  We refer to the two values being "pointed to"
	// as x and y.
	numSlopes = 0;
	numValues = 0;
	xcol = 0;
	xitem = 0;

	// Iterate through the items to find X values
	while (xcol < columns) {
	    while (xitem < used[xcol]) {

		// Record this X and Y value
		xvalues[numValues] = (double)column2size(xcol);
		yvalues[numValues] = data[xcol][xitem];
		numValues++;

		// Start looking for Y values, given a single X 
		// value.  Start with the "next" item in sequence
		// after the one we chose for X.  Note that after
		// the next two lines, ycol/yitem might point out
		// of bounds.  That's OK, because we check them
		// immediately afterwards (incrementing if necessary).
		ycol = xcol;
		yitem = xitem + 1;

		while (ycol < columns) {
		    while (yitem < used[ycol]) {

			double xx, xy, yx, yy;
			xx = column2size(xcol);
			xy = data[xcol][xitem];
			yx = column2size(ycol);
			yy = data[ycol][yitem];

			// Try to avoid divide-by-zero errors
			if (yx != xx) {
			    double slope = (yy-xy) / (yx-xx);
			    slopes[numSlopes++] = slope;
			}
			else {
			    fprintf(stderr, "Warning:  Duplicate x values (%f,%f) = (%f,%f)\n", xx, xy, yx, yy);
			}

			yitem++;
		    }
		    ycol++;
		    yitem = 0;
		}

		xitem++;
	    }
	    xcol++;
	    xitem = 0;
	}

	// If we had to throw away points because of duplicate X
	// values, this could throw our confidence intervals off.
	if (numSlopes != maxSlopes) {
	    fprintf(stderr, "Warning: duplicate X values forced discarding of data points\n");
	}

	// Compute slope
	b = median(slopes, numSlopes);

	// Compute intercept
	double xmedian, ymedian;
	xmedian = median(xvalues, numValues);
	ymedian = median(yvalues, numValues);
	a = ymedian - b * xmedian;

	// Compute confidence interval on slope
	unsigned int T, r, s;
	T = Kendall::T(numValues, KendallP950);	// 90% confidence for now
	r = (numSlopes - T) / 2 - 1;
	s = ((numSlopes + T + 1)) / 2;
	
	bupper = slopes[r];
	blower = slopes[s];

	delete [] slopes;
	delete [] xvalues;
	delete [] yvalues;

    }

}

//
// ResultTable::lms
//
// Input:  None
//
// Output:  Linear regression parameters (a and b, where a is the
// linear constant and b is the X coeffecient), coeffecient of
// determination R2.
//
// Compute linear fit based on a Least Median of Squares fit, as
// described in Peter J. Rousseeuw and Annick M. Leroy's 
// "Robust Regression and Outlier Detection", John Wiley & Sons, Inc.,
// New York, NY, 1987.
//
void ResultTable::lms(double &a, double &b, double &r2)
{

    // Check for valid, cached results
    if (cacheLmsValid) {
    }
    else {
	unsigned int maxSlopes;	// maximum number of slopes to compute
	unsigned int numSlopes;	// actual number of slopes found
	unsigned int maxValues;	// max values in the table?
	int i;			// universal loop counter
	unsigned int xcol, xitem, ycol, yitem, zcol, zitem;
	bool estimatorFound;	// flag to see if we've actually computed
				// a residuals quantity yet
	double minLMS, minLMSa, minLMSb; // LMS estimator and associated regression parameters
	
	// Compute number of slopes we might need to work with
	maxSlopes = 0;
	maxValues = 0;
	for (i = 0; i < columns; i++) {
	    maxValues += used[i];
	}

	// If less than two values we can't compute a regression,
	// so give up.
	if (maxValues < 2) {
	    a = 0.0;
	    b = 0.0;
	    r2 = 0.0;
	    return;
	}

	maxSlopes = maxValues * (maxValues - 1) / 2;
	
	double *residuals;
	double *ys;
	residuals = new double[maxValues];
	if (residuals == NULL) {
	    fprintf(stderr, 
		    "Couldn't allocate residuals array for a ResultTable\n");
	    exit(1);
	}

	ys = new double[maxValues];
	if (ys == NULL) {
	    fprintf(stderr, 
		    "Couldn't allocate ys array for a ResultTable\n");
	    exit(1);
	}

        estimatorFound = false;

	// Find all pairs of points, and use them to find a trial
	// set of regression parameters.  We then compute the LMS
	// estimator given these regression parameters, and save
	// the parameters that give us the minimum value of the
	// estimator.
	// 
	// Implementation note:  As with ResultTable::tau (from which 
	// this code is derived), we try to treat the
	// maxSlopes datapoints as being in a single, 1-D array,
	// rather than being in a set of 1-D arrays of variable
	// sizes.  We refer to the two values being "pointed to"
	// as x and y.
	numSlopes = 0;
	xcol = 0;
	xitem = 0;

	// Iterate through the items to find X values
	while (xcol < columns) {
	    while (xitem < used[xcol]) {

		// Start looking for Y values, given a single X 
		// value.  Start with the "next" item in sequence
		// after the one we chose for X.  Note that after
		// the next two lines, ycol/yitem might point out
		// of bounds.  That's OK, because we check them
		// immediately afterwards (incrementing if necessary).
		ycol = xcol;
		yitem = xitem + 1;

		while (ycol < columns) {
		    while (yitem < used[ycol]) {

			double xx, xy, yx, yy;
			xx = column2size(xcol);
			xy = data[xcol][xitem];
			yx = column2size(ycol);
			yy = data[ycol][yitem];

			// Try to avoid divide-by-zero errors
			if (yx != xx) {
			    double slope = (yy-xy) / (yx-xx);
			    double intercept = xy - (slope * xx);
			    unsigned int numResiduals = 0;
			    double estimator;

			    // Compute residuals (well, actually
			    // we're computing the squares of the residuals)
			    zcol = 0;
			    zitem = 0;
			    while (zcol < columns) {
				while (zitem < used[zcol]) {
				    residuals[numResiduals] = 
    pow(data[zcol][zitem] - (column2size(zcol) * slope + intercept), 2);
				    numResiduals++;
				    zitem++;
				}
				zcol++;
				zitem = 0;
			    }

			    // Compute estimator.  If it's less than our
			    // minimum, then save the current regression
			    // parameters.
			    estimator = median(residuals, numResiduals);
			    
			    if ((!estimatorFound) || 
				(estimator < minLMS)) {

				minLMS = estimator;
				minLMSa = intercept;
				minLMSb = slope;
				estimatorFound = true;
				
			    }
			    numSlopes++;

			}
			else {
			    fprintf(stderr, "Warning:  Duplicate x values (%f,%f) = (%f,%f)\n", xx, xy, yx, yy);
			}

			yitem++;
		    }
		    ycol++;
		    yitem = 0;
		}

		xitem++;
	    }
	    xcol++;
	    xitem = 0;
	}

	// If we had to throw away points because of duplicate X
	// values, note this.  It shouldn't really affect results much.
	if (numSlopes != maxSlopes) {
	    fprintf(stderr, "Warning: duplicate X values forced discarding of data points\n");
	}

	if (estimatorFound) {
	    a = minLMSa;
	    b = minLMSb;

	    // Coefficient of Determination computation
	    unsigned int numResiduals;
	    unsigned int numYs;
	    double medianRabs;	// median of all absolute residuals
	    double medianY;	// median of all Y values
	    double madY;	// median absolute deviation

	    // We need to make two passes over the data.  The first pass
	    // gathers the absolute values of the residuals, as well as
	    // all of the data values.  The former will go to compute
	    // med|r sub i|, while the latter gives us med(y sub i).
	    xcol = 0;
	    xitem = 0;
	    numResiduals = 0;
	    numYs = 0;

	    while (xcol < columns) {
		while (xitem < used[xcol]) {

		    residuals[numResiduals] = 
			fabs(data[xcol][xitem] -
			     (column2size(xcol) * minLMSb + minLMSa));
		    numResiduals++;

		    ys[numYs] = data[xcol][xitem];
		    numYs++;

		    xitem++;
		}

		xcol++;
		xitem = 0;
	    }

	    medianRabs = median(residuals, numResiduals);
	    medianY = median(ys, numYs);

	    // In the second pass over the data, we use the median Y
	    // value we computed earlier to determine 
	    // med|y sub i - med(y sub j)|.
	    xcol = 0;
	    xitem = 0;
	    numYs = 0;

	    while (xcol < columns) {
		while (xitem < used[xcol]) {

		    ys[numYs] = 
			fabs(data[xcol][xitem] - medianY);
		    numYs++;
		    
		    xitem++;
		}
	       
		xcol++;
		xitem = 0;
	    }

	    madY = median(ys, numYs);
	    r2 = 1.0 - pow((medianRabs / madY), 2);

	}
	else {
	    fprintf(stderr, "Warning: residual computation failed\n");
	    a = 0.0;
	    b = 0.0;
	    r2 = 0.0;
	}

	delete [] residuals;
	delete [] ys;

    }

}

//
// ResultTable::lmsint
//
// Input:  None
//
// Output:  Linear regression parameters (a and b, where a is the
// linear constant and b is the X coeffecient), coeffecient of
// determination R2.
//
// Compute linear fit based on a Least Median of Squares fit.
// The algorithm used is the same as ResultTable::lms, except that
// we do all computations using only int32 variables.  This is a
// check of an IOS implementation of this algorithm.
//
void ResultTable::lmsint(double &a, double &b, double &r2)
{
    unsigned int *partialmins;	// We assume we've got minfiltered points
    unsigned int *residuals;	// Residuals
    unsigned int *ys;		// Copy of y values
    int i, j, k, l;		// loop counters
    int currentslope;
    int currentintercept;
    unsigned int r2int;		// coefficient of determination

    const unsigned int timeoutresult = 0;
    const unsigned int slopescale = 1000; // scaling factor for slope computations 
    const unsigned int codscale = 1000;	// sqrt of scaling factor for coefficient of determination

    ys = new unsigned int[columns];
    if (ys == NULL) {
	fprintf(stderr, 
		"Couldn't allocate ys array for a ResultTable\n");
	exit(1);
    }

    partialmins = new unsigned int[columns];
    if (partialmins == NULL) {
	fprintf(stderr, 
		"Couldn't allocate partialmins array for a ResultTable\n");
	exit(1);
    }

    for (i = 0; i < columns; i++) {
	// Convert dataset to integers representing microseconds.
	partialmins[i] = (unsigned int) (data[i][0] * 1000000.0);
    }
    residuals = new unsigned int[columns*columns];
    if (residuals == NULL) {
	fprintf(stderr, 
		"Couldn't allocate residuals array for a ResultTable\n");
	exit(1);
    }
    
    // Following code comes from the IOS version of pchar, hence
    // the C-style comments.

    /*
     * Linear regression happens on the minfiltered datapoints.
     */
    {
	/*
	 * Use the least median of squares regression.  Slopes are in
	 * microseconds per byte but this may change.
	 * 
	 * We need to do something here for the case that we didn't
	 * get any data points at all for one or more packet sizes.
	 */
	unsigned long testslope, testintercept;
	unsigned long estimator;
	unsigned long minestimator;
	bool estimatorvalid;

	minestimator = 0;
	estimatorvalid = false;
	testslope = 0;
	testintercept = 0;
	
	for (i = 0; i < columns; i++) {
	    for (j = i+1; j < columns; j++) {
		
		if ((partialmins[i] != timeoutresult) &&
		    (partialmins[j] != timeoutresult)) {
		    
		    /* Compute test slope and estimator */
		    testslope = (((partialmins[j] - partialmins[i])) * 
				 slopescale) /
			(column2size(j - i));
		    testintercept = partialmins[j] -
			((partialmins[j] - partialmins[i]) * 
			 (column2size(j)) / 
			 (column2size(j - i)));
		    
		    /* Compute squares of residuals */
		    for (k = 0, l = 0; k < columns; k++) {
			if (partialmins[k] != timeoutresult) {
			    residuals[l] = partialmins[k] - 
				((testslope * 
				  column2size(k) /
				  slopescale) + 
				 testintercept);
			    residuals[l] *= residuals[l];
			    l++;
			}
		    }
		    
		    if (l > 0) {
			
			/* Estimator is median of squared residuals */
			estimator = median(residuals, l);
			
			if ((estimator < minestimator) || (!estimatorvalid)) {
			    minestimator = estimator;
			    currentslope = testslope;
			    currentintercept = testintercept;
			    estimatorvalid = true;
			}
		    }
		}
	    }
	}
    }

    /* 
     * Coeffecient of determination calculation...how good was
     * the fit?
     */
    r2int = 0;
    if ((currentslope != 0) || (currentintercept != 0)) {
	
	unsigned int medianr;	/* median of all absolute residuals */
	unsigned int mediany;	/* median of all Y values */
	unsigned int mady;	/* median absolute deviation */
	
	/*
	 * Make two passes over the data.  The first pass gather
	 * the absolute values of the residuals, as well as all
	 * of the dependent variable values.  The former goes to
	 * compute med|r|, while the latter gives med(y).
	 */
	l = 0;
	for (i = 0; i < columns; i++) {
	    if (partialmins[i] != timeoutresult) {
		residuals[l] = abs( static_cast<int>(partialmins[i] - ((currentslope * column2size(i) /slopescale) + currentintercept)));
		ys[l] = partialmins[i];
		
		l++;
	    }
	}
	medianr = median(residuals, l);
	mediany = median(ys, l);
	
	/*
	 * In the second pass over the data, we use the median Y
	 * value computed by the first pass to determine
	 * med|y sub i - med(y)|
	 */
	l = 0;
	for (i = 0; i < columns; i++) {
	    if (partialmins[i] != timeoutresult) {
		ys[l] = abs(static_cast<int>(partialmins[i] - mediany));
		l++;
	    }
	}
	mady = median(ys, l);
	
	/* r2 = 1.0 - pow((medianr / mady), 2); */
	r2int = (codscale * codscale) -
	    ((codscale * codscale * medianr * medianr) /
	     (mady * mady));
	
    }
    
    a = ((double) currentintercept) / 1000000.0;
    b = ((double) currentslope / 1000000.0 / (double) slopescale);
    r2 = ((double) r2int) / ((double) codscale * (double) codscale);
    delete [] partialmins;
    delete [] residuals;
    delete [] ys;

}

//
// ResultTable::median
//
// Input:
//
// Output: Median value
//
// Compute the median of an array of doubles.  
// As a side effect, the input array is sorted
// 
double ResultTable::median(double *values, unsigned int numValues)
{
    double medianValue;

    // Sort the using qsort(3).
    extern int doublecomp(const void *a, const void *b);
    qsort((void *) values, numValues, sizeof(double), doublecomp);

    // Find median value.
    if (numValues & 1) {
	// Odd number of samples
	medianValue = values[(numValues-1)/2];
    }
    else {
	// Even number of samples
	medianValue = (values[(numValues/2)] + values[(numValues/2)-1]) /
	    2.0;
    }
    return medianValue;
}

// Function for qsort(3) to determine the relative ordering of two
// doubles.  Used in the call to qsort above.
int doublecomp(const void *a, const void *b) 
{
    double adouble = *(const double *) a;
    double bdouble = *(const double *) b;
    if (adouble == bdouble) {
	return 0;
    }
    else {
	if (adouble < bdouble) {
	    return -1;
	}
	else {
	    return 1;
	}
    }
}


//
// ResultTable::median
//
// Input:
//
// Output: Median value
//
// Compute the median of an array of unsigned ints.
// As a side effect, the input array is sorted
// 
unsigned int ResultTable::median(unsigned int *values, unsigned int numValues)
{
    unsigned int medianValue;

    // Sort the using qsort(3).
    extern int uintcomp(const void *a, const void *b);
    qsort((void *) values, numValues, sizeof(unsigned int), uintcomp);

    // Find median value.
    if (numValues & 1) {
	// Odd number of samples
	medianValue = values[(numValues-1)/2];
    }
    else {
	// Even number of samples
	medianValue = (values[(numValues/2)] + values[(numValues/2)-1]) /
	    2;
    }
    return medianValue;
}

// Function for qsort(3) to determine the relative ordering of two
// doubles.  Used in the call to qsort above.
int uintcomp(const void *a, const void *b) 
{
    unsigned int auint = *(const unsigned int *) a;
    unsigned int buint = *(const unsigned int *) b;
    if (auint == buint) {
	return 0;
    }
    else {
	if (auint < buint) {
	    return -1;
	}
	else {
	    return 1;
	}
    }
}


//
// ResultTable::Print
//
// Input:  file pointer to print to, tag string, hop number
//
// Output:  Success code
//
// Print the contents of the table to the file pointer fp.
//
int ResultTable::Print(FILE *fp, char *tag, int hop)
{

    int i, j;

    for (i = 0; i < columns; i++) {
	for (j = 0; j < used[i]; j++) {

	    fprintf(fp, "%s %d %d %f\n", tag, hop, column2size(i), 
		    data[i][j]);

	}
    }
    return 0;
}



