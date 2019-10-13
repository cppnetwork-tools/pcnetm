# pcnetm
```
pcnetm stands for path characteristics network measurement.
pcnetm is a rework of old pchar-1.5 to redesign and convert to modern C++.
```
[![C++](https://img.shields.io/badge/C%2B%2B-11-yellowgreen)](https://www.cppreference.com/) 
[![License](https://img.shields.io/badge/license-GPL3-_red.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)
### Obtaining old pchar

```
At present, the latest version of pchar is the 1.5 version released in 2005, which has not been updated for more than ten years. The software can be obtained by the following command:

wget http://www.kitchenlab.org/www/bmah/Software/pcnetm/pcnetm-1.5.tar.gz
```

### Description

       pcnetm  measures  the  characteristics  of  the network path between two Internet hosts, on
       either IPv4 or IPv6 networks.  It is  an  independently-written  reimplementation  of  the
       pathchar  utility, using similar algorithms.  Both programs measure network throughput and
       round-trip time by sending varying-sized UDP packets into the network and waiting for ICMP
       messages in response.  Like traceroute, they modulate the IPv4 time-to-live (TTL) field or
       the IPv6 hop limit field to get measurements at different distances along a path.

       In its default mode, a run of pcnetm over a short path might produce an output  that  looks
       like this:
       pcnetm to dancer.ca.sandia.gov (146.246.246.1) using UDP/IPv4
       Packet size increments by 32 to 1500
       46 test(s) per repetition
       32 repetition(s) per hop
        0:
           Partial loss:      0 / 1472 (0%)
           Partial char:      rtt = 0.657235 ms, (b = 0.000358 ms/B), r2 = 0.989713
                              stddev rtt = 0.004140, stddev b = 0.000006
           Hop char:          rtt = 0.657235 ms, bw = 22333.268771 Kbps
           Partial queueing:  avg = 0.000150 ms (418 bytes)
        1: 146.246.243.254 (con243.ca.sandia.gov)
           Partial loss:      0 / 1472 (0%)
           Partial char:      rtt = 0.811278 ms, (b = 0.000454 ms/B), r2 = 0.995401
                              stddev rtt = 0.003499, stddev b = 0.000005
           Hop char:          rtt = 0.154043 ms, bw = 83454.764777 Kbps
           Partial queueing:  avg = 0.000153 ms (336 bytes)
        2: 146.246.250.251 (slcon1.ca.sandia.gov)
           Partial loss:      0 / 1472 (0%)
           Partial char:      rtt = 1.044412 ms, (b = 0.002161 ms/B), r2 = 0.999658
                              stddev rtt = 0.004533, stddev b = 0.000006
           Hop char:          rtt = 0.233133 ms, bw = 4686.320952 Kbps
           Partial queueing:  avg = 0.000100 ms (46 bytes)
        3: 146.246.246.1 (dancer.ca.sandia.gov)
           Path length:       3 hops
           Path char:         rtt = 1.044412 ms, r2 = 0.999658
           Path bottleneck:   4686.320952 Kbps
           Path pipe:         611 bytes
           Path queueing:     average = 0.000100 ms (46 bytes)

       The  path  here  passes  through  three  hops.  Each hop consists of four lines of output:
       Partial loss documents the number and percentage of probe packets that  were  lost  during
       the  probes  for that hop.  The partial char line shows the estimated round-trip time from
       the probing host through the current hop.  The hop char line shows estimates of the round-
       trip  time  and  bandwidth  for  the  current hop.  Finally, the partial queueing shows an
       estimate of the average queueing along the path, up to and including the current hop.

       Between each hop, pcnetm prints the IP address and (if known) name of  the  host/router  at
       the end of the link.

       After  the last hop (usually the target host), pcnetm prints statistics on the entire path,
       including the path length and path pipe (the latter is an estimate of the  delay-bandwidth
       product of the path).

       pcnetm  has another mode of operation, called trout (short for “tiny traceroute”).  In this
       mode, packets of random sizes (one packet per hop diameter) are sent along the path  to  a
       destination.   No  attempt  at  estimating  link properties is made; however, this mode is
       extremely fast.  It is intended for use as a part of a larger measurement  infrastructure.
       The output from this mode might look like:
       trout to bmah-freebsd-1.cisco.com (171.70.84.44) using ICMP/IPv4 (raw sockets)
       Packet size increments from 28 to 1500 by 32
        0: 171.70.84.42 (bmah-freebsd-0.cisco.com)
        1: 171.70.84.44 (bmah-freebsd-1.cisco.com) 352 -> 352 bytes: 0.318 ms

### Usage

```
       -a analysis
              Set  analysis  type.   Current  choices are lsq (the default), which uses a minimum
              filter followed by a least sum-of-squares fit to estimate link bandwidths, kendall,
              which uses the same minimum filter followed by a linear fit based on Kendall's test
              statistic, lms, which does a minimum filter followed by a least median  of  squares
              fit,  and  lmsint,  which  is  an implementation of the lms computations using only
              integer arithmetic.

       -b burst
              Set the size of packet bursts.  A burst parameter > 1 will result in some number of
              ICMP_ECHOREPLY  packets  sent  before  the  probe packet to induce queueing.  These
              packets are useful for  measuring  store-and-forward  switched  subnets,  but  make
              measurements of fast links behind bottlenecks inaccurate.

       -c     Ignore  routing  changes  detected during running.  Normally, pcnetm will exit if it
              receives responses from more than one host for a  given  hop,  assuming  that  this
              condition  is  caused  by  a  routing  transient.   However, certain load-balancing
              schemes can also cause this condition.  In such situations, using the -c option may
              be useful.

       -C     Use pcap(3) packet capture library (this must have been enabled at configure time).
              Note that this option must be specified to enable TCP-based probes.

       -d debug
              Sets debugging output level.  Generally not useful except to the developer.

       -g gap Set the mean inter-probe gap in seconds.  The default is  0.25,  which  results  in
              approximately  four  probes  per  second  being  run.   Care should be taken not to
              decrease this gap by too much, in order to avoid flooding the network.  The default
              value  here  is  deliberately  conservative; users with the need or desire to probe
              more quickly are presumed to have  at  least  perused  the  documentation  for  the
              relevant command-line options.

       -G gaptype
              Set  distribution  used  to  select interprobe gap times.  Current alternatives are
              fixed  (the  default)  and  exp,  which  picks  gap  times  from   an   exponential
              distribution.   The  latter  option  is an attempt to simulate a Poisson process of
              probe packets (a lot of aliteration), however due  to  the  fact  that  each  probe
              experiment takes a non-zero amount of time, this is only an approximation.

       -H hops
              Set the maximum number of hops that pcnetm will probe into the network.  The default
              maximum is 30 hops, the same as with pathchar and traceroute.

       -h     Print usage information.

       -i interface
              Set the interface to listen on for the -C option.

       -I increment
              Set the probe packet size increment.  pcnetm will send IP packets  with  sizes  that
              are  integer  multiples of increment, up to the maximum specified by the -m option.
              The default is a 32-byte increment.  Small increments should produce more  accurate
              results, but will result in more probes (thus taking longer to run).

       -l origin
              Set the local source of probe packets.  This option is mostly useful on multi-homed
              hosts.  If not specified, it defaults to the value of hostname(3).  Note that  this
              option  must  be  used  if the local hostname cannot be resolved to an IPv4 or IPv6
              address.

       -m mtu Set the maximum probe packet size.  This value should be no larger  than  the  path
              MTU between the two hosts.  The default is 1500 bytes, the Ethernet MTU.

       -M mode
              Set  operational  mode.   The  normal  operational mode is pcnetm, which uses active
              probes to characterize the bandwidth, latency, loss,  and  queueing  of  the  links
              comprising  a path.  Another mode is trout, a “tiny traceroute” that is intended to
              be used as a portion of a larger network management infrastructure.

       -n     Don't attempt to resolve host addresses to names.

       -p protocol
              Select protocol to use.  Current options are: ipv4udp (UDP over IPv4), ipv4raw (UDP
              over  IPv4, using raw IP packets), ipv4icmp (ICMP over IPv4, using raw IP packets),
              ipv4tcp (TCP over IPv4, using raw IP packets), ipv6icmp (ICMPv6  over  IPv6,  using
              raw  IP  packets),  and  ipv6udp  (UDP  over IPv6).  The default protocol is either
              ipv4udp or ipv6udp, as appropriate to the network-layer address associated with the
              hostname  provided.   Compared  with  ipv4udp, the implementation of ipv4raw offers
              finer control over the contents of packet fields, but is otherwise identical.  Note
              that  the  ipv6icmp  and  ipv6udp  options  are  only available if IPv6 support was
              compiled into pcnetm, which can be selected at configure time.  Finally, the ipv4tcp
              option  requires  that  pcap(3)  support be specified at configure time and enabled
              with the -C option.

       -P port
              Select starting UDP port number (the default is  32768).   pcnetm  uses  consecutive
              port  numbers  starting  from this value, counting up.  Care should be taken not to
              use port numbers that are actually in use by network services.

       -q     Quiet mode, suppressing all output.  Useful if writing statistics to  standard  out
              (see the -w option).

       -r file
              Read  measurements  in  from  a file named file, as written by the -w option.  This
              option is useful for experimenting with different analysis algorithms over a  fixed
              data set.

       -R reps
              Set the number of repetitions of each probe packet size to be sent.  The default is
              32 packets of each size.  Smaller values  speed  up  testing,  at  the  expense  of
              accuracy.

       -s hop Set  the  starting  hop  at  which  to begin probing.  The default is 1, so network
              probing will begin at the host adjacent to the  host  where  pcnetm  is  being  run.
              Larger values allow probing to begin farther out from the testing host; this can be
              helpful when attempting to probe outside a local internetwork whose  characterisics
              are well-known.

       -S     Do  SNMP  queries at each hop to determine each router's idea of what it thinks its
              next-hop interface characteristics are.  Use of this features requires the UCD SNMP
              library, as well as enabling at configure-time using --with-snmp.

       -t timeout
              Set  the amount of time (in seconds) that pcnetm will wait for an ICMP error message
              before declaring a packet loss.  The default is 3 seconds.

       -T tos Set the IP Type Of Service bits  for  outgoing  UDP  packets.   This  option  isn't
              terribly  useful  for  a lot of people, but it can be used, for example, to force a
              particular DiffServ codepoint within networks that support this functionality.  For
              values  of  -p  that  use  IPv6  as  a network-layer protocol, this option sets the
              traffic class field in the IPv6 header according to RFC 2460.

       -v     Verbose mode.  While each probe is in progress, print a synopsis of the hop number,
              repetition, and probe packet size on standard out.  Verbose mode mimicks the output
              of pathchar.

       -V     Print version and copyright information and exit.

       -w file
              Write statistics to a datafile named file.  This  file  can  be  read  back  in  by
              specifying  the  -r  option  in a subsequent run of pcnetm for off-line analysis, or
              parsed by other programs for plotting, etc.

              If file is given as  - , then the statistics are written to standard out.  In  this
              case,  the  quiet  flag  -q  may be useful, to avoid cluttering the standard output
              stream.
```

### SEE ALSO

```
   pcap(3), ping(8), traceroute(8), pathchar(8)
```

### Notes

```
       Because pcnetm relies on measurements to drive its estimates of network characteristics, it
       may  occasionally  produce  some  seemingly  odd  results.   Care  should  be  taken  when
       interpreting the output of pcnetm.  For example, the coeffecients of determination for  the
       least squares fit can be useful in seeing how “good” of a fit the bandwidth and round-trip
       time parameters describe the performance seen by the probe packets.   The  coefficient  of
       determination  takes  values  from 0 to 1, where a value of 1 indicates that the estimated
       parameters perfectly fit the data.

       pcnetm was originally named pc, which was either an abbreviation for “path characteristics”
       or “pathchar clone”.
```

### Bugs

```
       Pathchar  automatically  determines  an appropriate maximum packet size to use, based on a
       Path MTU discovery algorithm.  pcnetm relies on the user specifying the maximum packet size
       manually.

       Some  versions  of  Solaris  rate-limit the generation of ICMP error messages.  Any run of
       pcnetm through, or to, a Solaris machine may show abnormally high packet loss rates.   This
       feature  of  Solaris affects traceroute and pathchar as well, but not ping.  Some versions
       of Linux appear to have similar rate-limiting.  In situations such as  this,  the  use  of
       ICMP-based  probes  (selected  by  the -p option) may yield more satisfactory (or at least
       faster) results.

       Timestamps printed after each run are printed relative to the local time zone.  Timestamps
       saved in trace files are expressed as seconds past the epoch.

       There are way too many command-line options
```

### Author

```
       Bruce  A. Mah <bmah@acm.org>.  The author of the original pathchar utility is Van Jacobson
       <van@ee.lbl.gov>.  The algorithms used by pcnetm were coded from Van Jacobson's  viewgraphs
       describing the operation of pathchar.
```

### To Obtain and Build

```
git clone https://github.com/cppnetwork-tools/pcnetm

% ./configure
% make

To enable IPv6 support, give the --with-ipv6 option to configure.  If
there is a directory for IPv6-specific libraries, it can be specified
via an argument to the --with-ipv6 option, for example:

% ./configure --with-ipv6=/usr/local/v6
% make
```

### Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

### License
[GPL-3.0](https://choosealicense.com/licenses/gpl-3.0/) 