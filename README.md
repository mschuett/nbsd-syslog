# NetBSD Syslog with IETF syslog protocols

This is the codebase of the _Google Summer of Code 2008_ project to implement
the IETF syslog protocols for [NetBSD](http://netbsd.org/).

The project finished successfully; it was one of the first implementations
of syslog-protocol and still seems to be the only implementation of syslog-sign.

Its codebase was imported into NetBSD-Current, where it is maintained and which
should be regarded as the "primary source".
This repository is only a second copy, already out of sync.
It is intended to simplify access to the codebase and to make
further development easier than is possible with NetBSD's CVS.

#Links

* [IETF Syslog Working Group](http://tools.ietf.org/wg/syslog/)
  * [RFC 5424, The Syslog Protocol](http://tools.ietf.org/html/rfc5424)
  * [RFC 5425, Transport Layer Security (TLS) Transport Mapping for Syslog](http://tools.ietf.org/html/rfc5425)
  * [RFC 5426, Transmission of Syslog Messages over UDP](http://tools.ietf.org/html/rfc5426)
  * [RFC 5848, Signed Syslog Messages](http://tools.ietf.org/html/rfc5848)
* [old GSoC project status page](http://netbsd-soc.sourceforge.net/projects/syslogd/)
* [Presentation at EuroBSDCon08](http://mschuette.name/files/uni/081018-eurobsdcon-syslogd-anim.pdf)
* [Technical Report](https://mschuette.name/files/uni/090817-GSoC-syslogd_in_NetBSD.pdf)

