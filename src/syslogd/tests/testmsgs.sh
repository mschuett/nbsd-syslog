#! /bin/sh
echo -n '<35>Jul  6 12:39:08 host.some.domain.de mschuett[123]: hallo1' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 host.some.domain.de mschuett: hallo2' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 host mschuett[123]: hallo3' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 host mschuett: hallo4' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 127.0.0.1 mschuett[123]: hallo5' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 127.0.0.1 mschuett: hallo6' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 mschuett[123]: hallo7' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 mschuett: hallo8' | socat stdin unix-sendto:/var/run/log
echo -n '<35>Jul  6 12:39:08 2000::ff postfix/smtpd: hallo9' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host.some.domain.de mschuett 123 - hallo10' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host.some.domain.de mschuett - - hallo11' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host.some.domain.de mschuett 123 - hallo12' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host.some.domain.de mschuett - - hallo13' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host.some.domain.de - - - hallo14' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host.some.domain.de - - - hallo15' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host mschuett 123 - hallo16' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host mschuett - - hallo17' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host mschuett 123 - hallo18' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host mschuett - - hallo19' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host - - - hallo20' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 host - - - hallo21' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 127.0.0.1 mschuett 123 - hallo22' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 127.0.0.1 mschuett - - hallo23' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 127.0.0.1 mschuett 123 - hallo24' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 127.0.0.1 mschuett - - hallo25' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 127.0.0.1 - - - hallo26' | socat stdin unix-sendto:/var/run/log
echo -n '<35>1 2008-07-06T14:25:09.510867+02:00 127.0.0.1 - - - hallo27' | socat stdin unix-sendto:/var/run/log

