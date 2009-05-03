# Makefile for syslogd
# to build outside NetBSD's /usr/src

CFLAGS+= -std=c99 -g
CFLAGS+= -DINET6 -DLIBWRAP -DSUPPORT_UTMPX -DSUPPORT_UTMP
CFLAGS+= -Wall -Werror

LIBS= -lwrap -lutil -lssl -lcrypto -levent

.if .FreeBSD
# for libevent
CFLAGS+= -I/usr/local/include
LIBS+= -L/usr/local/lib
.endif

all: syslogd syslogd.cat8 syslog.conf.cat5 tests

syslogd: syslogd.o tls.o dehumanize_number.o strndup.o sign.o bpg.o
	$(CC) $(LIBS) -o syslogd syslogd.o tls.o dehumanize_number.o strndup.o sign.o bpg.o

syslogd.cat8: syslogd.8
	nroff -mandoc syslogd.8 > syslogd.cat8

syslog.conf.cat5: syslog.conf.5
	nroff -mandoc syslog.conf.5 > syslog.conf.cat5

syslogd.html: syslogd.8
	groff -mandoc -T html syslogd.8 > syslogd.8.html

syslog.conf.html: syslog.conf.5
	groff -mandoc -T html syslog.conf.5 > syslog.conf.5.html

tests: tests/pgpencode tests/evp_sign

tests/pgpencode: tests/pgpencode.o bpg.o
	$(CC) $(LIBS) -o tests/pgpencode tests/pgpencode.o bpg.o strndup.o 

tests/pgpencode.o: tests/pgpencode.c
	$(CC) $(CFLAGS) -c -o tests/pgpencode.o tests/pgpencode.c

tests/evp_sign: tests/evp_sign.o bpg.o
	$(CC) $(LIBS) -o tests/evp_sign tests/evp_sign.o bpg.o

tests/evp_sign.o: tests/evp_sign.c
	$(CC) $(CFLAGS) -c -o tests/evp_sign.o tests/evp_sign.c


clean:
	rm -f ./syslogd ./syslog.conf.cat5 ./syslogd.cat8 ./syslogd.8.html \
		./syslog.conf.5.html ./*.o tests/pgpencode tests/evp_sign
