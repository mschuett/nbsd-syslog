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

all: syslogd syslogd.cat8 syslog.conf.cat5

syslogd: syslogd.o tls_stuff.o dehumanize_number.o strndup.o
	$(CC) $(LIBS) -o syslogd syslogd.o tls_stuff.o dehumanize_number.o strndup.o

syslogd.cat8: syslogd.8
	nroff -mandoc syslogd.8 > syslogd.cat8

syslog.conf.cat5: syslog.conf.5
	nroff -mandoc syslog.conf.5 > syslog.conf.cat5

syslogd.html: syslogd.8
	groff -mandoc -T html syslogd.8 > syslogd.8.html

syslog.conf.html: syslog.conf.5
	groff -mandoc -T html syslog.conf.5 > syslog.conf.5.html

clean:
	rm -f ./syslogd ./syslog.conf.cat5 ./syslogd.cat8 ./syslogd.8.html ./syslog.conf.5.html ./*.o 
