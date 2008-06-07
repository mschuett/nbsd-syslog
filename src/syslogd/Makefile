# custom makefile for developement without external
# dependencies from /usr/src

CC=gcc
CFLAGS= -Wall -g -ggdb -DINET6 -DLIBWRAP -D_NO_NETBSD_USR_SRC_ -lwrap
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wno-sign-compare -Wno-traditional -Werror

syslogd: syslogd.c
	$(CC) $(CFLAGS) -o syslogd syslogd.c

test: syslogd
	sudo ./syslogd -d -p /var/run/logtest -f ./syslog.conf -t . -u mschuett
