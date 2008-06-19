# custom makefile for developement without external
# dependencies from /usr/src

CC=gcc
CFLAGS= -std=c99 -Wall -g -ggdb -D_NO_NETBSD_USR_SRC_ -lssl -levent
CFLAGS+= -DINET6 -DLIBWRAP -lwrap 
# only on my machine, NetBSD 4.0 has current OpenSSL libraries in base
CFLAGS+= -I/usr/local/include -L/usr/local/lib 
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith -Wno-sign-compare -Wno-traditional -Werror

all: syslogd

syslogd: syslogd.c tls_stuff.c tls_stuff.h
	$(CC) $(CFLAGS) -o syslogd syslogd.c tls_stuff.c

test: syslogd
	sudo ./syslogd -d -p /var/run/logtest -f ./syslog.conf -t / -u mschuett

clean: syslogd
	rm ./syslogd
