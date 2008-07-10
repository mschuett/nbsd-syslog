# Makefile for syslogd
# to build outside NetBSD's /usr/src

CFLAGS+= -std=c99 -g
CFLAGS+= -DINET6 -DLIBWRAP -DSUPPORT_UTMPX -DSUPPORT_UTMP
CFLAGS+= -Wall -Werror

LIBS= -lwrap -lutil -lssl -lcrypto -levent

all: syslogd

syslogd: syslogd.o tls_stuff.o dehumanize_number.o strndup.o
  $(CC) $(LIBS) -o syslogd syslogd.o tls_stuff.o dehumanize_number.o strndup.o

clean:
  rm -f ./syslogd ./*.o
