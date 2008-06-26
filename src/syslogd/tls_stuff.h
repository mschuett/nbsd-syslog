/*
 * tls_stuff.h
 * 
 */
#ifndef _TLS_STUFF_H
#define _TLS_STUFF_H

#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define SERVICENAME "55555"
#define TLSBACKLOG 4
#define TLS_MAXERRORCOUNT 4

/* copied from FreeBSD -- makes some loops shorter */
#ifndef SLIST_FOREACH_SAFE

#define SLIST_FOREACH_SAFE(var, head, field, tvar)          \
    for ((var) = SLIST_FIRST((head));               \
        (var) && ((tvar) = SLIST_NEXT((var), field), 1);        \
        (var) = (tvar))
        
#endif /* !SLIST_FOREACH_SAFE */

/* 
 * incoming sockets and TLS functions on them are non-blocking,
 * so the immediate retry inside the dispatch routines may take
 * up to TLS_NONBLOCKING_TRIES * TLS_NONBLOCKING_USEC usec.
 *
 * After that the function schedules a kevent to call itself
 * TLS_RETRY_KEVENT_MSEC msec later.
 *
 * This approach prevents DoS attacks on the event-loop
 * (eg. by sending large certificate chains).
 * 
 * I found that the necessary time for SSL_accept(), ie. for the
 * TLS handshake, varies considerably depending on system load.
 * I also have no idea which values are optimal or whether setting up
 * the timer-kevent is more expensive than sleeping for some time.
 */
#define TLS_NONBLOCKING_USEC  750
#define TLS_NONBLOCKING_TRIES 2
#define TLS_RETRY_KEVENT_USEC 20000

/* reconnect to lost server after n sec */
#define TLS_RECONNECT_SEC 10

/* options for peer certificate verification */
#define X509VERIFY_ALWAYS 0
#define X509VERIFY_IFPRESENT 1
#define X509VERIFY_NONE 2

/*
 * holds TLS related settings for one connection to be
 * included in the SSL object and available in callbacks
 * 
 * It serves two different purposes:
 * - for outgoing connections it contains the values from syslog.conf and
 *   the server's cert is checked against these values by check_peer_cert()
 * - for incoming connections it is not used for checking, instead
 *   dispatch_accept_tls() fills in the connected hostname/port and
 *   check_peer_cert() fills in the actual values as read from the peer cert
 * 
 */
struct tls_conn_settings {
        /* short int verify_depth;      currently not checked. necessary? */
        unsigned int x509verify:2,              /* kind of validation needed */
                     incoming:1;                /* set if we are server */
           
        SSL  *sslptr;        /* active SSL object            */
        struct event *event; /* event for socket activity    */
        struct event *event2;/* event for scheduling. TODO: find a way to remove this  */
        char *hostname;      /* hostname or IP we connect to */
        char *port;          /* service name or port number  */
        char *subject;       /* configured hostname in cert  */
        char *fingerprint;   /* fingerprint of peer cert     */
        char *certfile;      /* copy of peer cert */
        char errorcount;     /* to be able to close a connection after sveral errors */
        struct tls_global_options_t *tls_opt;   /* global tls options. 
                                only set for incoming connections
                                to be used for certificate authentication */
};
/*
 * may be a TODO:
 * collect status information for possible SNMP MIB support
 *
struct daemon_status {

};
 */

/* return values for TLS_examine_error() */
#define TLS_OK 0                /* no real problem, just ignore */
#define TLS_RETRY 1             /* just retry, non-blocking operation not finished yet */
#define TLS_TEMP_ERROR 2        /* recoverable error condition, but try again */
#define TLS_PERM_ERROR 3        /* non-recoverable error condition, closed TLS and socket */

SSL_CTX *init_global_TLS_CTX(const char *keyfilename, const char *certfilename, const char *CAfile, const char *CApath, const char *strx509verify);
int check_peer_cert(int preverify_ok, X509_STORE_CTX * store);
bool get_fingerprint(const X509 *cert, char **returnstring, const char *alg_name);
bool match_hostnames(X509 *cert, const struct tls_conn_settings *conn);
bool match_fingerprint(const X509 *cert, const struct tls_conn_settings *conn);

bool copy_string(char **mem, const char *p, const char *q);
bool copy_config_value_quoted(const char *keyword, char **mem, char **p, char **q);
bool copy_config_value(const char *, char **, char **, char **, const char *, const int);
bool copy_config_value_cont(char **, char **);
bool parse_tls_destination(char *p, struct filed *f);
struct socketEvent *socksetup_tls(const int af, const char *bindhostname, const char *port);

void tls_split_messages(struct TLS_Incoming_Conn *c);

void dispatch_accept_socket(int fd_lib, short event, void *ev);
void dispatch_accept_tls(int fd, short event, void *ev);
void dispatch_read_tls(int fd_lib, short event, void *ev);
void dispatch_eof_tls(int fd, short event, void *arg);
bool tls_connect(SSL_CTX *, struct filed *);
void tls_reconnect(int fd, short event, void *ev);
bool tls_send(struct filed *f, char *line, size_t len);

void free_tls_sslptr(struct tls_conn_settings *tls_conn);
void free_tls_conn(struct tls_conn_settings *tls_conn);
int tls_examine_error(const char *functionname, const SSL *ssl, struct tls_conn_settings *tls_conn, const int rc);

#endif /* !_TLS_STUFF_H */
