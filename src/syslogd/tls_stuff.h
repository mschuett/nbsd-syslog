/*
 * tls_stuff.h
 * 
 */
#ifndef _TLS_STUFF_H
#define _TLS_STUFF_H

#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#define SERVICENAME "55555"
#define TLSBACKLOG 4
#define TLS_MAXERRORCOUNT 4

/* initial size for TLS inbuf, minimum prefix + linelength
 * guaranteed to be accepted */
#define TLS_MIN_LINELENGTH         (2048 + 5) 
/* usually the inbuf is enlarged as needed and then kept.
 * if bigger than TLS_PERSIST_LINELENGTH, then shrink
 * to TLS_LARGE_LINELENGTH immediately  */
#define TLS_LARGE_LINELENGTH      8192
#define TLS_PERSIST_LINELENGTH   32768
/* TODO: keep simple statistics with a moving average linelength? */ 


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
#define TLS_RETRY_EVENT_USEC 20000

/* reconnect to lost server after n sec */
#define TLS_RECONNECT_SEC 2

/* default algorithm for certificate fingerprints */
#define DEFAULT_FINGERPRINT_ALG "SHA1"

/* options for peer certificate verification */
#define X509VERIFY_ALWAYS 0
#define X509VERIFY_IFPRESENT 1
#define X509VERIFY_NONE 2

/* attributes for self-generated keys/certificates */
#define TLS_GENCERT_BITS  1024
#define TLS_GENCERT_SERIAL   1
#define TLS_GENCERT_DAYS   365

/* connection states, currently for outgoing connections only */
#define ST_NONE       0
#define ST_TCP_EST    1
#define ST_CLOSING    2
#define ST_CONNECTING 4
#define ST_EOF        8
#define ST_WRITING   16
#define ST_TLS_EST   32

#define ST_CHANGE(x, y) do { DPRINTF(D_TLS, "Change state %p to %d\n", &(x), (y)); \
                             (x) = (y); } while (0)

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
        unsigned int x509verify:2,      /* kind of validation needed */
                     incoming:1;        /* set if we are server */
        unsigned int state;             /* outgoing connection state */
           
        SSL  *sslptr;        /* active SSL object             */
        struct event *event; /* event for read/write activity */
        struct event *retryevent;  /* event for retries       */
        bool  retrying;      /* keeps state which event is active */
        char *hostname;      /* hostname or IP we connect to */
        char *port;          /* service name or port number  */
        char *subject;       /* configured hostname in cert  */
        char *fingerprint;   /* fingerprint of peer cert     */
        char *certfile;      /* copy of peer cert */
        unsigned int reconnect;   /* seconds between reconnects */
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
#define TLS_OK          0        /* no real problem, just ignore */
#define TLS_RETRY_READ  1        /* just retry, non-blocking operation not finished yet */
#define TLS_RETRY_WRITE 2        /* just retry, non-blocking operation not finished yet */
#define TLS_TEMP_ERROR  4        /* recoverable error condition, but try again */
#define TLS_PERM_ERROR  8        /* non-recoverable error condition, closed TLS and socket */

SSL_CTX *init_global_TLS_CTX(const char *, const char *, const char *, const char *, const char *);
int check_peer_cert(int, X509_STORE_CTX *);
bool read_certfile(X509 **, const char *);
bool write_x509files(EVP_PKEY *, X509 *, const char *, const char *);
bool mk_x509_cert(X509 **, EVP_PKEY **, int, int, int);

bool get_fingerprint(const X509 *, char **, const char *);
bool get_commonname(X509 *, char **);
bool match_hostnames(X509 *, const char *, const char *);
bool match_fingerprint(const X509 *, const char *);
bool match_certfile(const X509 *, const char *);

bool copy_string(char **, const char *, const char *);
bool copy_config_value_quoted(const char *, char **, char **);
bool copy_config_value(const char *, char **, char **, const char *, const int);
bool copy_config_value_word(char **, char **);
bool parse_tls_destination(char *, struct filed *);
struct socketEvent *socksetup_tls(const int, const char *, const char *);

void tls_split_messages(struct TLS_Incoming_Conn *);

void dispatch_accept_socket(int, short, void *);
void dispatch_accept_tls(int, short, void *);
void dispatch_read_tls(int, short, void *);
void dispatch_eof_tls(int, short, void *);
bool tls_connect(SSL_CTX *, struct tls_conn_settings *);
void dispatch_SSL_connect(int, short, void *);
void tls_reconnect(int, short, void *);
bool tls_send(struct filed *, struct buf_msg *);
void dispatch_tls_send(int, short, void *);

void dispatch_SSL_shutdown(int, short, void *);
void free_tls_sslptr(struct tls_conn_settings *);
void free_tls_conn(struct tls_conn_settings *);
int tls_examine_error(const char *, const SSL *, struct tls_conn_settings *, const int);

int accept_cert(const char* , struct tls_conn_settings *, char *, char *);
int deny_cert(struct tls_conn_settings *, char *, char *);

#endif /* !_TLS_STUFF_H */
