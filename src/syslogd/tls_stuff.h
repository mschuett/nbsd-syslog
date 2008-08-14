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

/* timeout to call non-blocking TLS operations again */
#define TLS_RETRY_EVENT_USEC 20000

/* reconnect to lost server after n sec (initial value) */
#define TLS_RECONNECT_SEC 10
/* backoff connection attempts */
#define TLS_RECONNECT_BACKOFF_FACTOR 15/10
#define TLS_RECONNECT_BACKOFF(x)     (x) = (x) * TLS_RECONNECT_BACKOFF_FACTOR
/* abandon connection attempts after n sec
 * This has to be <= 5h (with 10sec initial interval),
 * otherwise a daily SIGHUP from newsylog will reset
 * all timers and the giveup time will never be reached
 * 
 * set here: 2h, reached after ca. 7h of reconnecting 
 */
#define TLS_RECONNECT_GIVEUP         60*60*2

/* default algorithm for certificate fingerprints */
#define DEFAULT_FINGERPRINT_ALG "SHA1"

/* default X.509 files */
#define DEFAULT_X509_CERTFILE "/etc/openssl/default.crt"
#define DEFAULT_X509_KEYFILE "/etc/openssl/default.key"

/* options for peer certificate verification */
#define X509VERIFY_ALWAYS 0
#define X509VERIFY_IFPRESENT 1
#define X509VERIFY_NONE 2

/* attributes for self-generated keys/certificates */
#define TLS_GENCERT_BITS  1024
#define TLS_GENCERT_SERIAL   1
#define TLS_GENCERT_DAYS   365

/* TLS connection states */
#define ST_NONE       0
#define ST_TLS_EST    1
#define ST_TCP_EST    2
#define ST_CONNECTING 3
#define ST_ACCEPTING  4  
#define ST_READING    5
#define ST_WRITING    6
#define ST_EOF        7
#define ST_CLOSING0   8
#define ST_CLOSING1   9
#define ST_CLOSING2  10

/*
 * holds TLS related settings for one connection to be
 * included in the SSL object and available in callbacks
 * 
 * It serves two different purposes:
 * - for outgoing connections it contains the values from syslog.conf and
 *   the server's cert is checked against these values by check_peer_cert()
 * - for incoming connections it is not used for checking, instead
 *   dispatch_tls_accept() fills in the connected hostname/port and
 *   check_peer_cert() fills in the actual values as read from the peer cert
 * 
 */
struct tls_conn_settings {
        unsigned      accepted:1,   /* workaround cf. check_peer_cert*/
                      x509verify:2, /* kind of validation needed     */
                      incoming:1,   /* set if we are server          */
                      state:4;      /* outgoing connection state     */
        struct event *event;        /* event for read/write activity */
        struct event *retryevent;   /* event for retries             */
        SSL          *sslptr;       /* active SSL object             */
        char         *hostname;     /* hostname or IP we connect to  */
        char         *port;         /* service name or port number   */
        char         *subject;      /* configured hostname in cert   */
        char         *fingerprint;  /* fingerprint of peer cert      */
        char         *certfile;     /* copy of peer cert             */
        unsigned      reconnect;    /* seconds between reconnects    */
        char          errorcount;   /* to close conn. after errors   */
};

/* argument struct only used for tls_send() */
struct tls_send_msg {
        struct filed   *f;
        struct buf_msg *buffer;
        struct buf_queue *qentry;
        char           *line;      /* formatted message */
        size_t          linelen;
        unsigned        offset;    /* in case of partial writes */
};

/* return values for TLS_examine_error() */
#define TLS_OK          0        /* no real problem, just ignore */
#define TLS_RETRY_READ  1        /* just retry, non-blocking operation not finished yet */
#define TLS_RETRY_WRITE 2        /* just retry, non-blocking operation not finished yet */
#define TLS_TEMP_ERROR  4        /* recoverable error condition, but try again */
#define TLS_PERM_ERROR  8        /* non-recoverable error condition, closed TLS and socket */

/* global TLS setup and utility */
char *init_global_TLS_CTX(void);
struct socketEvent *socksetup_tls(const int, const char *, const char *);
int check_peer_cert(int, X509_STORE_CTX *);
int accept_cert(const char* , struct tls_conn_settings *, char *, char *);
int deny_cert(struct tls_conn_settings *, char *, char *);
bool read_certfile(X509 **, const char *);
bool write_x509files(EVP_PKEY *, X509 *, const char *, const char *);
bool mk_x509_cert(X509 **, EVP_PKEY **, int, int, int);
bool x509_cert_add_subjectAltName(X509 *, X509V3_CTX *);
int tls_examine_error(const char *, const SSL *, struct tls_conn_settings *, const int);

bool get_fingerprint(const X509 *, char **, const char *);
bool get_commonname(X509 *, char **);
bool match_hostnames(X509 *, const char *, const char *);
bool match_fingerprint(const X509 *, const char *);
bool match_certfile(const X509 *, const char *);

/* configuration & parsing */
bool parse_tls_destination(char *, struct filed *, const unsigned);
/* event callbacks */
void dispatch_socket_accept(int, short, void *);
void dispatch_tls_accept(int, short, void *);
void dispatch_tls_read(int, short, void *);
void dispatch_tls_send(int, short, void *);
void dispatch_tls_eof(int, short, void *);
void dispatch_SSL_connect(int, short, void *);
void dispatch_SSL_shutdown(int, short, void *);
void dispatch_force_tls_reconnect(int, short, void *);

bool tls_connect(struct tls_conn_settings *);
void tls_reconnect(int, short, void *);
bool tls_send(struct filed *, char *, size_t, struct buf_queue*);
void tls_split_messages(struct TLS_Incoming_Conn *);

void free_tls_conn(struct tls_conn_settings *);
void free_tls_sslptr(struct tls_conn_settings *);
void free_tls_send_msg(struct tls_send_msg *);

#endif /* !_TLS_STUFF_H */
