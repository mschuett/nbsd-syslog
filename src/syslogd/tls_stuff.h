/*
 * tls_stuff.h
 * 
 */
#ifndef _TLS_STUFF_H
#define _TLS_STUFF_H

/* includes data from TLS/tls_stuff.h and TLS/common.h */
#include <stdbool.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MYKEY "localhost.key"
#define MYCERT  "localhost.crt"
#define MYCA  "testca.crt"
#define MYCAPATH NULL
#define X509VERIFY X509VERIFY_NONE
#define SERVICENAME "55555"
#define TLSBACKLOG 4
#define TLS_MAXERRORCOUNT 4

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
#define TLS_NONBLOCKING_USEC  200
#define TLS_NONBLOCKING_TRIES 2
#define TLS_RETRY_KEVENT_MSEC 200

/* reconnect to lost server after n sec */
#define TLS_RECONNECT_SEC 10

/* buffersize to process file length prefixes in TLS messages */
#define PREFIXLENGTH 10

/* options for peer certificate verification */
#define X509VERIFY_ALWAYS 0
#define X509VERIFY_IFPRESENT 1
#define X509VERIFY_NONE 2

/* one special problem:
 * kevent.udata has a different type an NetBSD and FreeBSD :-(
 */
#ifndef _NO_NETBSD_USR_SRC_
#define KEVENT_UDATA_CAST (intptr_t)
#else
#define KEVENT_UDATA_CAST (void*)
#endif /* !_NO_NETBSD_USR_SRC_ */

/*
 * holds TLS related settings for one connection to be
 * included in the SSL object and available in callbacks
 */
struct tls_conn_settings {
        /* short int verify_depth;      currently not checked. necessary? */
        unsigned int x509verify:6, force_fingerprint_check:1;   /* the kind of
                                                                 * certificate
                                                                 * validation needed */
        SSL  *sslptr;        /* active SSL object            */
        char *hostname;      /* hostname or IP we connect to */
        char *port;          /* service name or port number  */
        char *subject;       /* configured hostname in cert  */
        char *fingerprint;   /* fingerprint of peer cert     */
        char *certfile;      /* copy of peer cert -- not implemented */
        char errorcount;     /* to be able to close a connection after sveral errors */
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

SSL_CTX *init_global_TLS_CTX(char const *keyfilename, char const *certfilename, char const *CAfile, char const *CApath, char x509verify);
int check_peer_cert(int preverify_ok, X509_STORE_CTX * store);
bool tls_connect(SSL_CTX **context, struct tls_conn_settings *conn);
bool get_fingerprint(X509 * cert, char **returnstring, char *alg_name);
bool match_hostnames(X509 * cert, struct tls_conn_settings *conn);
bool match_fingerprint(X509 * cert, struct tls_conn_settings *conn);
int *socksetup_tls(int af, const char *bindhostname, const char *port);
void free_tls_sslptr(struct tls_conn_settings *tls_conn);
void free_tls_conn(struct tls_conn_settings *tls_conn);
int tls_examine_error(char *functionname, SSL *ssl, struct tls_conn_settings *tls_conn, int rc);

/* forward declarations */
bool copy_config_value(char **mem, char *p, char *q);
bool copy_config_value_quoted(char *keyword, char **mem, char **p, char **q);
bool parse_tls_destination(char *line, struct filed *f);
void tls_split_messages(struct TLS_Incoming_Conn *c);

void dispatch_accept_socket(struct kevent *ev);
void dispatch_accept_tls(struct kevent *ev);
void dispatch_read_tls(struct kevent *ev);
void tls_reconnect(struct kevent *ev);
void tls_send_queue(struct filed *f);
bool tls_send(struct filed *f, char *line, size_t len);

#endif /* !_TLS_STUFF_H */
