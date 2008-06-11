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

/* incoming sockets are non-blocking and every action may take up to
 * TLS_SLEEP_TRIES * TLS_SLEEP_USEC usec before it finishes or gives up.
 * I found that an SSL_accept() often needs that time for the handshake.
 * 
 * Is this reasonable or too long for a busy logserver?
 * 
 * The waiting time has to be long enough to check all valid certificates,
 * but short enough to prevent a DoS from an attacker sending very large
 * certificates to disturb our event loop.
 * If we have to wait for several milliseconds then we might try to 
 * save the SSL* and use a kevent timer to continue the SSL_accept()
 * later. 
 */
#define TLS_SLEEP_USEC  5000
#define TLS_SLEEP_TRIES 5

#define TLS_RECONNECT_SEC 10

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

#endif /* !_TLS_STUFF_H */
