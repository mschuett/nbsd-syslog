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

#define MYKEY NULL
#define MYCERT  NULL
#define MYCA  NULL //"testca.crt"
#define MYCAPATH NULL
#define X509VERIFY X509VERIFY_NONE
#define SERVICENAME "5555"

/* options for peer certificate verification */
#define X509VERIFY_ALWAYS 0
#define X509VERIFY_IFPRESENT 1
#define X509VERIFY_NONE 2

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
};
/*
 * may be a TODO:
 * collect status information for possible SNMP MIB support
 *
struct daemon_status {

};
 */

SSL_CTX *init_global_TLS_CTX(char const *keyfilename, char const *certfilename, char const *CAfile, char const *CApath, char x509verify);
int check_peer_cert(int preverify_ok, X509_STORE_CTX * store);
bool tls_connect(SSL_CTX **context, struct tls_conn_settings *conn);
bool get_fingerprint(X509 * cert, char **returnstring, char *alg_name);
bool match_hostnames(X509 * cert, struct tls_conn_settings *conn);
bool match_fingerprint(X509 * cert, struct tls_conn_settings *conn);

#endif /* !_TLS_STUFF_H */
