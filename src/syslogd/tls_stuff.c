/*
 * tls_stuff.c TLS related code for syslogd
 *
 * implements the TLS init and handshake callbacks with all required
 * checks from http://tools.ietf.org/html/draft-ietf-syslog-transport-tls-12
 * (without hostname wildcards)
 *
 * TODO: trans-port-tls12+ (Mail from jsalowey on 080523) requires
 *       server and client to be able to generate self-signed certificates
 * TODO: define fingerprints for incoming connections.
 *
 * Martin Schütte
 */

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/event.h>
#include <sys/time.h>
#include "syslogd.h"
#include "tls_stuff.h"

/* to output SSL error codes */
char *SSL_ERRCODE[9] = {
        "SSL_ERROR_NONE",
        "SSL_ERROR_SSL",
        "SSL_ERROR_WANT_READ",
        "SSL_ERROR_WANT_WRITE",
        "SSL_ERROR_WANT_X509_LOOKUP",
        "SSL_ERROR_SYSCALL",
        "SSL_ERROR_ZERO_RETURN",
        "SSL_ERROR_WANT_CONNECT",
        "SSL_ERROR_WANT_ACCEPT"};


/* definitions in syslogd.c */
extern short int Debug;
#define dprintf if (Debug) printf

extern SSL_CTX *global_TLS_CTX;
extern struct TLS_Incoming TLS_Incoming_Head;
extern char *linebuf;
extern size_t linebufsize;
extern int     RemoteAddDate; 

extern void    logerror(const char *, ...);
extern void    printline(char *, char *, int);
extern void    die(struct kevent *);
extern void    dispatch_accept_tls(struct kevent *ev);
extern struct kevent *allocevchange(void);

/*
 * init OpenSSL lib and one context. returns NULL on error, otherwise SSL_CTX
 * all pointer arguments may be NULL (at least for clients)
 * x509verify determines the level of certificate validation
 */
SSL_CTX *
init_global_TLS_CTX(char const *keyfilename, char const *certfilename, char const *CAfile, char const *CApath, char x509verify)
{
        SSL_CTX *ctx;
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_digests();
        if (!(ctx = SSL_CTX_new(SSLv23_method()))) {
                ERR_print_errors_fp(stderr);
                return NULL;
        }
        /* load keys and certs here */
        if (keyfilename && certfilename) {
                if (!(SSL_CTX_use_PrivateKey_file(ctx, keyfilename, SSL_FILETYPE_PEM)
                    && SSL_CTX_use_certificate_chain_file(ctx, certfilename))) {
                        dprintf("unable to get private key and certificate\n");
                        ERR_print_errors_fp(stderr);
                        exit(1);
                }
                if (!SSL_CTX_check_private_key(ctx)) {
                        dprintf("private key does not match certificate\n");
                        ERR_print_errors_fp(stderr);
                        exit(1);
                } else {
                        dprintf("loaded and checked own certificate\n");
                }
        }
        if (CAfile || CApath) {
                if (!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) {
                        dprintf("unable to load trust anchors\n");
                        ERR_print_errors_fp(stderr);
                } else {
                        dprintf("loaded trust anchors\n");
                }
        }
        /* peer verification */
        if ((x509verify == X509VERIFY_NONE) || (x509verify == X509VERIFY_IFPRESENT))
                /* ask for cert, but a client does not have to send one */
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, check_peer_cert);
        else
                /* default: ask for cert and check it */
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, check_peer_cert);

        (void)SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        (void)SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        return ctx;
}
/*
 * get fingerprint of cert
 * returnstring will be allocated and should be free()d by the caller
 * alg_name selects an algorithm, if it is NULL then SHA-1 will be used
 * return value and non-NULL *returnstring indicate success
 */
bool
get_fingerprint(X509 * cert, char **returnstring, char *alg_name)
{
#define MAX_ALG_NAME_LENGTH 8
        unsigned char md[EVP_MAX_MD_SIZE];
        char fp_val[4];
        unsigned int len, memsize;
        EVP_MD *digest;
        int i = 0;
        dprintf("get_fingerprint(cert, %p, %s)\n", returnstring, alg_name);
        *returnstring = NULL;
        if ((alg_name && !(digest = (EVP_MD *) EVP_get_digestbyname(alg_name)))
            || (!alg_name && !(digest = (EVP_MD *) EVP_get_digestbyname("SHA1")))) {
                dprintf("unknown digest algorithm %s\n", alg_name);
                
                return false;
        }
        if (!X509_digest(cert, digest, md, &len)) {
                dprintf("cannot get %s digest\n", alg_name);
                return false;
        }
        /* needed memory. 3 string bytes for every binary byte with delimiter
         * + alg_name with delimiter */
        memsize = (len * 3) + strlen(OBJ_nid2sn(EVP_MD_type(digest))) + 1;
        if (!(*returnstring = malloc(memsize))) {
                dprintf("cannot allocate %d bytes memory\n", memsize);
                return false;
        }
        /* 'normalise' the algorithm name */
        (void)strlcpy(*returnstring, OBJ_nid2sn(EVP_MD_type(digest)), memsize);
        (void)strlcat(*returnstring, ":", memsize);
        /* append the fingeprint data */
        for (i = 0; i < len; i++) {
                (void)snprintf(fp_val, 4, "%02X:", (unsigned int) md[i]);
                (void)strlcat(*returnstring, fp_val, memsize);
        }
        if ((*returnstring)[memsize - 1] != '\0')
                dprintf("memory overflow. last 4 chars are: %c%c%c%c\n",
                    (*returnstring)[memsize - 4], (*returnstring)[memsize - 3],
                    (*returnstring)[memsize - 2], (*returnstring)[memsize - 1]);
        return true;
}
/*
 * test if cert matches as configured hostname or IP
 * checks a 'really used' hostname and optionally a second expected subject
 * against iPAddresses, dnsNames and commonNames
 *
 * TODO: wildcard matching for dnsNames is not implemented.
 *       in transport-tls that is a MAY, and I do not trust them anyway.
 *       but there might be demand for, so it's a todo item.
 */
bool
match_hostnames(X509 * cert, struct tls_conn_settings *conn)
{
        int i, len, num;
        char *buf;
        unsigned char *ubuf;
        GENERAL_NAMES *gennames;
        GENERAL_NAME *gn;
        X509_NAME *x509name;
        X509_NAME_ENTRY *entry;
        ASN1_OCTET_STRING *asn1_ip, *asn1_cn_ip;
        int crit, idx;
        dprintf("match_hostnames() to check cert against %s and %s\n",
            conn->subject, conn->hostname);

        /* see if hostname is an IP */
        i = (asn1_ip = a2i_IPADDRESS(conn->subject)) || (asn1_ip = a2i_IPADDRESS(conn->hostname));

        if (!(gennames = X509_get_ext_d2i(cert, NID_subject_alt_name, &crit, &idx))) {
                dprintf("X509_get_ext_d2i() returned (%p,%d,%d) --> no subjectAltName\n", gennames, crit, idx);
        } else {
                num = sk_GENERAL_NAME_num(gennames);
                if (asn1_ip) {
                        /* first loop: check IPs */
                        for (i = 0; i < num; ++i) {
                                gn = sk_GENERAL_NAME_value(gennames, i);
                                if (gn->type == GEN_IPADD
                                    && !ASN1_OCTET_STRING_cmp(asn1_ip, gn->d.iPAddress))
                                        return true;
                        }
                }
                /* second loop: check DNS names */
                for (i = 0; i < num; ++i) {
                        gn = sk_GENERAL_NAME_value(gennames, i);
                        if (gn->type == GEN_DNS) {
                                buf = (char *)ASN1_STRING_data(gn->d.ia5);
                                len = ASN1_STRING_length(gn->d.ia5);
                                if (!strncasecmp(conn->subject, buf, len)
                                    || !strncasecmp(conn->hostname, buf, len))
                                        return true;
                        }
                }
        }

        /* check commonName; not sure if more than one CNs possible, but we
         * will look at all of them */
        x509name = X509_get_subject_name(cert);
        i = X509_NAME_get_index_by_NID(x509name, NID_commonName, -1);
        while (i != -1) {
                entry = X509_NAME_get_entry(x509name, i);
                len = ASN1_STRING_to_UTF8(&ubuf, X509_NAME_ENTRY_get_data(entry));
                if (len > 0) {
                        dprintf("found CN: %.*s\n", len, ubuf);
                        /* hostname */
                        if ((conn->subject && !strncasecmp(conn->subject, (char*)ubuf, len))
                            || (conn->hostname && !strncasecmp(conn->hostname, (char*)ubuf, len))) {
                                OPENSSL_free(ubuf);
                                return true;
                        }
                        OPENSSL_free(ubuf);
                        /* IP -- convert to ASN1_OCTET_STRING and compare then
                         * so that "10.1.2.3" and "10.01.02.03" are equal */
                        if ((asn1_ip)
                            && (asn1_cn_ip = a2i_IPADDRESS(conn->subject))
                            && !ASN1_OCTET_STRING_cmp(asn1_ip, asn1_cn_ip)) {
                                return true;
                        }
                }
                i = X509_NAME_get_index_by_NID(x509name, NID_commonName, i);
        }
        return false;
}
/*
 * check if certificate matches given fingerprint
 */
bool
match_fingerprint(X509 * cert, struct tls_conn_settings *conn)
{
#define MAX_ALG_NAME_LENGTH 8
        char alg[MAX_ALG_NAME_LENGTH];
        char *certfingerprint;
        char *p, *q;
        dprintf("match_fingerprint(%s)\n", conn->fingerprint);
        if (!conn->fingerprint)
                return false;

        /* get algorithm */
        p = alg;
        q = conn->fingerprint;
        while (*q != ':' && *q != '\0' && p < (char *)alg + MAX_ALG_NAME_LENGTH)
                *p++ = *q++;
        *p = '\0';

        if (!get_fingerprint(cert, &certfingerprint, alg)) {
                dprintf("cannot get %s digest\n", alg);
                return false;
        }
        if (strncmp(certfingerprint, conn->fingerprint, strlen(certfingerprint))) {
                dprintf("fail: fingerprints do not match\n");
                free(certfingerprint);
                return false;
        }
        dprintf("accepted: fingerprints match\n");
        free(certfingerprint);
        return true;
}
/*
 * Callback after OpenSSL has verified a peer certificate,
 * gets called for every certificate in a chain (starting with root CA).
 * preverify_ok indicates a valid trust path (necessary),
 * then we check wether the hostname or configured subject matches the cert.
 */
int
check_peer_cert(int preverify_ok, X509_STORE_CTX * ctx)
{
        char buf[256];
        char *fingerprint;
        SSL *ssl;
        X509 *cur_cert;
        int cur_err, cur_depth;
        bool rc;
        struct tls_conn_settings *conn_info;
        /* read context info */
        cur_cert = X509_STORE_CTX_get_current_cert(ctx);
        cur_err = X509_STORE_CTX_get_error(ctx);
        cur_depth = X509_STORE_CTX_get_error_depth(ctx);
        ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        conn_info = SSL_get_app_data(ssl);

        /* some info */
        X509_NAME_oneline(X509_get_subject_name(cur_cert), buf, sizeof(buf));
        get_fingerprint(cur_cert, &fingerprint, NULL);
        dprintf("check cert for connection with %s. depth is %d, preverify is %d, subject is %s, fingerprint is %s\n",
            conn_info->hostname, cur_depth, preverify_ok, buf, fingerprint);
        free(fingerprint);


        if (conn_info->x509verify == X509VERIFY_NONE)
                return 1;

        if ((conn_info->force_fingerprint_check) && (cur_depth == 0)) {
                rc = match_fingerprint(cur_cert, conn_info);
                dprintf("depth 0 arrived, match_fingerprint() returned %d\n", rc);
                return rc;
        }
        if (!preverify_ok) {
                if (cur_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
                        X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
                        dprintf("openssl verify error:missing cert for issuer= %s\n", buf);
                }
                dprintf("openssl verify error:num=%d:%s:depth=%d:%s\t\n", cur_err,
                    X509_verify_cert_error_string(cur_err), cur_depth, buf);

                if ((conn_info->fingerprint) && (cur_depth != 0)) {
                        dprintf("accepting otherwise invalid chain element, waiting for depth 0 to check fingerprint\n");
                        conn_info->force_fingerprint_check = true;
                        return 1;
                } else {
                        return 0;
                }
        }
        /* check hostname for last cert in chain */
        if ((cur_depth == 0) && (conn_info->x509verify != X509VERIFY_NONE)) {
                return match_hostnames(cur_cert, conn_info);
        }
        return 1;
}

/*
 * Create TCP sockets for incoming TLS connections.
 * To be used like socksetup(), hostname and port are optional,
 * returns bound stream sockets. 
 */
extern bool TLSClientOnly;
int *
socksetup_tls(int af, const char *bindhostname, const char *port)
{
        struct addrinfo hints, *res, *r;
        struct kevent *ev;
        int error, maxs, *s, *socks;
        const int on = 1;

        if(TLSClientOnly)
                return(NULL);

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = af;
        hints.ai_socktype = SOCK_STREAM;
        
        error = getaddrinfo(bindhostname, (port ? port : SERVICENAME), &hints, &res);
        if (error) {
                logerror(gai_strerror(error));
                errno = 0;
                die(NULL);
        }

        /* Count max number of sockets we may open */
        for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
                continue;
        socks = malloc((maxs+1) * sizeof(int));
        if (!socks) {
                logerror("Couldn't allocate memory for sockets");
                die(NULL);
        }

        *socks = 0;   /* num of sockets counter at start of array */
        s = socks + 1;
        for (r = res; r; r = r->ai_next) {
                *s = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
                if (*s < 0) {
                        logerror("socket() failed: %s", strerror(errno));
                        continue;
                }
                if (r->ai_family == AF_INET6 && setsockopt(*s, IPPROTO_IPV6,
                    IPV6_V6ONLY, &on, sizeof(on)) < 0) {
                        logerror("setsockopt(IPV6_V6ONLY) failed: %s", strerror(errno));
                        close(*s);
                        continue;
                }
                if (bind(*s, r->ai_addr, r->ai_addrlen) < 0) {
                        logerror("bind() failed: %s", strerror(errno));
                        close(*s);
                        continue;
                }
                if (listen(*s, TLSBACKLOG) < 0) {
                        logerror("listen() failed: %s", strerror(errno));
                        close(*s);
                        continue;
                }
                ev = allocevchange();
                EV_SET(ev, *s, EVFILT_READ, EV_ADD | EV_ENABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_accept_tls);

                *socks = *socks + 1;
                s++;
        }

        if (*socks == 0) {
                free (socks);
                if(Debug)
                        return(NULL);
                else
                        die(NULL);
        }
        if (res)
                freeaddrinfo(res);

        return(socks);
}

/*
 * establish TLS connection 
 */
bool tls_connect(SSL_CTX **context, struct tls_conn_settings *conn)
{
        struct addrinfo hints, *res, *res1;
        int    error, rc, sock;
        const int one = 1;
        char   buf[MAXLINE];
        SSL    *ssl; 
        SSL_CTX *g_TLS_CTX = *context;
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_CANONNAME;
        error = getaddrinfo(conn->hostname, (conn->port ? conn->port : SERVICENAME), &hints, &res);
        if (error) {
                logerror(gai_strerror(error));
                return false;
        }
        
        if (!g_TLS_CTX) {
                g_TLS_CTX = init_global_TLS_CTX(MYKEY, MYCERT, MYCA, MYCAPATH, X509VERIFY);
        }
        
        sock = -1;
        for (res1 = res; res1; res1 = res1->ai_next) {
                if (-1 == (sock = socket(res1->ai_family, res1->ai_socktype, res1->ai_protocol))) {
                        dprintf("Unable to open socket.\n");
                        continue;
                }
                dprintf("got socket with fd=%d, protocol=%d\n", sock, res1->ai_protocol);
                
                if ((-1 == (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))))
                                 || (-1 == (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))))
                                 || (-1 == (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one))))) {
                        dprintf("Unable to setsockopt(): %s\n", strerror(errno));
                }
                if (-1 == connect(sock, res1->ai_addr, res1->ai_addrlen)) {
                        dprintf("Unable to connect() to %s: %s\n", res1->ai_canonname, strerror(errno));
                        close(sock);
                        sock = -1;
                        continue;
                }
                dprintf("connect()\n");
                
                if (!(ssl = SSL_new(g_TLS_CTX))) {
                        ERR_error_string_n(ERR_get_error(), buf, MAXLINE);
                        dprintf("Unable to establish TLS: %s\n", buf);
                        close(sock);
                        sock = -1;
                        continue;                                
                }
                dprintf("SSL_new()\n");
                
                if (!SSL_set_fd(ssl, sock)) {
                        ERR_error_string_n(ERR_get_error(), buf, MAXLINE);
                        dprintf("Unable to connect TLS to socket: %s\n", buf);
                        SSL_free(ssl);
                        close(sock);
                        sock = -1;
                        continue;                                
                }
                dprintf("SSL_set_fd(ssl, %d)\n", sock);

                while ((rc = ERR_get_error())) {
                        ERR_error_string_n(rc, buf, MAXLINE);
                        dprintf("Found SSL error in queue: %s\n", buf);
                }

                SSL_set_app_data(ssl, conn);
                SSL_set_connect_state(ssl);
                while ((rc = ERR_get_error())) {
                        ERR_error_string_n(rc, buf, MAXLINE);
                        dprintf("Found SSL error in queue: %s\n", buf);
                }
                dprintf("SSL_set_app_data(), SSL_set_connect_state()\n");
                
                /* connect */
                //rc = SSL_do_handshake(ssl);
                //dprintf("SSL_do_handshake() returned %d: ", rc);
                dprintf("SSL_get_fd() gives: %d\n", SSL_get_fd(ssl));
                dprintf("now calling connect...\n");
                errno = 0;  /* reset to be sure we get the right one later on */
                rc = SSL_connect(ssl);
                if (rc >= 1) {
                        dprintf("TLS connection established.\n");
                        freeaddrinfo(res);
                        conn->sslptr = ssl;
                        return true;  /* okay we got one */
                }
                error = tls_examine_error("SSL_connect", ssl, conn, rc);
                close(sock);
                sock = -1;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                continue;
        }
        return false;
}

int
tls_examine_error(char *functionname, SSL *ssl, struct tls_conn_settings *tls_conn, int rc)
{
        int ssl_error, err_error;
        
        ssl_error = SSL_get_error(ssl, rc);
        dprintf("%s returned rc %d and error %s: %s\n", functionname, rc, SSL_ERRCODE[ssl_error], ERR_error_string(ssl_error, NULL));
        switch (ssl_error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                        return TLS_RETRY;
                        break;
                case SSL_ERROR_SYSCALL:
                        dprintf("SSL_ERROR_SYSCALL: ");
                        err_error = ERR_get_error();
                        if ((rc == -1) && (err_error == 0)) {
                                dprintf("socket I/O error: %s\n", strerror(errno));
                        } else if ((rc == 0) && (err_error == 0)) {
                                dprintf("unexpected EOF from %s\n", tls_conn ? tls_conn->hostname : NULL);
                        } else {
                                dprintf("no further info\n");
                        }
                        return TLS_PERM_ERROR;
                        break;                                            
                case SSL_ERROR_ZERO_RETURN:
                        logerror("TLS connection closed by %s", tls_conn ? tls_conn->hostname : NULL);
                        return TLS_PERM_ERROR;
                        break;                                
                case SSL_ERROR_SSL:
                        logerror("internal SSL error, error queue gives %s", ERR_error_string(ERR_get_error(), NULL));
                        /* TODO: handle wrong cert */
                        return TLS_PERM_ERROR;
                        break;
                default:
                        break;     
        }
        if (tls_conn) (tls_conn->errorcount)++;
        return TLS_TEMP_ERROR;
}


/* auxillary code to allocate memory and copy a string */
bool
copy_config_value(/*@out@*/ char **mem, char *p, char *q)
{
        if (!(*mem = malloc(1 + q - p))) {
                printf("Couldn't allocate memory for TLS config\n");
                return false;
        }
        strncpy(*mem, p, q - p);
        (*mem)[q - p] = '\0';
        return true;
}

bool
copy_config_value_quoted(char *keyword, char **mem, /*@null@*/char **p, /*@null@*/char **q)
{
        if (strncmp(*p, keyword, strlen(keyword)))
                return false;
        *q = *p += strlen(keyword);
        if (!(*q = strchr(*p, '"'))) {
                printf("unterminated \"\n");
                return false;
        }
        if (!(copy_config_value(mem, *p, *q)))
                return false;
        *p = ++(*q);
        return true;
}

/* 
 * Auxiliary function because TAILQ_HEAD_INITIALIZER is defined for
 * initialization and cannot be used in an assignment after malloc()
 * (?)
 */
inline struct buf_queue_head
makebuf_queue_head(struct filed *f)
{
        struct buf_queue_head bqh = TAILQ_HEAD_INITIALIZER(f->f_un.f_tls.qhead);
        return bqh;
}        

bool
parse_tls_destination(char *line, struct filed *f)
{
        char *p, *q;

        p = line;
        if ((*p++ != '@') || *p++ != '[') {
                logerror("parse_tls_destination() on non-TLS action");
                return false; 
        }
        
        if (!(q = strchr(p, ']'))) {
                logerror("Unterminated [ in configuration");
                return false;
        }

        if (!(f->f_un.f_tls.tls_conn = malloc(sizeof(struct tls_conn_settings)))) {
                logerror("Couldn't allocate memory for TLS config");
                return false;
        }
        /* default values */
        bzero(f->f_un.f_tls.tls_conn, sizeof(struct tls_conn_settings));
        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_NONE;
        f->f_un.f_tls.qhead = makebuf_queue_head(f);
        TAILQ_INIT(&f->f_un.f_tls.qhead);

        if (!(copy_config_value(&(f->f_un.f_tls.tls_conn->hostname), p, q)))
                return false;
        p = ++q;
        
        if (*p == ':') {
                p++; q++;
                while (isalnum((unsigned char)*q))
                        q++;
                if (!(copy_config_value(&(f->f_un.f_tls.tls_conn->port), p, q)))
                        return false;
                p = q;
        }
        /* allow whitespace for readability? */
        while (isblank(*p))
                p++;
        if (*p == '(') {
                p++;
                while (*p != ')') {
                        if (copy_config_value_quoted("subject=\"", &(f->f_un.f_tls.tls_conn->subject), &p, &q)
                            || copy_config_value_quoted("fingerprint=\"", &(f->f_un.f_tls.tls_conn->fingerprint), &p, &q)
                            || copy_config_value_quoted("cert=\"", &(f->f_un.f_tls.tls_conn->certfile), &p, &q)) {
                        /* nothing */
                        }
                        else if (!strncmp(p, "verify=", strlen("verify="))) {
                                q = p += strlen("verify=");
                                if (*p == '\"') { p++; q++; }  /* "" are optional */
                                while (isalpha((unsigned char)*q)) q++;
                                if ((q-p > 1) && !strncasecmp("off", p, q-p))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_NONE;
                                else if ((q-p > 1) && !strncasecmp("opt", p, q-p))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_IFPRESENT;
                                else if ((q-p > 1) && !strncasecmp("on", p, q-p))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_ALWAYS;
                                else {
                                        logerror("unknown verify value %.*s", q-p, p);
                                }
                                if (*q == '\"') q++;  /* "" are optional */
                                p = q;
                        }
                        else {
                                logerror("unknown keyword %s", p);
                                return false;        
                        }
                        while (*p == ',' || isblank(*p))
                                p++;
                        if (*p == '\0') {
                                logerror("unterminated (");
                                return false;
                        }
                }
        }
        dprintf("got TLS config: host %s, port %s, subject: %s\n",
                f->f_un.f_tls.tls_conn->hostname,
                f->f_un.f_tls.tls_conn->port,
                f->f_un.f_tls.tls_conn->subject);
        return true;
}

/*
 * Dispatch routine (triggered by timer) to reconnect to a lost TLS server
 */
void
tls_reconnect(struct kevent *ev)
{
        struct filed *f = (struct filed *) ev->ident;
        
        dprintf("reconnect timer expired\n");
        if (!tls_connect(&global_TLS_CTX, f->f_un.f_tls.tls_conn)) {
                logerror("Unable to connect to TLS server %s", f->f_un.f_tls.tls_conn->hostname);
                EV_SET(ev, (uintptr_t)f, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
                    0, 3*1000*TLS_RECONNECT_SEC, KEVENT_UDATA_CAST tls_reconnect); 
        } else {
                tls_send_queue(f);
        }        
        return;
}

/* send message queue after reconnect */
void
tls_send_queue(struct filed *f)
{
        struct buf_queue *qptr;
        
        while (!TAILQ_EMPTY(&f->f_un.f_tls.qhead)) {
                qptr = TAILQ_FIRST(&f->f_un.f_tls.qhead);
                
                if (!tls_send(f, qptr->msg->line, qptr->msg->len))
                        /* stop on first error --> next reconnect will continue */
                        return;
                
                TAILQ_REMOVE(&f->f_un.f_tls.qhead, qptr, entries);
                if (!qptr->msg->refcount) {
                        free(qptr->msg->line);
                        free(qptr->msg);
                }
                free(qptr);
        }                
}

/*
 * Dispatch routine for accepting TCP/TLS sockets.
 * TODO: check correct LIBWRAP usage for TCP connections
 * TODO: how do we handle fingerprint auth for incoming?
 *       set up a list of tls_conn_settings and pick one matching the hostname?
 */
void
dispatch_accept_tls(struct kevent *ev)
{
#ifdef LIBWRAP
        struct request_info req;
#endif
        struct sockaddr_storage frominet;
        socklen_t addrlen;
        int fd = ev->ident;
        int reject = 0;
        int tries = 0;
        int newsock, rc, error;
        SSL *ssl;
        struct tls_conn_settings *conn_info;
        struct TLS_Incoming_Conn *tls_in;
        struct kevent *newev;
        char hbuf[NI_MAXHOST];
        char *peername;

        dprintf("incoming TLS connection\n");
        if (!global_TLS_CTX) {
                logerror("global_TLS_CTX not initialized!");
                return;
        }

#ifdef LIBWRAP
        request_init(&req, RQ_DAEMON, "syslogd", RQ_FILE, fd, NULL);
        fromhost(&req);
        reject = !hosts_access(&req);
#endif
        addrlen = sizeof(frominet);
        if (!(conn_info = malloc(sizeof(struct tls_conn_settings)))
         || !(tls_in = malloc(sizeof(struct TLS_Incoming_Conn)))) {
                logerror("cannot allocate memory");
                return;
        }
          
        if (-1 == (newsock = accept(fd, (struct sockaddr *)&frominet, &addrlen))) {
                logerror("Error in accept(): %s", strerror(errno));
                return;
        }
        if ((rc = getnameinfo((struct sockaddr *)&frominet, addrlen, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV))) {
                dprintf("could not get peername: %s", gai_strerror(rc));
                peername = NULL;
        }
        else {
                if (!(peername = malloc(strlen(hbuf)+1))) {
                        dprintf("cannot allocate %d bytes memory\n", strlen(hbuf)+1);
                        return;
                }
                (void)strlcpy(peername, hbuf, strlen(hbuf)+1);
        }
#ifdef LIBWRAP
        if (reject) {
                logerror("access from %s denied by hosts_access", peername);
                return;
        }
#endif
        if (-1 == (fcntl(newsock, F_SETFL, O_NONBLOCK))) {
                dprintf("Unable to fcntl(sock, O_NONBLOCK): %s\n", strerror(errno));
        }
        
        if (!(ssl = SSL_new(global_TLS_CTX))) {
                dprintf("Unable to establish TLS: %s\n", ERR_error_string(ERR_get_error(), NULL));
                close(newsock);
                return;                                
        }
        if (!SSL_set_fd(ssl, newsock)) {
                dprintf("Unable to connect TLS to socket %d: %s\n", newsock, ERR_error_string(ERR_get_error(), NULL));
                SSL_free(ssl);
                close(newsock);
                return;
        }
        dprintf("connection from %s accept()ed, and connected SSL*@%p with fd %d...\n",
                peername, ssl, newsock);

        /* store connection details inside ssl object, used to verify
         * cert and immediately match against hostname */
        bzero(conn_info, sizeof(*conn_info));
        conn_info->hostname = peername;
        conn_info->x509verify = X509VERIFY_NONE;
        conn_info->sslptr = ssl;
        SSL_set_app_data(ssl, conn_info);
        SSL_set_accept_state(ssl);
        
        /* non-blocking might require several calls? */
try_SSL_accept:        
        rc = SSL_accept(ssl);
        if (0 >= rc) {
                error = tls_examine_error("SSL_accept()", ssl, NULL, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++tries < TLS_SLEEP_TRIES) {
                                        usleep(TLS_SLEEP_USEC);
                                        goto try_SSL_accept;
                                }
                                break;
                        default:break;
                }
        } else {
                bzero(tls_in, sizeof(tls_in));
                tls_in->tls_conn = conn_info;
                tls_in->socket = newsock;
                tls_in->ssl = ssl;
                tls_in->inbuf[0] = '\0';
                tls_in->read_pos = tls_in->cur_msg_start = \
                        tls_in->cur_msg_len = tls_in->closenow = 0;
                SLIST_INSERT_HEAD(&TLS_Incoming_Head, tls_in, entries);
    
                newev = allocevchange();
                EV_SET(newev, newsock, EVFILT_READ, EV_ADD | EV_ENABLE,
                    0, 0, KEVENT_UDATA_CAST dispatch_read_tls);
                dprintf("established TLS connection from %s\n", peername);
                
                /*
                 * We could also listen to EOF kevents -- but I do not think
                 * that would be useful, because we still had to read() the buffer
                 * before closing the socket.
                 */
        }
}

/*
 * Dispatch routine to read from TCP/TLS sockets.
 * NB: This gets called when the TCP socket has data available, thus
 *     we can call SSL_read() on it. But that does not mean the SSL buffer
 *     holds a complete record and SSL_read() lets us read any data now.
 * Question: we get the socket fd and have to look up the tls_conn object.
 *     IMHO we always have <100 connections and a list traversal is
 *     fast enough. A possible optimization would be keeping track of
 *     message counts and moving busy sources to the front of the list.
 */
void
dispatch_read_tls(struct kevent *ev)
{
        int fd = ev->ident;
        int error, tries;
        int_fast16_t rc;
        struct TLS_Incoming_Conn *c;

        dprintf("active TLS socket %d\n", fd);
        
        SLIST_FOREACH(c, &TLS_Incoming_Head, entries) {
                dprintf("look at tls_in@%p with fd %d\n", c, c->socket);
                if (c->socket == fd)
                        break;
        }
        if (!c) {
                logerror("lost TLS socket fd %d, closing", fd);
                close(fd);
                return;
        }

/* according to draft-ietf-syslog-transport-tls-12 "It is ... possible
 * that a syslog message be transferred in multiple TLS records."
 * So we have to buffer it just like with TCP with a seperate incoming buffer.
 * 
 * Example: If a msg is sent in two TLS records 
 * then we might read the beginning (from the 1st record),
 * but wait some time for the end (in the 2nd record).
 * In that waiting time we must not block.
 */
        
        tries = 0;
try_SSL_read:
        dprintf("incoming status is msg_start %d, msg_len %d, pos %d\n",
                c->cur_msg_start, c->cur_msg_len, c->read_pos);
        dprintf("calling SSL_read(%p, %p, %d)\n", c->ssl,
                &(c->inbuf[c->read_pos]), sizeof(c->inbuf) - c->read_pos);
        rc = SSL_read(c->ssl, &(c->inbuf[c->read_pos]), sizeof(c->inbuf) - c->read_pos);
        if (rc <= 0) {
                error = tls_examine_error("SSL_read()", c->ssl, c->tls_conn, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++tries < TLS_SLEEP_TRIES) {
                                        usleep(TLS_SLEEP_USEC);
                                        goto try_SSL_read;
                                }
                                break;
                        case TLS_TEMP_ERROR:
                                if (c->tls_conn->errorcount < TLS_MAXERRORCOUNT)
                                        break;
                                /* else fallthrough */
                        case TLS_PERM_ERROR:
                                /* there might be data in the inbuf, so only
                                 * mark for closing after message retrieval */
                                c->closenow = 1;
                                break;
                        default:break;
                }
        } else {
                dprintf("SSL_read() returned %d\n", rc);
                c->errorcount = 0;
                c->read_pos += rc;
        }
        tls_split_messages(c);
}

/* moved message splitting out of dispatching function.
 * now we can call it recursively.
 */
void
tls_split_messages(struct TLS_Incoming_Conn *c)
{
/* define only to make it better readable */
#define MSG_END_OFFSET (c->cur_msg_start + c->cur_msg_len)
        uint_fast16_t offset;
        char numbuf[PREFIXLENGTH+1];
        
        dprintf("tls_split_messages() -- incoming status is " \
                "msg_start %d, msg_len %d, pos %d\n",
                c->cur_msg_start, c->cur_msg_len, c->read_pos);

        if(c->closenow && !c->read_pos) {
                /* close socket */
                free_tls_conn(c->tls_conn);
                SLIST_REMOVE(&TLS_Incoming_Head, c, TLS_Incoming_Conn, entries);
                free(c);
        }
        if (!c->read_pos)
                return;
        if (c->read_pos < MSG_END_OFFSET)
                return;
                
        /* read length prefix, always at start of buffer */
        offset = 0;
        while (isdigit((int)c->inbuf[offset])
                && offset < c->read_pos
                && offset < PREFIXLENGTH) {
                numbuf[offset] = c->inbuf[offset];
                numbuf[++offset] = '\0';
        }
        if (offset == c->read_pos) {
                return;
        }
        if (((c->inbuf[offset] != ' ') && !isdigit((int)c->inbuf[offset]))
                || offset == PREFIXLENGTH) {
                /* found non-digit in prefix or filled buffer */
                /* Question: would it be useful to skip this message and
                 * try to find next message by looking for its beginning?
                 * IMHO not.   
                 */
                logerror("Unable to handle TLS length prefix. " \
                        "Protocol error? Closing connection now.");
                free_tls_conn(c->tls_conn);
                SLIST_REMOVE(&TLS_Incoming_Head, c, TLS_Incoming_Conn, entries);
                free(c);
                return;
        } else if (c->inbuf[offset] == ' ') {
                c->cur_msg_len = strtol(numbuf, NULL, 10);
                c->cur_msg_start = offset + 1;
                if (c->cur_msg_len > linebufsize) {
                        /* TODO: handle messages too large for our buffer
                         *  --> either receive and truncate or malloc()
                         */
                        logerror("c->cur_msg_len > linebufsize");
                        die(NULL);
                }
        }
        /* read one syslog message */        
        if (c->read_pos >= MSG_END_OFFSET) {
                /* process complete msg */
                (void)memcpy(linebuf, &c->inbuf[c->cur_msg_start], c->cur_msg_len);
                linebuf[c->cur_msg_len] = '\0';
                printline(c->tls_conn->hostname, linebuf, RemoteAddDate ? ADDDATE : 0);

                /* 
                 * silently ignore whitespace after messages.
                 * this allows debugging with socat  :-)
                 */
                if (Debug)
                        while (isspace(c->inbuf[c->read_pos-1])) {
                                c->read_pos--;
                                dprintf("skip\n"); 
                        }

                if (MSG_END_OFFSET == c->read_pos) {
                        /* no unprocessed data in buffer --> reset to empty */
                        c->cur_msg_start = c->cur_msg_len = c->read_pos = 0;
                } else {
                        /* move remaining input to start of buffer */
                        dprintf("move inbuf of length %d by %d chars\n",
                                c->read_pos - (MSG_END_OFFSET),
                                MSG_END_OFFSET);
                        memmove(&c->inbuf[0],
                                &c->inbuf[MSG_END_OFFSET],
                                c->read_pos - (MSG_END_OFFSET));
                        c->read_pos -= (MSG_END_OFFSET);
                        c->cur_msg_start = c->cur_msg_len = 0;
                }
        }
        dprintf("return with status: msg_start %d, msg_len %d, pos %d\n",
                 c->cur_msg_start, c->cur_msg_len, c->read_pos);

        /* try to read another message */
        if (c->read_pos > 10)
                tls_split_messages(c);
        return;
}

/* send one line with tls
 * f has to be of typ TLS
 * line has to be in transport format with length prefix
 */
bool
tls_send(struct filed *f, char *line, size_t len)
{
        int i, j, retry, rc, error;
        char *tlslineptr = line;
        size_t tlslen = len;
        struct kevent *newev;
        
        dprintf("tls_send(f=%p, line=\"%.*s...\", len=%d) to %sconnected dest.\n",
                f, (len>20 ? 20 : len), line, len,
                f->f_un.f_tls.tls_conn->sslptr ? "" : "un");

        if (!f->f_un.f_tls.tls_conn->sslptr) {
                return false;
        }

        /* simple sanity check for length prefix */
        for (i = 0, j = len; j /= 10; i++)
                if (!isdigit(line[i])) {
                        dprintf("malformed TLS line: %.*s", (len>20 ? 20 : len), line);
                        /* silently discard malformed line, re-queuing it would only cause a loop */
                        return true;
                } 
        if (line[++i] != ' ') {
                dprintf("malformed TLS line: %.*s", (len>20 ? 20 : len), line);
                return true;
        }

        retry = 0;
try_SSL_write:
        rc = SSL_write(f->f_un.f_tls.tls_conn->sslptr, tlslineptr, tlslen);
        if (0 >= rc) {
                error = tls_examine_error("SSL_write()",
                        f->f_un.f_tls.tls_conn->sslptr,
                        f->f_un.f_tls.tls_conn, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++retry < TLS_SLEEP_TRIES) {
                                        usleep(TLS_SLEEP_USEC);
                                        goto try_SSL_write;
                                }
                                break;
                        case TLS_TEMP_ERROR:
                                if ((f->f_un.f_tls.tls_conn->errorcount)++ < TLS_MAXERRORCOUNT)
                                        break;
                                /* else fallthrough */
                        case TLS_PERM_ERROR:
                                /* Reconnect after x seconds  */
                                newev = allocevchange();
                                EV_SET(newev, (uintptr_t)f, EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT,
                                    0, 1000*TLS_RECONNECT_SEC, KEVENT_UDATA_CAST tls_reconnect);
                                dprintf("scheduled reconnect in %d seconds\n", TLS_RECONNECT_SEC);
                                break;
                        default:break;
                }
                free_tls_sslptr(f->f_un.f_tls.tls_conn);
                return false;
        }
        else if (rc < tlslen) {
        dprintf("TLS: SSL_write() wrote %d out of %d bytes\n",
                        rc, tlslen);
                tlslineptr += rc;
                tlslen -= rc;
                goto try_SSL_write;
        }
        f->f_un.f_tls.tls_conn->errorcount = 0;
        return true;
}

/*
 * Close a SSL connection and its queue and its tls_conn.
 */
void
free_tls_conn(struct tls_conn_settings *tls_conn)
{
        if (tls_conn->sslptr)
                free_tls_sslptr(tls_conn);
        /* TODO: free queue */
        if (tls_conn->port)        free(tls_conn->port);
        if (tls_conn->subject)     free(tls_conn->subject);
        if (tls_conn->hostname)    free(tls_conn->hostname);
        if (tls_conn->certfile)    free(tls_conn->certfile);
        if (tls_conn->fingerprint) free(tls_conn->fingerprint);
        if (tls_conn)              free(tls_conn);
}

/*
 * Close a SSL object
 */
void
free_tls_sslptr(struct tls_conn_settings *tls_conn)
{
        int sock;
        sock = SSL_get_fd(tls_conn->sslptr);
        
        if (!tls_conn->sslptr)
                return;
        else {
                if (SSL_shutdown(tls_conn->sslptr) || SSL_shutdown(tls_conn->sslptr)) {
                        /* shutdown has two steps, returns 1 on completion */
                        dprintf("Closed TLS connection to %s\n", tls_conn->hostname);
                } else { 
                        dprintf("Unable to cleanly shutdown TLS connection to %s\n", tls_conn->hostname);
                }        
                if (shutdown(sock, SHUT_RDWR))
                        dprintf("Unable to cleanly shutdown TCP socket %d: %s\n", sock, strerror(errno));
                if (close(sock))
                        dprintf("Unable to cleanly close socket %d: %s\n", sock, strerror(errno));
                SSL_free(tls_conn->sslptr);
                tls_conn->sslptr = NULL;
        }
}

