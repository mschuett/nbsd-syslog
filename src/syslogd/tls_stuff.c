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

#include "syslogd.h"
#include "tls_stuff.h"

/* to output SSL error codes */
const char *SSL_ERRCODE[] = {
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

extern struct tls_global_options_t tls_opt;
extern struct TLS_Incoming TLS_Incoming_Head;
extern char *linebuf;
extern size_t linebufsize;
extern int     RemoteAddDate; 

extern void    logerror(const char *, ...);
extern bool    fprintlog_noqueue(struct filed *, int, char *, struct buf_msg *);
extern void    printline(char *, char *, int);
extern void    die(int fd, short event, void *ev);
extern struct event *allocev(void);
extern void    send_queue(struct filed *);
extern inline void schedule_event(struct event **, struct timeval *, void (*)(int, short, void *), void *);
/*
 * init OpenSSL lib and one context. returns NULL on error, otherwise SSL_CTX
 * all pointer arguments may be NULL (at least for clients)
 * x509verify determines the level of certificate validation
 */
SSL_CTX *
init_global_TLS_CTX(const char *keyfilename, const char *certfilename,
                const char *CAfile, const char *CApath, const char *strx509verify)
{
        SSL_CTX *ctx;
        int x509verify = X509VERIFY_ALWAYS;
        
        if (strx509verify && !strcasecmp(strx509verify, "off"))
                x509verify = X509VERIFY_NONE;
        else if (strx509verify && !strcasecmp(strx509verify, "opt"))
                x509verify = X509VERIFY_IFPRESENT;
        
        SSL_load_error_strings();
        (void) SSL_library_init();
        OpenSSL_add_all_digests();
        if (!(ctx = SSL_CTX_new(SSLv23_method()))) {
                ERR_print_errors_fp(stderr);
                return NULL;
        }
        /* load keys and certs here */
        if (keyfilename && certfilename) {
                if (!(SSL_CTX_use_PrivateKey_file(ctx, keyfilename, SSL_FILETYPE_PEM)
                    && SSL_CTX_use_certificate_chain_file(ctx, certfilename))) {
                        DPRINTF("unable to get private key and certificate\n");
                        ERR_print_errors_fp(stderr);
                        exit(1);
                }
                if (!SSL_CTX_check_private_key(ctx)) {
                        DPRINTF("private key does not match certificate\n");
                        ERR_print_errors_fp(stderr);
                        exit(1);
                } else {
                        DPRINTF("loaded and checked own certificate\n");
                }
        }
        if (CAfile || CApath) {
                if (!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) {
                        DPRINTF("unable to load trust anchors\n");
                        ERR_print_errors_fp(stderr);
                } else {
                        DPRINTF("loaded trust anchors\n");
                }
        }
        /* peer verification */
        /* 
         * TODO: is it possible to have one destination with and one
         * without verification?
         */
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
get_fingerprint(const X509 *cert, char **returnstring, const char *alg_name)
{
#define MAX_ALG_NAME_LENGTH 8
        unsigned char md[EVP_MAX_MD_SIZE];
        char fp_val[4];
        unsigned int len, memsize, i = 0;
        EVP_MD *digest;

        DPRINTF("get_fingerprint(cert, %p, %s)\n", returnstring, alg_name);
        *returnstring = NULL;
        if ((alg_name && !(digest = (EVP_MD *) EVP_get_digestbyname(alg_name)))
            || (!alg_name && !(digest = (EVP_MD *) EVP_get_digestbyname("SHA1")))) {
                DPRINTF("unknown digest algorithm %s\n", alg_name);
                
                return false;
        }
        if (!X509_digest(cert, digest, md, &len)) {
                DPRINTF("cannot get %s digest\n", alg_name);
                return false;
        }
        /* needed memory. 3 string bytes for every binary byte with delimiter
         * + alg_name with delimiter */
        memsize = (len * 3) + strlen(OBJ_nid2sn(EVP_MD_type(digest))) + 1;
        if (!(*returnstring = malloc(memsize))) {
                logerror("Unable to allocate memory");
                return false;
        }
        /* 'normalise' the algorithm name */
        (void)strlcpy(*returnstring, OBJ_nid2sn(EVP_MD_type(digest)), memsize);
        (void)strlcat(*returnstring, ":", memsize);
        /* append the fingeprint data */
        for (i = 0; i < len; i++) {
                (void)snprintf(fp_val, sizeof(fp_val), "%02X:", (unsigned int) md[i]);
                (void)strlcat(*returnstring, fp_val, memsize);
        }
        if ((*returnstring)[memsize - 1] != '\0')
                DPRINTF("memory overflow. last 4 chars are: %c%c%c%c\n",
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
match_hostnames(X509 *cert, const struct tls_conn_settings *conn)
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
        DPRINTF("match_hostnames() to check cert against %s and %s\n",
            conn->subject, conn->hostname);

        /* see if hostname is an IP */
        i = (asn1_ip = a2i_IPADDRESS(conn->subject)) || (asn1_ip = a2i_IPADDRESS(conn->hostname));

        if (!(gennames = X509_get_ext_d2i(cert, NID_subject_alt_name, &crit, &idx))) {
                DPRINTF("X509_get_ext_d2i() returned (%p,%d,%d) --> no subjectAltName\n", gennames, crit, idx);
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
                        DPRINTF("found CN: %.*s\n", len, ubuf);
                        /* hostname */
                        if ((conn->subject && !strncasecmp(conn->subject, (const char*)ubuf, len))
                            || (conn->hostname && !strncasecmp(conn->hostname, (const char*)ubuf, len))) {
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
match_fingerprint(const X509 *cert, const struct tls_conn_settings *conn)
{
#define MAX_ALG_NAME_LENGTH 8
        char alg[MAX_ALG_NAME_LENGTH];
        char *certfingerprint;
        char *p, *q;
        DPRINTF("match_fingerprint(%s)\n", conn->fingerprint);
        if (!conn->fingerprint)
                return false;

        /* get algorithm */
        p = alg;
        q = conn->fingerprint;
        while (*q != ':' && *q != '\0' && p < alg + MAX_ALG_NAME_LENGTH)
                *p++ = *q++;
        *p = '\0';

        if (!get_fingerprint(cert, &certfingerprint, alg)) {
                DPRINTF("cannot get %s digest\n", alg);
                return false;
        }
        if (strncmp(certfingerprint, conn->fingerprint, strlen(certfingerprint))) {
                DPRINTF("fail: fingerprints do not match\n");
                free(certfingerprint);
                return false;
        }
        DPRINTF("accepted: fingerprints match\n");
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
check_peer_cert(int preverify_ok, X509_STORE_CTX *ctx)
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
        (void)X509_NAME_oneline(X509_get_subject_name(cur_cert), buf, sizeof(buf));
        (void)get_fingerprint(cur_cert, &fingerprint, NULL);
        DPRINTF("check cert for connection with %s. depth is %d, preverify is %d, subject is %s, fingerprint is %s\n",
            conn_info->hostname, cur_depth, preverify_ok, buf, fingerprint);
        free(fingerprint);


        if (conn_info->x509verify == X509VERIFY_NONE)
                return 1;

        if ((conn_info->force_fingerprint_check) && (cur_depth == 0)) {
                rc = match_fingerprint(cur_cert, conn_info);
                DPRINTF("depth 0 arrived, match_fingerprint() returned %d\n", rc);
                return rc;
        }
        if (!preverify_ok) {
                if (cur_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
                        X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, sizeof(buf));
                        DPRINTF("openssl verify error:missing cert for issuer= %s\n", buf);
                }
                DPRINTF("openssl verify error:num=%d:%s:depth=%d:%s\t\n", cur_err,
                    X509_verify_cert_error_string(cur_err), cur_depth, buf);

                if ((conn_info->fingerprint) && (cur_depth != 0)) {
                        DPRINTF("accepting otherwise invalid chain element, waiting for depth 0 to check fingerprint\n");
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
struct socketEvent *
socksetup_tls(const int af, const char *bindhostname, const char *port)
{
        struct addrinfo hints, *res, *r;
        int error, maxs;
        const int on = 1;
        struct socketEvent *s, *socks;

        if(tls_opt.client_only)
                return(NULL);

        memset(&hints, 0, sizeof(hints));
        hints.ai_flags = AI_PASSIVE;
        hints.ai_family = af;
        hints.ai_socktype = SOCK_STREAM;
        
        error = getaddrinfo(bindhostname, (port ? port : SERVICENAME), &hints, &res);
        if (error) {
                logerror(gai_strerror(error));
                errno = 0;
                die(0, 0, NULL);
        }

        /* Count max number of sockets we may open */
        for (maxs = 0, r = res; r; r = r->ai_next, maxs++)
                continue;
        socks = malloc((maxs+1) * sizeof(*socks));
        if (!socks) {
                logerror("Unable to allocate memory for sockets");
                die(0, 0, NULL);
        }

        socks->fd = 0;   /* num of sockets counter at start of array */
        s = socks + 1;
        for (r = res; r; r = r->ai_next) {
                if ((s->fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1) {
                        logerror("socket() failed: %s", strerror(errno));
                        continue;
                }
                if (r->ai_family == AF_INET6
                 && setsockopt(s->fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1) {
                        logerror("setsockopt(IPV6_V6ONLY) failed: %s", strerror(errno));
                        close(s->fd);
                        continue;
                }
                if ((error = bind(s->fd, r->ai_addr, r->ai_addrlen)) == -1) {
                        logerror("bind() failed: %s", strerror(errno));
                        /* is there a better way to handle a EADDRINUSE? */
                        close(s->fd);
                        continue;
                }
                if (listen(s->fd, TLSBACKLOG) == -1) {
                        logerror("listen() failed: %s", strerror(errno));
                        close(s->fd);
                        continue;
                }
                s->ev = allocev();
                event_set(s->ev, s->fd, EV_READ | EV_PERSIST, dispatch_accept_socket, s->ev);
                if (event_add(s->ev, NULL) == -1) {
                        DPRINTF("Failure in event_add()\n");
                }

                socks->fd = socks->fd + 1;  /* num counter */
                s++;
        }

        if (socks->fd == 0) {
                free (socks);
                if(Debug)
                        return(NULL);
                else
                        die(0, 0, NULL);
        }
        if (res)
                freeaddrinfo(res);

        return(socks);
}

/*
 * establish TLS connection 
 */
bool
tls_connect(SSL_CTX *context, struct tls_conn_settings *conn)
{
        struct addrinfo hints, *res, *res1;
        int    error, rc, sock;
        const int one = 1;
        char   buf[MAXLINE];
        SSL    *ssl; 
        
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
        
        if (!context) {
                logerror("No TLS context in tls_connect()");
                return false;
        }
        
        sock = -1;
        for (res1 = res; res1; res1 = res1->ai_next) {
                if ((sock = socket(res1->ai_family, res1->ai_socktype, res1->ai_protocol)) == -1) {
                        DPRINTF("Unable to open socket.\n");
                        continue;
                }
                if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
                        DPRINTF("Unable to setsockopt(): %s\n", strerror(errno));
                }
                if (connect(sock, res1->ai_addr, res1->ai_addrlen) == -1) {
                        DPRINTF("Unable to connect() to %s: %s\n", res1->ai_canonname, strerror(errno));
                        close(sock);
                        sock = -1;
                        continue;
                }
                if (!(ssl = SSL_new(context))) {
                        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
                        DPRINTF("Unable to establish TLS: %s\n", buf);
                        close(sock);
                        sock = -1;
                        continue;                                
                }
                if (!SSL_set_fd(ssl, sock)) {
                        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
                        DPRINTF("Unable to connect TLS to socket: %s\n", buf);
                        SSL_free(ssl);
                        close(sock);
                        sock = -1;
                        continue;                                
                }
                SSL_set_app_data(ssl, conn);
                SSL_set_connect_state(ssl);
                while ((rc = ERR_get_error())) {
                        ERR_error_string_n(rc, buf, sizeof(buf));
                        DPRINTF("Found SSL error in queue: %s\n", buf);
                }
                /* connect */
                DPRINTF("Calling SSL_connect()...\n");
                errno = 0;  /* reset to be sure we get the right one later on */
                /* TODO: change outgoing sockets to non-blocking? */
                rc = SSL_connect(ssl);
                if (rc >= 1) {
                        DPRINTF("TLS connection established.\n");
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
tls_examine_error(const char *functionname, const SSL *ssl, struct tls_conn_settings *tls_conn, const int rc)
{
        int ssl_error, err_error;
        
        ssl_error = SSL_get_error(ssl, rc);
        DPRINTF("%s returned rc %d and error %s: %s\n", functionname, rc, SSL_ERRCODE[ssl_error], ERR_error_string(ssl_error, NULL));
        switch (ssl_error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                        return TLS_RETRY;
                        break;
                case SSL_ERROR_SYSCALL:
                        DPRINTF("SSL_ERROR_SYSCALL: ");
                        err_error = ERR_get_error();
                        if ((rc == -1) && (err_error == 0)) {
                                DPRINTF("socket I/O error: %s\n", strerror(errno));
                        } else if ((rc == 0) && (err_error == 0)) {
                                DPRINTF("unexpected EOF from %s\n", tls_conn ? tls_conn->hostname : NULL);
                        } else {
                                DPRINTF("no further info\n");
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
        if (tls_conn)
                tls_conn->errorcount++;
        return TLS_TEMP_ERROR;
}


/* auxillary code to allocate memory and copy a string */
bool
copy_string(char **mem, const char *p, const char *q)
{
        const size_t len = 1 + q - p;
        if (!(*mem = malloc(len))) {
                logerror("Unable to allocate memory for config");
                return false;
        }
        strlcpy(*mem, p, len);
        return true;
}

/* keyword has to end with ",  everything until next " is copied */
bool
copy_config_value_quoted(const char *keyword, char **mem, char **p, char **q)
{
        if (strncasecmp(*p, keyword, strlen(keyword)))
                return false;
        *q = *p += strlen(keyword);
        if (!(*q = strchr(*p, '"'))) {
                logerror("unterminated \"\n");
                return false;
        }
        if (!(copy_string(mem, *p, *q)))
                return false;
        *p = ++(*q);
        return true;
}

/* for config file:
 * following = required but whitespace allowed, quotes optional
 * if numeric, then conversion to integer and no memory allocation 
 */
bool
copy_config_value(const char *keyword, char **mem, char **p, char **q, const char *file, const int line)
{
        if (strncasecmp(*p, keyword, strlen(keyword)))
                return false;
        *p += strlen(keyword);

        while (isspace((unsigned char)**p))
                *p += 1;
        if (**p != '=') {
                logerror("expected \"=\" in file %s, line %d", file, line);
                return false;
        }
        *p += 1;
        while (isspace((unsigned char)**p))
                *p += 1;

        if (**p == '"')
                return copy_config_value_quoted("\"", mem, p, q);

        /* without quotes: find next whitespace or end of line */
        (void) ((*q = strchr(*p, ' ')) || (*q = strchr(*p, '\t'))
          || (*q = strchr(*p, '\n')) || (*q = strchr(*p, '\0')));

        if (!(copy_string(mem, *p, *q)))
                return false;

        *p = ++(*q);
        return true;
}

bool
parse_tls_destination(char *p, struct filed *f)
{
        char *q;

        if ((*p++ != '@') || *p++ != '[') {
                logerror("parse_tls_destination() on non-TLS action");
                return false; 
        }
        
        if (!(q = strchr(p, ']'))) {
                logerror("Unterminated [ in configuration");
                return false;
        }

        if (!(f->f_un.f_tls.tls_conn = calloc(1, sizeof(*f->f_un.f_tls.tls_conn)))) {
                logerror("Couldn't allocate memory for TLS config");
                return false;
        }
        /* default values */
        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_NONE;

        if (!(copy_string(&(f->f_un.f_tls.tls_conn->hostname), p, q)))
                return false;
        p = ++q;
        
        if (*p == ':') {
                p++; q++;
                while (isalnum((unsigned char)*q))
                        q++;
                if (!(copy_string(&(f->f_un.f_tls.tls_conn->port), p, q)))
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
                        else if (!strcmp(p, "verify=")) {
                                q = p += sizeof("verify=")-1;
                                if (*p == '\"') { p++; q++; }  /* "" are optional */
                                while (isalpha((unsigned char)*q)) q++;
                                if ((q-p > 1) && !strncasecmp("off", p, sizeof("off")-1))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_NONE;
                                else if ((q-p > 1) && !strncasecmp("opt", p, sizeof("opt")-1))
                                        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_IFPRESENT;
                                else if ((q-p > 1) && !strncasecmp("on", p, sizeof("on")-1))
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
        DPRINTF("got TLS config: host %s, port %s, subject: %s\n",
                f->f_un.f_tls.tls_conn->hostname,
                f->f_un.f_tls.tls_conn->port,
                f->f_un.f_tls.tls_conn->subject);
        return true;
}

/*
 * Dispatch routine (triggered by timer) to reconnect to a lost TLS server
 */
void
tls_reconnect(int fd, short event, void *arg)
{
        struct filed *f = (struct filed *) arg;
        
        DPRINTF("reconnect timer expired\n");

        if (!tls_connect(tls_opt.global_TLS_CTX, f->f_un.f_tls.tls_conn)) {
                logerror("Unable to connect to TLS server %s", f->f_un.f_tls.tls_conn->hostname);
                schedule_event(&f->f_un.f_tls.tls_conn->event,
                        &((struct timeval){TLS_RECONNECT_SEC, 0}),
                        tls_reconnect, f);
        } else {
                send_queue(f);
        }        
        return;
}

/*
 * Dispatch routine for accepting TLS connections.
 * Has to be idempotent in case of TLS_RETRY (~ EAGAIN), so we can defer
 * a slow handshake with a timer-kevent and continue some msec later.
 */
void
dispatch_accept_tls(int fd, short event, void *arg)
{
        struct tls_conn_settings *conn_info = (struct tls_conn_settings *) arg;
        int rc, error, tries = 0;
        struct TLS_Incoming_Conn *tls_in;

        DPRINTF("start TLS on connection\n");
        
try_SSL_accept:        
        rc = SSL_accept(conn_info->sslptr);
        if (0 >= rc) {
                error = tls_examine_error("SSL_accept()",
                        conn_info->sslptr, NULL, rc);
                if (error == TLS_RETRY) {
                        /* first retry immediately again,
                         * then schedule for later */ 
                        if (++tries < TLS_NONBLOCKING_TRIES) {
                                usleep(TLS_NONBLOCKING_USEC);
                                goto try_SSL_accept;
                        }
                        schedule_event(&conn_info->event, 
                                &((struct timeval){0, TLS_RETRY_KEVENT_USEC}),
                                dispatch_accept_tls, conn_info);
                }
                return;
        }
        /* else */
        if (!(tls_in = calloc(1, sizeof(*tls_in)))
         || !(tls_in->inbuf = malloc(MAXLINE))) {
                logerror("Unable to allocate memory for accepted connection");
                free(tls_in);
                free_tls_conn(conn_info);
                return;
        }        
        tls_in->tls_conn = conn_info;
        tls_in->socket = SSL_get_fd(conn_info->sslptr);
        tls_in->ssl = conn_info->sslptr;
        tls_in->inbuf[0] = '\0';
        tls_in->inbuflen = MAXLINE;
        SLIST_INSERT_HEAD(&TLS_Incoming_Head, tls_in, entries);

        event_set(conn_info->event, tls_in->socket, EV_READ | EV_PERSIST, dispatch_read_tls, &tls_in->socket);
        if (event_add(conn_info->event, NULL) == -1) {
                DPRINTF("Failure in event_add()\n");
        }
        DPRINTF("established TLS connection from %s\n", conn_info->hostname);
        
        /*
         * We could also listen to EOF kevents -- but I do not think
         * that would be useful, because we still had to read() the buffer
         * before closing the socket.
         */
}

/*
 * Dispatch routine for accepting TCP connections and preparing
 * the tls_conn_settings object for a following SSL_accept().
 * TODO: how do we handle fingerprint auth for incoming?
 *       set up a list of tls_conn_settings and pick one matching the hostname?
 */
void
dispatch_accept_socket(int fd, short event, void *ev)
{
#ifdef LIBWRAP
        struct request_info req;
#endif
        struct sockaddr_storage frominet;
        socklen_t addrlen;
        int newsock, rc;
        SSL *ssl;
        struct tls_conn_settings *conn_info;
        char hbuf[NI_MAXHOST];
        char *peername;

        DPRINTF("incoming TCP connection\n");
        if (!tls_opt.global_TLS_CTX) {
                logerror("global_TLS_CTX not initialized!");
                return;
        }

        addrlen = sizeof(frominet);
        if ((newsock = accept(fd, (struct sockaddr *)&frominet, &addrlen)) == -1) {
                logerror("Error in accept(): %s", strerror(errno));
                return;
        }
        /* TODO: do we want an IP or a hostname? maybe even both? */
        if ((rc = getnameinfo((struct sockaddr *)&frominet, addrlen, hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST|NI_NUMERICSERV))) {
                DPRINTF("could not get peername: %s", gai_strerror(rc));
                peername = NULL;
        }
        else {
                if (!(peername = malloc(strlen(hbuf)+1))) {
                        logerror("Unable to allocate memory");
                        shutdown(newsock, SHUT_RDWR);
                        close(newsock);
                        return;
                }
                (void)strlcpy(peername, hbuf, strlen(hbuf)+1);
        }

#ifdef LIBWRAP
        request_init(&req, RQ_DAEMON, "syslogd", RQ_FILE, newsock, NULL);
        fromhost(&req);
        if (!hosts_access(&req)) {
                logerror("access from %s denied by hosts_access", peername);
                shutdown(newsock, SHUT_RDWR);
                close(newsock);
                return;
        }
#endif

        if (!(conn_info = calloc(1, sizeof(*conn_info)))
         || !(conn_info->event = calloc(1, sizeof(*conn_info->event)))) {
                free(conn_info);
                logerror("Unable to allocate memory");
                return;
        }

        if ((fcntl(newsock, F_SETFL, O_NONBLOCK)) == -1) {
                DPRINTF("Unable to fcntl(sock, O_NONBLOCK): %s\n", strerror(errno));
        }
        
        if (!(ssl = SSL_new(tls_opt.global_TLS_CTX))) {
                DPRINTF("Unable to establish TLS: %s\n", ERR_error_string(ERR_get_error(), NULL));
                close(newsock);
                return;                                
        }
        if (!SSL_set_fd(ssl, newsock)) {
                DPRINTF("Unable to connect TLS to socket %d: %s\n", newsock, ERR_error_string(ERR_get_error(), NULL));
                SSL_free(ssl);
                close(newsock);
                return;
        }
        /* store connection details inside ssl object, used to verify
         * cert and immediately match against hostname */
        conn_info->hostname = peername;
        conn_info->x509verify = X509VERIFY_NONE;
        conn_info->sslptr = ssl;
        SSL_set_app_data(ssl, conn_info);
        SSL_set_accept_state(ssl);

        DPRINTF("socket connection from %s accept()ed with fd %d, " \
                "calling SSL_accept()...\n",  peername, newsock);
        
        dispatch_accept_tls(newsock, 0, conn_info);
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
/* uses the fd as passed by reference in ev */
void
dispatch_read_tls(int fd_lib, short event, void *ev)
{
        int error, tries;
        int_fast16_t rc;
        struct TLS_Incoming_Conn *c;
        int fd = *(int*) ev;

        DPRINTF("active TLS socket %d\n", fd);
        
        SLIST_FOREACH(c, &TLS_Incoming_Head, entries) {
                DPRINTF("look at tls_in@%p with fd %d\n", c, c->socket);
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
        DPRINTF("incoming status is msg_start %d, msg_len %d, pos %d\n",
                c->cur_msg_start, c->cur_msg_len, c->read_pos);
        DPRINTF("calling SSL_read(%p, %p, %d)\n", c->ssl,
                &(c->inbuf[c->read_pos]), c->inbuflen - c->read_pos);
        rc = SSL_read(c->ssl, &(c->inbuf[c->read_pos]), c->inbuflen - c->read_pos);
        if (rc <= 0) {
                error = tls_examine_error("SSL_read()", c->ssl, c->tls_conn, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++tries < TLS_NONBLOCKING_TRIES) {
                                        usleep(TLS_NONBLOCKING_USEC);
                                        goto try_SSL_read;
                                }
                                /* problem: we cannot use c->tls_conn->event,
                                 * which is still used for fd EV_READ */
                                schedule_event(&c->tls_conn->event2,
                                        &((struct timeval){0, TLS_RETRY_KEVENT_USEC}),
                                        dispatch_read_tls, &fd);
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
                DPRINTF("SSL_read() returned %d\n", rc);
                c->errorcount = 0;
                c->read_pos += rc;
        }
        tls_split_messages(c);
}

/* moved message splitting out of dispatching function.
 * now we can call it recursively.
 * 
 * TODO: the code for oversized messages still needs testing,
 * especially for the skipping case.
 */
void
tls_split_messages(struct TLS_Incoming_Conn *c)
{
/* define only to make it better readable */
#define MSG_END_OFFSET (c->cur_msg_start + c->cur_msg_len)
        unsigned int offset = 0;
        unsigned int msglen = 0;
        char *newbuf;
        
        DPRINTF("tls_split_messages() -- incoming status is " \
                "msg_start %d, msg_len %d, pos %d\n",
                c->cur_msg_start, c->cur_msg_len, c->read_pos);

        if(c->closenow && !c->read_pos) {
                /* close socket */
                free_tls_conn(c->tls_conn);
                FREEPTR(c->inbuf);
                SLIST_REMOVE(&TLS_Incoming_Head, c, TLS_Incoming_Conn, entries);
                free(c);
                return;
        }
        if (!c->read_pos)
                return;
                
        if (c->dontsave && c->read_pos < MSG_END_OFFSET) {
                c->cur_msg_len -= c->read_pos;
                c->read_pos = 0;
        } else if (c->dontsave && c->read_pos == MSG_END_OFFSET) {
                c->cur_msg_start = c->cur_msg_len = c->read_pos = 0;
                c->dontsave = false;
        } else if (c->dontsave && c->read_pos > MSG_END_OFFSET) {
                /* move remaining input to start of buffer */
                DPRINTF("move inbuf of length %d by %d chars\n",
                        c->read_pos - (MSG_END_OFFSET),
                        MSG_END_OFFSET);
                memmove(&c->inbuf[0],
                        &c->inbuf[MSG_END_OFFSET],
                        c->read_pos - (MSG_END_OFFSET));
                c->read_pos -= (MSG_END_OFFSET);
                c->cur_msg_start = c->cur_msg_len = 0;
                c->dontsave = false;
        }
        if (c->read_pos < MSG_END_OFFSET) {
                return;
        }
                
        /* read length prefix, always at start of buffer */
        while (isdigit((unsigned char)c->inbuf[offset])
                && offset < c->read_pos) {
                msglen *= 10;
                msglen += c->inbuf[offset] - '0';
                offset++;
        }
        if (offset == c->read_pos) {
                /* next invocation will have more data */
                return;
        }
        if (c->inbuf[offset] == ' ') {
                c->cur_msg_len = msglen;
                c->cur_msg_start = offset + 1;
                if (MSG_END_OFFSET > c->inbuflen) {
                        newbuf = realloc(c->inbuf, MSG_END_OFFSET);
                        if (newbuf) {
                                DPRINTF("Reallocated inbuf\n");
                                c->inbuflen = MSG_END_OFFSET;
                                c->inbuf = newbuf;
                        } else {
                                logerror("Couldn't reallocate buffer, will skip this message");
                                c->dontsave = true;
                                c->cur_msg_len -= c->read_pos;
                                c->cur_msg_start = 0;
                                c->read_pos = 0;
                        }
                }
        } else {
                /* found non-digit in prefix */
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
        } 
        /* read one syslog message */        
        if (c->read_pos >= MSG_END_OFFSET) {
                /* process complete msg */
                (void)memcpy(linebuf, &c->inbuf[c->cur_msg_start], c->cur_msg_len);
                linebuf[c->cur_msg_len] = '\0';
                printline(c->tls_conn->hostname, linebuf, RemoteAddDate ? ADDDATE : 0);

                if (MSG_END_OFFSET == c->read_pos) {
                        /* no unprocessed data in buffer --> reset to empty */
                        c->cur_msg_start = c->cur_msg_len = c->read_pos = 0;
                } else {
                        /* move remaining input to start of buffer */
                        DPRINTF("move inbuf of length %d by %d chars\n",
                                c->read_pos - (MSG_END_OFFSET),
                                MSG_END_OFFSET);
                        memmove(&c->inbuf[0],
                                &c->inbuf[MSG_END_OFFSET],
                                c->read_pos - (MSG_END_OFFSET));
                        c->read_pos -= (MSG_END_OFFSET);
                        c->cur_msg_start = c->cur_msg_len = 0;
                }
        }
        DPRINTF("return with status: msg_start %d, msg_len %d, pos %d\n",
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
        int i, retry, rc, error;
        char *tlslineptr = line;
        size_t tlslen = len;
        
        DPRINTF("tls_send(f=%p, line=\"%.*s...\", len=%d) to %sconnected dest.\n",
                f, (len>24 ? 24 : len), line, len,
                f->f_un.f_tls.tls_conn->sslptr ? "" : "un");

        if (!f->f_un.f_tls.tls_conn->sslptr) {
                return false;
        }

        /* simple sanity check for length prefix */
        for (i = 0; isdigit((int)line[i]); i++)
                /* skip digits */;
        if (line[i] != ' ') {
                DPRINTF("malformed TLS line: %.*s", (len>24 ? 24 : len), line);
                /* silently discard malformed line, re-queuing it would only cause a loop */
                return true;
        }

        /* 
         * what happens if a peer does not acknowledge a TCP/TS transmission?
         * --> that will hang our syslogd.
         * 
         * should I make outgoing sockets non-blocking?
         * --> depends on how much we trust the logserver
         *     (to be non-malicious _and_ bug-free)
         * --> TODO
         */
        retry = 0;
try_SSL_write:
        rc = SSL_write(f->f_un.f_tls.tls_conn->sslptr, tlslineptr, tlslen);
        if (0 >= rc) {
                error = tls_examine_error("SSL_write()",
                        f->f_un.f_tls.tls_conn->sslptr,
                        f->f_un.f_tls.tls_conn, rc);
                switch (error) {
                        case TLS_RETRY:
                                if (++retry < TLS_NONBLOCKING_TRIES) {
                                        usleep(TLS_NONBLOCKING_USEC);
                                        goto try_SSL_write;
                                }
                                break;
                        case TLS_TEMP_ERROR:
                                if ((f->f_un.f_tls.tls_conn->errorcount)++ < TLS_MAXERRORCOUNT)
                                        break;
                                /* else fallthrough */
                        case TLS_PERM_ERROR:
                                /* Reconnect after x seconds  */
                                schedule_event(&f->f_un.f_tls.tls_conn->event,
                                        &((struct timeval){0, TLS_RECONNECT_SEC}),
                                        tls_reconnect, f);
                                break;
                        default:break;
                }
                free_tls_sslptr(f->f_un.f_tls.tls_conn);
                return false;
        }
        else if (rc < tlslen) {
        DPRINTF("TLS: SSL_write() wrote %d out of %d bytes\n",
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
        if (tls_conn->port)        free(tls_conn->port);
        if (tls_conn->subject)     free(tls_conn->subject);
        if (tls_conn->hostname)    free(tls_conn->hostname);
        if (tls_conn->certfile)    free(tls_conn->certfile);
        if (tls_conn->fingerprint) free(tls_conn->fingerprint);
        if (tls_conn->event)       free(tls_conn->event);
        if (tls_conn->event2)      free(tls_conn->event2);
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
                        DPRINTF("Closed TLS connection to %s\n", tls_conn->hostname);
                } else { 
                        DPRINTF("Unable to cleanly shutdown TLS connection to %s\n", tls_conn->hostname);
                }        
                if (shutdown(sock, SHUT_RDWR))
                        DPRINTF("Unable to cleanly shutdown TCP socket %d: %s\n", sock, strerror(errno));
                if (close(sock))
                        DPRINTF("Unable to cleanly close socket %d: %s\n", sock, strerror(errno));
                SSL_free(tls_conn->sslptr);
                tls_conn->sslptr = NULL;
        }
}

