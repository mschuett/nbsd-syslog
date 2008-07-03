/*
 * tls_stuff.c TLS related code for syslogd
 *
 * implements the TLS init and handshake callbacks with all required
 * checks from http://tools.ietf.org/html/draft-ietf-syslog-transport-tls-12
 * (without hostname wildcards)
 *
 * TODO: trans-port-tls12+ (Mail from jsalowey on 080523) requires
 *       server and client to be able to generate self-signed certificates
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
extern char  *linebuf;
extern size_t linebufsize;
extern int    RemoteAddDate; 
extern char  *timestamp;

extern void    logerror(const char *, ...);
extern void    printline(char *, char *, int);
extern void    die(int fd, short event, void *ev);
extern struct event *allocev(void);
extern void    send_queue(struct filed *);
extern void schedule_event(struct event **, struct timeval *, void (*)(int, short, void *), void *);
extern char *make_timestamp(bool);
extern struct filed *get_f_by_conninfo(struct tls_conn_settings *conn_info);
extern void tls_send_msg_free(struct tls_send_msg *msg);
extern bool message_queue_add(struct filed *, struct buf_msg *);

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

        if (keyfilename && certfilename) {
                /* TODO: first check if files exist */
                if (tls_opt.gen_cert) {
                        EVP_PKEY *pkey = NULL;
                        X509     *cert = NULL;
        
                        logerror("Generating a self-signed certificate and "
                                "writing files \"%s\" and \"%s\"",
                                keyfilename, certfilename);
                        mk_x509_cert(&cert, &pkey, TLS_GENCERT_BITS,
                                TLS_GENCERT_SERIAL, TLS_GENCERT_DAYS);
                        write_x509files(pkey, cert,
                                keyfilename, certfilename);
                }
        }

        /* load keys and certs here */
        if (keyfilename && certfilename) {
                if (!(SSL_CTX_use_PrivateKey_file(ctx, keyfilename, SSL_FILETYPE_PEM)
                    && SSL_CTX_use_certificate_chain_file(ctx, certfilename))) {
                        logerror("Unable to get private key and "
                                "certificate from files \"%s\" and \"%s\"",
                                keyfilename, certfilename);
                        ERR_print_errors_fp(stderr);
                        die(0,0,NULL);  /* any better reaction? */
                }
                if (!SSL_CTX_check_private_key(ctx)) {
                        logerror("Private key \"%s\" does not match "
                                "certificate \"%s\"",
                                keyfilename, certfilename);
                        ERR_print_errors_fp(stderr);
                        die(0,0,NULL);
                } else {
                        char *fp = NULL, *cn = NULL;
                        X509 *cert;
                        
                        if (!read_certfile(&cert, certfilename))
                                fp = cn = NULL;
                        else {
                                get_fingerprint(cert, &fp, NULL);
                                get_commonname(cert, &cn);
                        }
                        DPRINTF(D_TLS, "loaded and checked own certificate\n");
                        logerror("Initialize SSL context using library \"%s\"."
                                " Load certificate from file \"%s\" with CN "
                                "\"%s\" and fingerprint \"%s\"",
                                SSLeay_version(SSLEAY_VERSION),
                                certfilename, cn, fp);
                        free(cn);
                        free(fp);
                }
        }
        if (CAfile || CApath) {
                if (!SSL_CTX_load_verify_locations(ctx, CAfile, CApath)) {
                	if (CAfile && CApath)
	                        logerror("unable to load trust anchors from "
	                        	"\"%s\" and \"%s\"\n", CAfile, CApath);
	                else
	                        logerror("unable to load trust anchors from "
	                        	"\"%s\"\n", CAfile ? CAfile : CApath);
                        ERR_print_errors_fp(stderr);
                } else {
                        DPRINTF(D_TLS, "loaded trust anchors\n");
                }
        }
        /* peer verification */
        /* 
         * TODO: is it possible to have one destination with and one
         * without verification?
         * --> no. there is only SSL_CTX_set_verify() but no SSL_set_verify()
         *     so the settings are global for all connections.
         * 
         * --> the latest draft mandates the use of certificates for client and server.
         *     so the option X509VERIFY_NONE should give a warning and the
         *     practically useless X509VERIFY_IFPRESENT can be eliminated
         * (http://tools.ietf.org/html/draft-ietf-syslog-transport-tls-13#section-4.2.1)
         * 
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

        DPRINTF(D_TLS, "get_fingerprint(cert, %p, \"%s\")\n", returnstring, alg_name);
        *returnstring = NULL;
        if ((alg_name && !(digest = (EVP_MD *) EVP_get_digestbyname(alg_name)))
            || (!alg_name && !(digest = (EVP_MD *) 
                             EVP_get_digestbyname(DEFAULT_FINGERPRINT_ALG)))) {
                DPRINTF(D_TLS, "unknown digest algorithm %s\n", alg_name);
                
                return false;
        }
        if (!X509_digest(cert, digest, md, &len)) {
                DPRINTF(D_TLS, "cannot get %s digest\n", alg_name);
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
        return true;
}

/* 
 * gets first CN from cert in returnstring (has to be freed by caller)
 * on failure it returns false and *returnstring is NULL
 */
bool
get_commonname(X509 *cert, char **returnstring)
{
        X509_NAME *x509name;
        X509_NAME_ENTRY *entry;
        unsigned char *ubuf;
        int len, i;
        
        x509name = X509_get_subject_name(cert);
        i = X509_NAME_get_index_by_NID(x509name, NID_commonName, -1);
        if (i != -1) {
                entry = X509_NAME_get_entry(x509name, i);
                len = ASN1_STRING_to_UTF8(&ubuf, X509_NAME_ENTRY_get_data(entry));
                if (len > 0
                 && (*returnstring = malloc(len+1))) {
                        strlcpy(*returnstring, (const char*)ubuf, len+1);
                        OPENSSL_free(ubuf);
                        return true;
                }
                OPENSSL_free(ubuf);
        }
        *returnstring = NULL;
        return false;
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
match_hostnames(X509 *cert, const char *hostname, const char *subject)
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

        DPRINTF((D_TLS|D_CALL), "match_hostnames(%p, \"%s\", \"%s\")\n",
            cert, hostname, subject);

        /* see if hostname is an IP */
        if ((subject  && (asn1_ip = a2i_IPADDRESS(subject )))
         || (hostname && (asn1_ip = a2i_IPADDRESS(hostname))))
                /* nothing */;
        else
                asn1_ip = NULL;

        if (!(gennames = X509_get_ext_d2i(cert, NID_subject_alt_name, &crit, &idx))) {
                DPRINTF(D_TLS, "X509_get_ext_d2i() returned (%p,%d,%d) --> no subjectAltName\n", gennames, crit, idx);
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
                                if (!strncasecmp(subject, buf, len)
                                    || !strncasecmp(hostname, buf, len))
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
                        DPRINTF(D_TLS, "found CN: %.*s\n", len, ubuf);
                        /* hostname */
                        if ((subject && !strncasecmp(subject, (const char*)ubuf, len))
                            || (hostname && !strncasecmp(hostname, (const char*)ubuf, len))) {
                                OPENSSL_free(ubuf);
                                return true;
                        }
                        OPENSSL_free(ubuf);
                        /* IP -- convert to ASN1_OCTET_STRING and compare then
                         * so that "10.1.2.3" and "10.01.02.03" are equal */
                        if ((asn1_ip)
                            && subject
                            && (asn1_cn_ip = a2i_IPADDRESS(subject))
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
match_fingerprint(const X509 *cert, const char *fingerprint)
{
#define MAX_ALG_NAME_LENGTH 8
        char alg[MAX_ALG_NAME_LENGTH];
        char *certfingerprint;
        char *p;
        const char *q;

        DPRINTF((D_TLS|D_CALL), "match_fingerprint(%p, \"%s\")\n", cert, fingerprint);
        if (!fingerprint)
                return false;

        /* get algorithm */
        p = alg;
        q = fingerprint;
        while (*q != ':' && *q != '\0' && p < alg + MAX_ALG_NAME_LENGTH)
                *p++ = *q++;
        *p = '\0';

        if (!get_fingerprint(cert, &certfingerprint, alg)) {
                DPRINTF(D_TLS, "cannot get %s digest\n", alg);
                return false;
        }
        if (strncmp(certfingerprint, fingerprint, strlen(certfingerprint))) {
                DPRINTF(D_TLS, "fail: fingerprints do not match\n");
                free(certfingerprint);
                return false;
        }
        DPRINTF(D_TLS, "accepted: fingerprints match\n");
        free(certfingerprint);
        return true;
}

/*
 * check if certificate matches given certificate file
 */
bool
match_certfile(const X509 *cert, const char *certfilename)
{
        X509 *add_cert;
        bool rc = false;
        errno = 0;
        
        if (read_certfile(&add_cert, certfilename)) {
                rc = X509_cmp(cert, add_cert);
                OPENSSL_free(add_cert);
                DPRINTF(D_TLS, "X509_cmp() returns %d\n", rc);
        }
        return rc;
}

/*
 * reads X.509 certificate from file
 * caller has to free it later with 'OPENSSL_free(cert);'
 */
bool
read_certfile(X509 **cert, const char *certfilename)
{
        FILE *certfile;
        errno = 0;
        
        DPRINTF((D_TLS|D_CALL), "read_certfile(%p, \"%s\")\n", cert, certfilename);
        if (!cert || !certfilename)
                return false;

        if (!(certfile = fopen(certfilename, "rb"))) {
                logerror("Unable to open certificate file: %s", certfilename);
                return false;
        }

        /* either PEM or DER */
        if (!(*cert = PEM_read_X509(certfile, NULL, NULL, NULL))
         && !(*cert = d2i_X509_fp(certfile, NULL))) {
                DPRINTF((D_TLS), "Unable to read certificate from %s\n", certfilename);
                (void)fclose(certfile);
                return false;
        }
        else {
                DPRINTF((D_TLS), "Read certificate from %s\n", certfilename);
                (void)fclose(certfile);
                return true;
        }
}

/* used for incoming connections in check_peer_cert() */
int
accept_cert(const char* reason, struct tls_conn_settings *conn_info, char *cur_fingerprint, char *cur_subjectline)
{
        if (cur_fingerprint)
                conn_info->fingerprint = cur_fingerprint;
        if (cur_subjectline)
                conn_info->subject = cur_subjectline;

        logerror("Established connection and accepted %s certificate "
                "from %s due to %s. Subject is \"%s\", fingerprint is "
                "\"%s\"", conn_info->incoming ? "server" : "client", 
                conn_info->hostname, reason, cur_subjectline, cur_fingerprint);
        return 1;        
}
int
deny_cert(struct tls_conn_settings *conn_info, char *cur_fingerprint, char *cur_subjectline)
{
        logerror("Deny %s certificate from %s. "
                "Subject is \"%s\", fingerprint is \"%s\"",
                conn_info->incoming ? "server" : "client", 
                conn_info->hostname,
                cur_subjectline, cur_fingerprint);
        FREEPTR(cur_fingerprint);
        FREEPTR(cur_subjectline);
        return 0;        
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
        char *cur_subjectline = NULL;
        char *cur_fingerprint = NULL;
        char cur_issuerline[256];
        SSL *ssl;
        X509 *cur_cert;
        int cur_err, cur_depth;
        struct tls_conn_settings *conn_info;
        struct peer_cred *cred, *tmp_cred;
        
        /* read context info */
        cur_cert = X509_STORE_CTX_get_current_cert(ctx);
        cur_err = X509_STORE_CTX_get_error(ctx);
        cur_depth = X509_STORE_CTX_get_error_depth(ctx);
        ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
        conn_info = SSL_get_app_data(ssl);

        /* some info */
        (void)get_commonname(cur_cert, &cur_subjectline);
        (void)get_fingerprint(cur_cert, &cur_fingerprint, NULL);
        DPRINTF((D_TLS|D_CALL), "check cert for connection with %s. "
                "depth is %d, preverify is %d, subject is %s, fingerprint "
                "is %s, conn_info@%p\n", conn_info->hostname, cur_depth, 
                preverify_ok, cur_subjectline, cur_fingerprint, conn_info);
        if (Debug && !preverify_ok) {
                DPRINTF(D_TLS, "openssl verify error:num=%d:%s:depth=%d:%s\t\n", cur_err,
                    X509_verify_cert_error_string(cur_err), cur_depth, cur_subjectline);
                if (cur_err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) {
                        X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), cur_issuerline, sizeof(cur_issuerline));
                        DPRINTF(D_TLS, "openssl verify error:missing cert for issuer= %s\n", cur_issuerline);
                }
        }

        /* 
         * quite a lot of variables here,
         * the big if/elseif covers all possible combinations. 
         *
         * here is a list, ordered like the conditions below:
         * - conn_info->x509verify
         *   X509VERIFY_NONE:      do not verify certificates,
         *                         only log its subject and fingerprint
         *   X509VERIFY_IFPRESENT: if we got her, then a cert is present,
         *                         so check it normally
         *   X509VERIFY_ALWAYS:    normal certificate check
         * - cur_depth:
         *   > 0:  peer provided CA cert. remember if its valid,
         *         but always accept, because most checks work on depth 0
         *   == 0: the peer's own cert. check this for final decision
         * - preverify_ok:
         *   true:  valid certificate chain from a trust anchor to this cert 
         *   false: no valid and trusted certificate chain
         * - conn_info->incoming:
         *   true:  we are the server, means we authenticate against all
         *          allowed attributes in conn_info->tls_opt
         *   false: otherwise we are client and conn_info has all attributes to check
         * - conn_info->fingerprint (only if !conn_info->incoming)
         *   NULL:  no fingerprint configured, only check certificate chain
         *   !NULL: a peer cert with this fingerprint is trusted
         * 
         */
        /* shortcut */
        if (cur_depth != 0) {
                FREEPTR(cur_fingerprint);
                FREEPTR(cur_subjectline);
                return 1;
        }

        if (conn_info->x509verify == X509VERIFY_NONE)
                return accept_cert("disabled verification", conn_info,
                        cur_fingerprint, cur_subjectline);

        /* implicit: (cur_depth == 0) && (conn_info->x509verify != X509VERIFY_NONE) */
        if (conn_info->incoming) {
                /* is preverify_ok important here? */
                /* now check allowed client fingerprints/certs */
                SLIST_FOREACH(cred, &conn_info->tls_opt->fprint_head, entries) {
                        conn_info->fingerprint = cred->data;
                        if (match_fingerprint(cur_cert, conn_info->fingerprint)) {
                                return accept_cert("matching fingerprint",
                                        conn_info, cur_fingerprint, cur_subjectline);
                        }
                        conn_info->fingerprint = NULL;
                }
                SLIST_FOREACH_SAFE(cred, &conn_info->tls_opt->cert_head, entries, tmp_cred) {
                        if (match_certfile(cur_cert, cred->data))
                                return accept_cert("matching certfile", conn_info,
                                        cur_fingerprint, cur_subjectline);
                }
                return deny_cert(conn_info, cur_fingerprint, cur_subjectline);
        }

        /* implicit: (cur_depth == 0) && (conn_info->x509verify != X509VERIFY_NONE) && !conn_info->incoming */
        if (!conn_info->incoming && preverify_ok) {
                /* certificate chain OK. check subject/hostname */
                if (match_hostnames(cur_cert, conn_info->hostname, conn_info->subject))
                        return accept_cert("matching hostname/subject", conn_info,
                                        cur_fingerprint, cur_subjectline);
                else
                        return deny_cert(conn_info, cur_fingerprint, cur_subjectline);
        } else if (!conn_info->incoming && !preverify_ok) {
                /* certificate chain not OK. check fingerprint/subject/hostname */
                if (match_fingerprint(cur_cert, conn_info->fingerprint))
                        return accept_cert("matching fingerprint", conn_info,
                                        cur_fingerprint, cur_subjectline);
                else if (match_certfile(cur_cert, conn_info->certfile))
                        return accept_cert("matching certfile", conn_info,
                                        cur_fingerprint, cur_subjectline);
                else if (match_hostnames(cur_cert, conn_info->hostname, conn_info->subject))
                        return accept_cert("matching hostname/subject", conn_info,
                                        cur_fingerprint, cur_subjectline);
                else
                        return deny_cert(conn_info, cur_fingerprint, cur_subjectline);
        }
        return 0;
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

        if(tls_opt.server)
                return(NULL);

        if (!tls_opt.global_TLS_CTX)
                tls_opt.global_TLS_CTX = init_global_TLS_CTX(tls_opt.keyfile,
                                        tls_opt.certfile, tls_opt.CAfile,
                                        tls_opt.CAdir, tls_opt.x509verify);


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
                EVENT_ADD(s->ev);

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
 * Dispatch routine for non-blocking SSL_connect()
 * Has to be idempotent in case of TLS_RETRY (~ EAGAIN),
 * so we can continue a slow handshake.
 */
void
dispatch_SSL_connect(int fd, short event, void *arg)
{
        struct tls_conn_settings *conn_info = (struct tls_conn_settings *) arg;
        SSL *ssl = conn_info->sslptr;
        int rc, error;

        DPRINTF((D_TLS|D_CALL), "dispatch_SSL_connect(conn_info@%p, fd %d)\n", conn_info, fd);
        assert(conn_info->state == ST_TCP_EST
            || conn_info->state == ST_CONNECTING);

        ST_CHANGE(conn_info->state, ST_CONNECTING);
        rc = SSL_connect(ssl);
        if (0 >= rc) {
                error = tls_examine_error("SSL_connect()",
                        conn_info->sslptr, NULL, rc);
                switch (error) {
                        /* no need to change retrying-bit, as retrying
                         * is the only way to dispatch this function
                         */
                        case TLS_RETRY_READ:
                                event_set(conn_info->retryevent, fd, EV_READ,
                                        dispatch_SSL_connect, conn_info);
                                EVENT_ADD(conn_info->retryevent);
                                break;
                        case TLS_RETRY_WRITE:
                                event_set(conn_info->retryevent, fd, EV_WRITE,
                                        dispatch_SSL_connect, conn_info);
                                EVENT_ADD(conn_info->retryevent);
                                break;
                        default: /* should not happen,
                                  * ... but does if the cert is not accepted */
                                logerror("Cannot establish TLS connection "
                                        "to \"%s\" -- wrong certificate "
                                        "configured?", conn_info->hostname);
                                ST_CHANGE(conn_info->state, ST_NONE);
                                conn_info->retrying = false;
                                conn_info->reconnect = 5*TLS_RECONNECT_SEC;
                                schedule_event(&conn_info->event,
                                        &((struct timeval)
                                        {conn_info->reconnect, 0}),
                                        tls_reconnect, conn_info);
                                break;
                }
                return;
        }
        /* else */
        ST_CHANGE(conn_info->state, ST_TLS_EST);
        conn_info->retrying = false;
        conn_info->reconnect = TLS_RECONNECT_SEC;
        event_set(conn_info->event, fd, EV_READ, dispatch_eof_tls, conn_info);
        EVENT_ADD(conn_info->event);
        
        DPRINTF(D_TLS, "TLS connection established.\n");

        /* not very elegant but maybe better than
         * using filed pointers everywhere (?) */
        send_queue(get_f_by_conninfo(conn_info));
}

/*
 * establish TLS connection 
 */
bool
tls_connect(SSL_CTX *context, struct tls_conn_settings *conn_info)
{
        struct addrinfo hints, *res, *res1;
        int    error, rc, sock;
        const int one = 1;
        char   buf[MAXLINE];
        SSL    *ssl = NULL;
        
        DPRINTF((D_TLS|D_CALL), "tls_connect(conn_info@%p)\n", conn_info);
        assert(conn_info->state == ST_NONE);
        
        if(!tls_opt.global_TLS_CTX)
        tls_opt.global_TLS_CTX = init_global_TLS_CTX(
                tls_opt.keyfile, tls_opt.certfile,
                tls_opt.CAfile, tls_opt.CAdir,
                tls_opt.x509verify);
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = 0;
        hints.ai_flags = AI_CANONNAME;
        error = getaddrinfo(conn_info->hostname, (conn_info->port ? conn_info->port : SERVICENAME), &hints, &res);
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
                        DPRINTF(D_NET, "Unable to open socket.\n");
                        continue;
                }
                if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
                        DPRINTF(D_NET, "Unable to setsockopt(): %s\n", strerror(errno));
                }
                if (connect(sock, res1->ai_addr, res1->ai_addrlen) == -1) {
                        DPRINTF(D_NET, "Unable to connect() to %s: %s\n", res1->ai_canonname, strerror(errno));
                        close(sock);
                        sock = -1;
                        continue;
                }
                ST_CHANGE(conn_info->state, ST_TCP_EST);

                if (!(ssl = SSL_new(context))) {
                        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
                        DPRINTF(D_TLS, "Unable to establish TLS: %s\n", buf);
                        close(sock);
                        sock = -1;
                        ST_CHANGE(conn_info->state, ST_NONE);
                        continue;                                
                }
                if (!SSL_set_fd(ssl, sock)) {
                        ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
                        DPRINTF(D_TLS, "Unable to connect TLS to socket: %s\n", buf);
                        FREE_SSL(ssl);
                        close(sock);
                        sock = -1;
                        ST_CHANGE(conn_info->state, ST_NONE);
                        continue;
                }
                
                SSL_set_app_data(ssl, conn_info);
                SSL_set_connect_state(ssl);
                while ((rc = ERR_get_error())) {
                        ERR_error_string_n(rc, buf, sizeof(buf));
                        DPRINTF(D_TLS, "Found SSL error in queue: %s\n", buf);
                }
                errno = 0;  /* reset to be sure we get the right one later on */
                
                if ((fcntl(sock, F_SETFL, O_NONBLOCK)) == -1) {
                        DPRINTF(D_NET, "Unable to fcntl(sock, O_NONBLOCK): %s\n", strerror(errno));
                }

                /* now we have a TCP connection, so assume we can
                 * use that and do not have to try another res */
                conn_info->sslptr = ssl;

                assert(conn_info->state == ST_TCP_EST);
                assert(!conn_info->event);
                assert(!conn_info->retryevent);
                conn_info->event = allocev();
                conn_info->retryevent = allocev();

                freeaddrinfo(res);
                dispatch_SSL_connect(sock, 0, conn_info);
                return true;
        }
        /* still no connection after for loop */
        DPRINTF((D_TLS|D_NET), "Unable to establish a TCP connection to %s\n", conn_info->hostname);
        freeaddrinfo(res);

        assert(conn_info->state == ST_NONE);
        if (sock != -1)
                close(sock);
        if (ssl) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
        }
        return false;
}

int
tls_examine_error(const char *functionname, const SSL *ssl, struct tls_conn_settings *tls_conn, const int rc)
{
        int ssl_error, err_error;
        
        ssl_error = SSL_get_error(ssl, rc);
        DPRINTF(D_TLS, "%s returned rc %d and error %s: %s\n", functionname,
                rc, SSL_ERRCODE[ssl_error], ERR_error_string(ssl_error, NULL));
        switch (ssl_error) {
                case SSL_ERROR_WANT_READ:
                        return TLS_RETRY_READ;
                        break;
                case SSL_ERROR_WANT_WRITE:
                        return TLS_RETRY_WRITE;
                        break;
                case SSL_ERROR_SYSCALL:
                        DPRINTF(D_TLS, "SSL_ERROR_SYSCALL: ");
                        err_error = ERR_get_error();
                        if ((rc == -1) && (err_error == 0)) {
                                DPRINTF(D_TLS, "socket I/O error: %s\n", strerror(errno));
                        } else if ((rc == 0) && (err_error == 0)) {
                                DPRINTF(D_TLS, "unexpected EOF from %s\n", tls_conn ? tls_conn->hostname : NULL);
                        } else {
                                DPRINTF(D_TLS, "no further info\n");
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
        /* TODO: is this ever reached? */
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
copy_config_value_quoted(const char *keyword, char **mem, char **p)
{
        char *q;
        if (strncasecmp(*p, keyword, strlen(keyword)))
                return false;
        q = *p += strlen(keyword);
        if (!(q = strchr(*p, '"'))) {
                logerror("unterminated \"\n");
                return false;
        }
        if (!(copy_string(mem, *p, q)))
                return false;
        *p = ++q;
        return true;
}

/* for config file:
 * following = required but whitespace allowed, quotes optional
 * if numeric, then conversion to integer and no memory allocation 
 */
bool
copy_config_value(const char *keyword, char **mem, char **p, const char *file, const int line)
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
        
        return copy_config_value_word(mem, p);
}

/* copy next parameter from a config line */
bool
copy_config_value_word(char **mem, char **p)
{
        char *q;
        while (isspace((unsigned char)**p))
                *p += 1;
        if (**p == '"')
                return copy_config_value_quoted("\"", mem, p);

        /* without quotes: find next whitespace or end of line */
        (void) ((q = strchr(*p, ' ')) || (q = strchr(*p, '\t'))
          || (q = strchr(*p, '\n')) || (q = strchr(*p, '\0')));

        if (q-*p == 0
         || !(copy_string(mem, *p, q)))
                return false;

        *p = ++q;
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
        f->f_un.f_tls.tls_conn->x509verify = X509VERIFY_ALWAYS;
        f->f_un.f_tls.tls_conn->reconnect = TLS_RECONNECT_SEC;

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
                        if (copy_config_value_quoted("subject=\"", &(f->f_un.f_tls.tls_conn->subject), &p)
                            || copy_config_value_quoted("fingerprint=\"", &(f->f_un.f_tls.tls_conn->fingerprint), &p)
                            || copy_config_value_quoted("cert=\"", &(f->f_un.f_tls.tls_conn->certfile), &p)) {
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
        DPRINTF((D_TLS|D_PARSE), "got TLS config: host %s, port %s, subject: %s\n",
                f->f_un.f_tls.tls_conn->hostname,
                f->f_un.f_tls.tls_conn->port,
                f->f_un.f_tls.tls_conn->subject);
        return true;
}

/*
 * Dispatch routine (triggered by timer) to reconnect to a lost TLS server
 */
#define RECONNECT_BACKOFF_FACTOR 15/10
#define RECONNECT_BACKOFF(x)     (x) = (x) * RECONNECT_BACKOFF_FACTOR
void
tls_reconnect(int fd, short event, void *arg)
{
        struct tls_conn_settings *conn_info = (struct tls_conn_settings *) arg;

        DPRINTF((D_TLS|D_CALL|D_EVENT), "tls_reconnect(conn_info@%p, "
                "server %s)\n", conn_info, conn_info->hostname);
        assert(conn_info->state == ST_NONE);
        FREEPTR(conn_info->event);
        FREEPTR(conn_info->retryevent);

        if (!tls_connect(tls_opt.global_TLS_CTX, conn_info)) {
                logerror("Unable to connect to TLS server %s, "
                        "try again in %d sec", conn_info->hostname,
                        conn_info->reconnect);
                /* TODO: slow backoff algorithm */
                schedule_event(&conn_info->event,
                        &((struct timeval){conn_info->reconnect, 0}),
                        tls_reconnect, conn_info);
                RECONNECT_BACKOFF(conn_info->reconnect);
        } else {
                assert(conn_info->state == ST_TLS_EST
                    || conn_info->state == ST_CONNECTING);
        }        
}
/*
 * Dispatch routine for accepting TLS connections.
 * Has to be idempotent in case of TLS_RETRY (~ EAGAIN),
 * so we can continue a slow handshake.
 */
void
dispatch_accept_tls(int fd, short event, void *arg)
{
        struct tls_conn_settings *conn_info = (struct tls_conn_settings *) arg;
        int rc, error;
        struct TLS_Incoming_Conn *tls_in;

        DPRINTF((D_TLS|D_CALL), "dispatch_accept_tls(conn_info@%p, fd %d)\n", conn_info, fd);
        
        rc = SSL_accept(conn_info->sslptr);
        if (0 >= rc) {
                error = tls_examine_error("SSL_accept()",
                        conn_info->sslptr, NULL, rc);
                switch (error) {
                        /* no need to change retrying-bit, as retrying
                         * is the only way to dispatch this function
                         */
                        case TLS_RETRY_READ:
                                event_set(conn_info->retryevent, fd, EV_READ,
                                        dispatch_accept_tls, conn_info);
                                EVENT_ADD(conn_info->retryevent);
                                break;
                        case TLS_RETRY_WRITE:
                                event_set(conn_info->retryevent, fd, EV_WRITE,
                                        dispatch_accept_tls, conn_info);
                                EVENT_ADD(conn_info->retryevent);
                                break;
                        default: /* should not happen */
                                free_tls_conn(conn_info);
                                break;
                }
                return;
        }
        /* else */
        if (!(tls_in = calloc(1, sizeof(*tls_in)))
         || !(tls_in->inbuf = malloc(TLS_MIN_LINELENGTH))) {
                logerror("Unable to allocate memory for accepted connection");
                free(tls_in);
                free_tls_conn(conn_info);
                return;
        }        
        tls_in->tls_conn = conn_info;
        tls_in->socket = SSL_get_fd(conn_info->sslptr);
        tls_in->ssl = conn_info->sslptr;
        tls_in->inbuf[0] = '\0';
        tls_in->inbuflen = TLS_MIN_LINELENGTH;
        SLIST_INSERT_HEAD(&TLS_Incoming_Head, tls_in, entries);

        conn_info->retrying = false;
        event_set(conn_info->event, tls_in->socket, EV_READ | EV_PERSIST, dispatch_read_tls, conn_info->event);
        EVENT_ADD(conn_info->event);

        logerror("established TLS connection from %s with certificate "
                "%s (%s)", conn_info->hostname, conn_info->subject,
                conn_info->fingerprint);
        /*
         * We could also listen to EOF kevents -- but I do not think
         * that would be useful, because we still had to read() the buffer
         * before closing the socket.
         */
}

/*
 * Dispatch routine for accepting TCP connections and preparing
 * the tls_conn_settings object for a following SSL_accept().
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

        DPRINTF((D_TLS|D_NET), "incoming TCP connection\n");
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
                DPRINTF(D_NET, "could not get peername: %s", gai_strerror(rc));
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
                DPRINTF(D_NET, "Unable to fcntl(sock, O_NONBLOCK): %s\n", strerror(errno));
        }
        
        if (!(ssl = SSL_new(tls_opt.global_TLS_CTX))) {
                DPRINTF(D_TLS, "Unable to establish TLS: %s\n", ERR_error_string(ERR_get_error(), NULL));
                close(newsock);
                return;                                
        }
        if (!SSL_set_fd(ssl, newsock)) {
                DPRINTF(D_TLS, "Unable to connect TLS to socket %d: %s\n", newsock, ERR_error_string(ERR_get_error(), NULL));
                SSL_free(ssl);
                close(newsock);
                return;
        }
        /* store connection details inside ssl object, used to verify
         * cert and immediately match against hostname */
        conn_info->hostname = peername;
        conn_info->x509verify = X509VERIFY_ALWAYS;
        conn_info->sslptr = ssl;
        conn_info->tls_opt = &tls_opt;
        conn_info->incoming = true;
        conn_info->event = allocev();
        conn_info->retryevent = allocev();
        SSL_set_app_data(ssl, conn_info);
        SSL_set_accept_state(ssl);

        DPRINTF(D_TLS, "socket connection from %s accept()ed with fd %d, " \
                "calling SSL_accept()...\n",  peername, newsock);
        
        dispatch_accept_tls(newsock, 0, conn_info);
}

/*
 * Dispatch routine to read from outgoing TCP/TLS sockets.
 * 
 * I do not know if libevent can tell us the difference
 * between available data and an EOF. But it does not matter
 * because there should not be any incoming data.
 * So we close the connection either because the peer closed its
 * side or because the peer broke the protocol by sending us stuff  ;-)
 */
void
dispatch_eof_tls(int fd, short event, void *arg)
{
        struct tls_conn_settings *conn_info = (struct tls_conn_settings *) arg;

        DPRINTF((D_TLS|D_EVENT|D_CALL), "dispatch_eof_tls(%d, %d, %p)\n", fd, event, arg);
        assert(conn_info->state == ST_TLS_EST);
        ST_CHANGE(conn_info->state, ST_EOF);

        free_tls_sslptr(conn_info);
        assert(conn_info->state == ST_NONE);

        /* this overwrites the EV_READ event */
        schedule_event(&conn_info->event,
                &((struct timeval){conn_info->reconnect, 0}),
                tls_reconnect, conn_info);
        RECONNECT_BACKOFF(conn_info->reconnect);
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
/* uses the fd as passed with ev */
void
dispatch_read_tls(int fd_lib, short event, void *ev)
{
        int error;
        int_fast16_t rc;
        struct TLS_Incoming_Conn *c;
        int fd = EVENT_FD(((struct event *)ev));

        DPRINTF((D_TLS|D_EVENT|D_CALL), "active TLS socket %d\n", fd);

        /* first: find the TLS_Incoming_Conn this socket belongs to */
        SLIST_FOREACH(c, &TLS_Incoming_Head, entries) {
                DPRINTF(D_TLS, "look at tls_in@%p with fd %d\n", c, c->socket);
                if (c->socket == fd)
                        break;
        }
        if (!c) {
                logerror("lost TLS socket fd %d, closing", fd);
                close(fd);
                return;
        }

        DPRINTF(D_TLS, "calling SSL_read(%p, %p, %d)\n", c->ssl,
                &(c->inbuf[c->read_pos]), c->inbuflen - c->read_pos);
        rc = SSL_read(c->ssl, &(c->inbuf[c->read_pos]), c->inbuflen - c->read_pos);
        if (rc <= 0) {
                error = tls_examine_error("SSL_read()", c->ssl, c->tls_conn, rc);
                switch (error) {
                        case TLS_RETRY_READ:
                                /* normal event loop will call us again */
                                break;
                        case TLS_RETRY_WRITE:
                                if (!c->tls_conn->retrying) {
                                        c->tls_conn->retrying = true;
                                        event_del(c->tls_conn->event);
                                }
                                event_set(c->tls_conn->retryevent, fd,
                                        EV_WRITE, dispatch_read_tls,
                                        &c->tls_conn);
                                EVENT_ADD(c->tls_conn->retryevent);
                                return;
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
                DPRINTF(D_TLS, "SSL_read() returned %d\n", rc);
                c->errorcount = 0;
                c->read_pos += rc;
        }
        if (c->tls_conn->retrying) {
                c->tls_conn->retrying = false;
                EVENT_ADD(c->tls_conn->event);
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
        char buf_char;
        
        DPRINTF((D_TLS|D_CALL|D_DATA), "tls_split_messages() -- incoming status is " \
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
                DPRINTF(D_DATA, "move inbuf of length %d by %d chars\n",
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
                if (MSG_END_OFFSET+1 > c->inbuflen) {  /* +1 for the '\0' */
                        newbuf = realloc(c->inbuf, MSG_END_OFFSET+1);
                        if (newbuf) {
                                DPRINTF(D_DATA, "Reallocated inbuf\n");
                                c->inbuflen = MSG_END_OFFSET+1;
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
                assert(MSG_END_OFFSET+1 <= c->inbuflen);
                /* message in c->inbuf is not NULL-terminated, so this avoids a complete copy */
                buf_char = c->inbuf[MSG_END_OFFSET];
                c->inbuf[MSG_END_OFFSET] = '\0';
                printline(c->tls_conn->hostname, &c->inbuf[c->cur_msg_start], RemoteAddDate ? ADDDATE : 0);
                c->inbuf[MSG_END_OFFSET] = buf_char;

                if (MSG_END_OFFSET == c->read_pos) {
                        /* no unprocessed data in buffer --> reset to empty */
                        c->cur_msg_start = c->cur_msg_len = c->read_pos = 0;
                } else {
                        /* move remaining input to start of buffer */
                        DPRINTF(D_DATA, "move inbuf of length %d by %d chars\n",
                                c->read_pos - (MSG_END_OFFSET),
                                MSG_END_OFFSET);
                        memmove(&c->inbuf[0],
                                &c->inbuf[MSG_END_OFFSET],
                                c->read_pos - (MSG_END_OFFSET));
                        c->read_pos -= (MSG_END_OFFSET);
                        c->cur_msg_start = c->cur_msg_len = 0;
                }
        }
        
        /* shrink inbuf if too large */
        if ((c->inbuflen > TLS_PERSIST_LINELENGTH)
         && (c->read_pos < TLS_LARGE_LINELENGTH)) {
                newbuf = realloc(c->inbuf, TLS_LARGE_LINELENGTH);
                if (newbuf) {
                        DPRINTF(D_DATA, "Shrink inbuf\n");
                        c->inbuflen = TLS_LARGE_LINELENGTH;
                        c->inbuf = newbuf;
                } else {
                        logerror("Couldn't shrink inbuf");
                        /* no change necessary */
                }
        }
        DPRINTF(D_DATA, "return with status: msg_start %d, msg_len %d, pos %d\n",
                 c->cur_msg_start, c->cur_msg_len, c->read_pos);

        /* try to read another message */
        if (c->read_pos > 10)
                tls_split_messages(c);
        return;
}

/* 
 * wrapper for dispatch_tls_send()
 * 
 * send one line with tls
 * f has to be of typ TLS
 * 
 * returns false if message cannot be sent right now,
 *      caller is responsible to enqueue it
 * returns true if message passed to dispatch_tls_send()
 *      delivery is not garantueed, but likely
 * 
 * TODO: try different algorithm: always remove current message
 *       from buffer and re-add it on failure 
 */
bool
tls_send(struct filed *f, struct buf_msg *buffer)
{
        int i, prefixlen, calclen;
        struct tls_send_msg *sendmsg;
        char *line = buffer->line;
        size_t len = buffer->linelen;

        DPRINTF((D_TLS|D_CALL), "tls_send(f=%p, buffer=%p, line=\"%.*s%s\", "
                "len=%d) to %sconnected dest.\n", f, buffer,
                (len>24 ? 24 : len), line, (len>24 ? "..." : ""),
                len, f->f_un.f_tls.tls_conn->sslptr ? "" : "un");

        if (!buffer->tlsline || !buffer->tlslen) {
                for (prefixlen = 0, i = len+1; i; i /= 10)
                        prefixlen++;
                calclen = prefixlen + 1 + len + 1;  /* with \0 */
                DPRINTF(D_DATA, "calculated prefixlen=%d, msglen=%d\n", prefixlen, calclen);

                if (!(buffer->tlsline = malloc(calclen))) {
                        logerror("Unable to allocate memory, drop message");
                        return false;
                }
                buffer->tlslen = snprintf(buffer->tlsline, calclen, "%d %s", len, line);
        }

        if(f->f_un.f_tls.tls_conn->state == ST_TLS_EST) {
                /* send now */
                if (!(sendmsg = calloc(1, sizeof(*sendmsg)))) {
                        logerror("Unable to allocate memory, drop message");
                        return false;
                }
                sendmsg->refcount = 1;
                sendmsg->f = f;
                sendmsg->buffer = buffer;
                buffer->refcount++;
                DPRINTF(D_DATA, "now sending line: \"%.*s\"\n", buffer->tlslen, buffer->tlsline);
                dispatch_tls_send(0, 0, sendmsg);
                return true;
        } else {
                /* other socket operation active, send later  */
                DPRINTF(D_DATA, "connection not ready, enqueue line: \"%.*s\"\n", buffer->tlslen, buffer->tlsline);
                
                /* now the caller has to enqueue the message (if not already sending from queue) */
                return false;
        }
}

void
dispatch_tls_send(int fd, short event, void *arg)
{
        struct tls_send_msg *sendmsg = (struct tls_send_msg *) arg;
        struct tls_conn_settings *conn_info = sendmsg->f->f_un.f_tls.tls_conn;
        struct buf_msg *buffer = sendmsg->buffer;
        int rc, error;
        
        DPRINTF((D_TLS|D_CALL), "dispatch_tls_send(f=%p, buffer=%p, "
                "line=\"%.*s%s\", len=%d, offset=%d) to %sconnected dest.\n",
                sendmsg->f, sendmsg->buffer,
                (buffer->tlslen>24 ? 24 : buffer->tlslen),
                buffer->tlsline, (buffer->tlslen>24 ? "..." : ""),
                buffer->tlslen, sendmsg->offset,
                conn_info->sslptr ? "" : "un");
        assert(conn_info->state == ST_TLS_EST
            || conn_info->state == ST_WRITING);

        ST_CHANGE(conn_info->state, ST_WRITING);
        rc = SSL_write(conn_info->sslptr,
                (buffer->tlsline + sendmsg->offset),
                (buffer->tlslen - sendmsg->offset));
        if (0 >= rc) {
                error = tls_examine_error("SSL_write()",
                        conn_info->sslptr,
                        conn_info, rc);
                switch (error) {
                        /* currently only called by retrying, so no checking here */
                        case TLS_RETRY_READ:
                                /* collides with eof event */
                                if (!conn_info->retrying) {
                                        event_del(conn_info->event);
                                        conn_info->retrying = true;
                                }
                                event_set(conn_info->retryevent, fd, EV_READ,
                                        dispatch_tls_send, arg);
                                RETRYEVENT_ADD(conn_info->retryevent);
                                return;
                                break;
                        case TLS_RETRY_WRITE:
                                event_set(conn_info->retryevent, fd, EV_WRITE,
                                        dispatch_tls_send, arg);
                                RETRYEVENT_ADD(conn_info->retryevent);
                                break;
                        case TLS_PERM_ERROR:
                                /* no need to check active events */
                                free_tls_sslptr(conn_info);
                                schedule_event(&conn_info->event,
                                        &((struct timeval){conn_info->reconnect, 0}),
                                        tls_reconnect, sendmsg->f);
                                RECONNECT_BACKOFF(conn_info->reconnect);
                                break;
                        default:break;
                }
        } else if (rc < buffer->tlslen) {
                DPRINTF((D_TLS|D_DATA), "TLS: SSL_write() wrote %d out of "
                        "%d bytes\n", rc, (buffer->tlslen - sendmsg->offset));
                sendmsg->offset += rc;
                /* try again */
                if (conn_info->retrying) {
                        conn_info->retrying = false;
                        EVENT_ADD(conn_info->event);
                }
                buffer->refcount++;
                dispatch_tls_send(0, 0, sendmsg);
                return;
        } else if (rc == (buffer->tlslen - sendmsg->offset)) {
                DPRINTF((D_TLS|D_DATA), "TLS: SSL_write() complete\n");
                ST_CHANGE(conn_info->state, ST_TLS_EST);
                tls_send_msg_free(sendmsg);
        } else {
                /* should not be reached */
                DPRINTF((D_TLS|D_DATA), "unreachable code after SSL_write()\n");
                ST_CHANGE(conn_info->state, ST_TLS_EST);
        }
        if (conn_info->retrying) {
                conn_info->retrying = false;
                if (conn_info->event->ev_events)
                        EVENT_ADD(conn_info->event);
        }

        
}

/*
 * Close a SSL connection and its queue and its tls_conn.
 */
void
free_tls_conn(struct tls_conn_settings *conn_info)
{
        DPRINTF(D_MEM, "free_tls_conn(conn_info@%p) with sslptr@%p\n", conn_info, conn_info->sslptr);

        if (conn_info->sslptr)
                free_tls_sslptr(conn_info);
        assert(conn_info->incoming == 1
            || conn_info->state == ST_NONE);

        FREEPTR(conn_info->port);
        FREEPTR(conn_info->subject);
        FREEPTR(conn_info->hostname);
        FREEPTR(conn_info->certfile);
        FREEPTR(conn_info->fingerprint);
        FREEPTR(conn_info->event);
        FREEPTR(conn_info->retryevent);
        FREEPTR(conn_info);
}

/*
 * Dispatch routine for non-blocking TLS shutdown
 */
void dispatch_SSL_shutdown(int fd, short event, void *arg)
{
        struct tls_conn_settings *conn_info = (struct tls_conn_settings *) arg;
        int rc, error;
        
        DPRINTF((D_TLS|D_CALL), "dispatch_SSL_shutdown(conn_info@%p, fd %d)\n", conn_info, fd);
        if ((conn_info->state != ST_CLOSING0)
         && (conn_info->state != ST_CLOSING1)
         && (conn_info->state != ST_CLOSING2))
                ST_CHANGE(conn_info->state, ST_CLOSING0);

        rc = SSL_shutdown(conn_info->sslptr);
        if (rc == 1) {  /* shutdown complete */
                DPRINTF((D_TLS|D_NET), "Closed TLS connection to %s\n", conn_info->hostname);
                ST_CHANGE(conn_info->state, ST_TCP_EST);  /* check this */
                /* closing TCP comes below */
        } else if (rc == 0) { /* unidirectional, now call a 2nd time */
                /* problem: when connecting as a client to rsyslogd this
                 * loops and I keep getting rc == 0
                 * maybe I hit this bug?
                 * http://www.mail-archive.com/openssl-dev@openssl.org/msg24105.html
                 * 
                 * anyway, now I use three closing states to make sure I abort
                 * after two rc = 0. 
                 */
                if (conn_info->state == ST_CLOSING0) {
                        ST_CHANGE(conn_info->state, ST_CLOSING1);
                        dispatch_SSL_shutdown(fd, 0, conn_info);
                } else if (conn_info->state == ST_CLOSING1) {
                        ST_CHANGE(conn_info->state, ST_CLOSING2);
                        dispatch_SSL_shutdown(fd, 0, conn_info);
                } else if (conn_info->state == ST_CLOSING2) {
                        /* abort shutdown, jump to close TCP below */
                } else
                        DPRINTF(D_TLS, "Unexpected connection state %d\n", conn_info->state);
                        /* and abort here too*/
        } else if (rc == -1) {
                error = tls_examine_error("SSL_shutdown()",
                        conn_info->sslptr, NULL, rc);
                switch (error) {
                        case TLS_RETRY_READ:
                                if (!conn_info->retrying) {
                                        conn_info->retrying = true;
                                        event_del(conn_info->event);
                                }
                                event_set(conn_info->retryevent, fd,
                                        EV_READ, dispatch_SSL_shutdown,
                                        conn_info);
                                EVENT_ADD(conn_info->retryevent);
                                return;
                                break;
                        case TLS_RETRY_WRITE:
                                if (!conn_info->retrying) {
                                        conn_info->retrying = true;
                                        event_del(conn_info->event);
                                }
                                event_set(conn_info->retryevent, fd,
                                        EV_WRITE, dispatch_SSL_shutdown,
                                        conn_info);
                                EVENT_ADD(conn_info->retryevent);
                                return;
                                break;
                        default:
                                /* we cannot shutdown after an error in
                                 * shutdown, can we?   %-)           */
                                break;
                }
        }
        if (conn_info->retrying)
                conn_info->retrying = false;
        if ((conn_info->state != ST_TLS_EST)
         && (conn_info->state != ST_CLOSING0)
         && (conn_info->state != ST_CLOSING1)) {
                if (shutdown(fd, SHUT_RDWR) == -1)
                        DPRINTF((D_TLS|D_NET), "Unable to cleanly shutdown TCP socket %d: %s\n", fd, strerror(errno));
                if (close(fd) == -1)
                        DPRINTF((D_TLS|D_NET), "Unable to cleanly close socket %d: %s\n", fd, strerror(errno));
                ST_CHANGE(conn_info->state, ST_NONE);
                FREE_SSL(conn_info->sslptr);                
         }

}


/*
 * Close a SSL object
 */
void
free_tls_sslptr(struct tls_conn_settings *conn_info)
{
        int sock;
        DPRINTF(D_MEM, "free_tls_sslptr(conn_info@%p)\n", conn_info);

        if (!conn_info->sslptr) {
                assert(conn_info->incoming == 1
                    || conn_info->state == ST_NONE);
                return;
        } else {
                sock = SSL_get_fd(conn_info->sslptr);
                dispatch_SSL_shutdown(sock, 0, conn_info);
        }
}

/* write self-generated certificates */
bool write_x509files(EVP_PKEY *pkey, X509 *cert, const char *keyfilename, const char *crtfilename)
{
        /* TODO */
        return false;
}

/* 
 * generates a private key and a X.509 certificate
 */
bool
mk_x509_cert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
    X509           *x;
    EVP_PKEY       *pk;
    RSA            *rsa;
    X509_NAME      *name = NULL;
    X509_EXTENSION *ex = NULL;
    /* TODO: cannot access LocalHostName from syslogd.c? */
    char *hostname = "localhost";

    printf("mk_x509_cert(%p, %p, %d, %d, %d)\n", x509p, pkeyp, bits, serial, days);
    
    if ((pkeyp == NULL) || (*pkeyp == NULL)) {
        if ((pk = EVP_PKEY_new()) == NULL) {
                printf("EVP_PKEY_new() failed\n");
                return false;
        }
    } else
        pk = *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL)) {
        if ((x = X509_new()) == NULL) {
                printf("X509_new() failed\n");
                return false;
        }
    } else
        x = *x509p;

    rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa)) {
        printf("EVP_PKEY_assign_RSA() failed\n");
        return false;
    }
    rsa = NULL;

    X509_set_version(x, 3);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

    /*
     * This function creates and adds the entry, working out the correct
     * string type and performing checks on its length. Normally we'd check
     * the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "The NetBSD Project", -1, -1, 0);

    X509_set_issuer_name(x, name);

    /*
     * Add extension using V3 code: we can set the config file as NULL
     * because we wont reference any other sections. We can also set the
     * context to NULL because none of these extensions below will need to
     * access it.
     */
    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type, "server");
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
                             "auto-generated by syslogd");
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_ssl_server_name, hostname);
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

    /* might want something like this too.... */
    ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                             "critical,CA:FALSE");
    X509_add_ext(x, ex, -1);
    X509_EXTENSION_free(ex);

    if (!X509_sign(x, pk, EVP_md5())) {
        printf("X509_sign() failed\n");
        return false;
    }

    *x509p = x;
    *pkeyp = pk;
    return true;
}
