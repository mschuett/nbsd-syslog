/*
 * sign.c
 * syslog-sign related code for syslogd
 *
 * Martin Schütte
 */
/* 
 * Issues with the current internet draft: 
 * 1. The draft is a bit unclear on the input format for the signature,
 *    so this might have to be changed later. Cf. sign_msg_sign()
 * 2. The draft only defines DSA signatures. I hope it will be extended
 *    to DSS, thus allowing DSA, RSA (ANSI X9.31) and ECDSA (ANSI X9.62)
 * 3. This current implementation uses high-level OpenSSL API.
 *    I am not sure if these completely implement the FIPS/ANSI standards.
 */
/* 
 * Limitations of this implementation:
 * - cannot use OpenPGP keys, only PKIX or DSA due to OpenSSL capabilities
 * - currently only SG 3
 * - due to the splitting and formatting this syslogd modifies messages
 *   (e.g. if it receives a message with two spaces between fields it will
 *   not forward the message unchanged). This would invalidate signatures,
 *   so all devices using syslog-sign should only emit correct syslog-protocol
 *   formatted messages.
 */
#ifndef DISABLE_SIGN
#include "syslogd.h"
#include "tls_stuff.h"
#include "sign.h"

/* definitions in syslogd.c */
extern short int Debug;
extern unsigned GlobalMsgCounter;
extern struct sign_global_t GlobalSign;
extern time_t now;
extern struct filed *Files;

extern struct tls_global_options_t tls_opt;
extern char   timestamp[];
extern char   LocalFQDN[];
extern char   LocalHostName[];

extern void  logerror(const char *, ...);
extern void  loginfo(const char *, ...);
extern void  logmsg_async_f(const int, const char *, const char *, const int, struct filed*);
extern bool  format_buffer(struct buf_msg*, char**, size_t*, size_t*, size_t*, size_t*);
extern void  fprintlog(struct filed *, struct buf_msg *, struct buf_queue *);
extern void  buf_msg_free(struct buf_msg *msg);
extern char *make_timestamp(time_t*, bool);
extern struct buf_msg 
            *buf_msg_new(const size_t);
extern unsigned int
             message_queue_purge(struct filed*, const unsigned int, const int);

/*
 * init all SGs for a given algorithm 
 */
bool
sign_global_init(unsigned alg, struct filed *Files)
{
        struct signature_group_t *newsg;
        FILE  *keyfile, *certfile;
        EVP_PKEY *pubkey = NULL, *privkey = NULL;
        unsigned char *der_pubkey = NULL, *ptr_der_pubkey = NULL;
        char *pubkey_b64 = NULL;
        int der_len;
        
        DPRINTF((D_CALL|D_SIGN), "sign_global_init()\n");
        if (alg != 3) {
                logerror("sign_init(): alg %d not implemented", alg);
                return false;
        }

        /* uses TLS keys */
        /* private key */
        if (tls_opt.keyfile && tls_opt.certfile
         && (keyfile = fopen(tls_opt.keyfile, "r"))
         && (certfile = fopen(tls_opt.certfile, "r"))) {
                X509 *cert;
                
                cert = PEM_read_X509(certfile, NULL, NULL, 0);
                (void)fclose(certfile);
                PEM_read_PrivateKey(keyfile, &privkey, NULL, 0);
                (void)fclose(keyfile);
                if (!privkey) {
                        logerror("PEM_read_PrivateKey() failed");
                        return false;
                }
                if (!cert) {
                        logerror("PEM_read_X509() failed");
                        return false;
                }
                if (!(pubkey = X509_get_pubkey(cert))) {
                        logerror("X509_get_pubkey() failed");
                        return false;
                }
        }

        if (privkey && pubkey) { /* PKIX */
                DPRINTF(D_SIGN, "Got public and private key from X.509 "
                        "--> use type PKIX\n");
                GlobalSign.keytype = 'C';
        } else {                 /* PKIX not available --> generate new key */
                DSA *dsa;

                DPRINTF(D_SIGN, "Unable to get keys from X.509 "
                        "--> use DSA with type 'K'\n");
                if (!(privkey = EVP_PKEY_new())) {
                        logerror("EVP_PKEY_new() failed");
                        return false;
                }
                dsa = DSA_generate_parameters(TLS_GENCERT_BITS, NULL, 0,
                        NULL, NULL, NULL, NULL);
                if (!DSA_generate_key(dsa)) {
                        logerror("EVP_PKEY_assign_DSA() failed");
                        return false;
                }
                if (!EVP_PKEY_assign_DSA(privkey, dsa)) {
                        logerror("EVP_PKEY_assign_DSA() failed");
                        return false;
                }
                GlobalSign.keytype = 'K';  /* public/private keys used */
        }
        assert(GlobalSign.keytype == 'C' || GlobalSign.keytype == 'K');
        GlobalSign.privkey = privkey;
        GlobalSign.pubkey = pubkey;        

        /* pubkey base64 encoding */
        der_len = i2d_PUBKEY(pubkey, NULL);
        if (!(ptr_der_pubkey = der_pubkey = malloc(der_len))
         || !(pubkey_b64 = malloc(der_len*2))) {
                free(der_pubkey);
                logerror("malloc() failed");
                return false;
        }
        if (i2d_PUBKEY(pubkey, &ptr_der_pubkey) <= 0) {
                logerror("i2d_PUBKEY() failed");
                return false;
        }
        b64_ntop(der_pubkey, der_len, pubkey_b64, der_len*2);
        free(der_pubkey);
        /* try to resize memory object as needed */
        GlobalSign.pubkey_b64 = realloc(pubkey_b64, strlen(pubkey_b64)+1);
        if (!GlobalSign.pubkey_b64)
                GlobalSign.pubkey_b64 = pubkey_b64;
        assert(GlobalSign.pubkey_b64 && GlobalSign.privkey && GlobalSign.pubkey);

        GlobalSign.sg = alg;
        GlobalSign.spri = 0;
        GlobalSign.gbc = 0;
        GlobalSign.rsid = now;
        TAILQ_INIT(&GlobalSign.SigGroups);

        /* hash algorithm */
        OpenSSL_add_all_digests();
        GlobalSign.mdctx = EVP_MD_CTX_create();
        EVP_MD_CTX_init(GlobalSign.mdctx);

#ifndef SIGN_USE_SHA256
        /* values for SHA-1 */
        GlobalSign.md = EVP_sha1();
        GlobalSign.md_len_b64 = 28;
        GlobalSign.ver = "0111";
#else
        /* values for SHA-256 */
        GlobalSign.md = EVP_sha256();
        GlobalSign.md_len_b64 = 44;
        GlobalSign.ver = "0121";
#endif

        /* signature algorithm */
        /* can probably be merged with the hash algorithm/context but
         * I leave the optimization for later until the RFC is ready */
        GlobalSign.sigctx = EVP_MD_CTX_create();
        EVP_MD_CTX_init(GlobalSign.sigctx);

        /* the signature algorithm depends on the type of key */
        if (EVP_PKEY_DSA == EVP_PKEY_type(GlobalSign.pubkey->type)) {
                GlobalSign.sig = EVP_dss1();
                GlobalSign.sig_len_b64 = 28;
        } else if (EVP_PKEY_RSA == EVP_PKEY_type(GlobalSign.pubkey->type)) {
                GlobalSign.sig = EVP_sha1();
                GlobalSign.sig_len_b64 = 28;
        } else {
                logerror("EVP_PKEY_type not supported");
                return false;
        }

        /* single SG(s) */
        assert(GlobalSign.sg == 3);
        for (struct filed *f = Files; f; f = f->f_next)
                if (f->f_flags & FFLAG_SIGN) {
                        //CALLOC(newsg, sizeof(*newsg));
                        newsg = calloc(1, sizeof(*newsg));
                        TAILQ_INIT(&newsg->hashes);
                        TAILQ_INSERT_TAIL(&GlobalSign.SigGroups,
                                newsg, entries);
                        f->f_sg = newsg;
                } else {
                        f->f_sg = NULL;
                }
        return true;
}

/*
 * free all SGs for a given algorithm 
 */
void
sign_global_free(struct filed *Files)
{
        struct signature_group_t *sg, *tmp_sg;
        FREEPTR(GlobalSign.pubkey);
        FREEPTR(GlobalSign.pubkey_b64);
        FREEPTR(GlobalSign.privkey);
        EVP_MD_CTX_destroy(GlobalSign.mdctx);        

        DPRINTF((D_CALL|D_SIGN), "sign_global_free(%p)\n", Files);
        assert(GlobalSign.sg == 3);
        for (struct filed *f = Files; f; f = f->f_next)
                if (f->f_flags & FFLAG_SIGN) {
                        sign_send_signature_block(f->f_sg, f);
                        f->f_sg = NULL;
                }

        TAILQ_FOREACH_SAFE(sg, &GlobalSign.SigGroups, entries, tmp_sg) {
                if (!TAILQ_EMPTY(&sg->hashes))
                        sign_free_hashes(sg);
                TAILQ_REMOVE(&GlobalSign.SigGroups, sg, entries);
                free(sg);
        }
}

/*
 * create and send certificate block
 */
bool
sign_send_certificate_block(struct filed *f)
{
        struct buf_msg *buffer;
        char *timestamp, *signature, *line;
        char payload[MAXLINE];
        char sd[SIGN_MAX_SD_LENGTH];
        int omask;
        size_t payload_len, sd_len, fragment_len, linelen, tlsprefixlen;
        size_t payload_index = 0;

        DPRINTF((D_CALL|D_SIGN), "sign_send_certificate_block(%p)\n", f);
        timestamp = make_timestamp(NULL, true);

        payload_len = snprintf(payload, MAXLINE, "%s %c %s", timestamp,
                GlobalSign.keytype, GlobalSign.pubkey_b64);
        if (payload_len >= MAXLINE) {
                DPRINTF(D_SIGN, "Buffer too small for syslog-sign setup\n");
                return false;
        }

        while (payload_index < payload_len) {
                if (payload_len - payload_index <= SIGN_MAX_FRAG_LENGTH)
                        fragment_len = payload_len - payload_index;
                else
                        fragment_len = SIGN_MAX_FRAG_LENGTH;

                /* 
                 * this basically duplicates logmsg_async_f() and
                 * part of fprintlog() because the message has to be
                 * completely formatted before it can be signed.
                 */ 
                buffer = buf_msg_new(0);
                buffer->timestamp = strdup(make_timestamp(NULL, true));
                buffer->prog = strdup("syslogd");
                buffer->recvhost = buffer->host = strdup(LocalHostName);
                buffer->pri = 110;
                buffer->flags = IGN_CONS|SIGNATURE;

                sd_len = snprintf(sd, sizeof(sd), "[ssign-cert "
                        "VER=\"%s\" RSID=\"%llu\" SG=\"%d\" "
                        "SPRI=\"%d\" TBPL=\"%d\" INDEX=\"%d\" "
                        "FLEN=\"%d\" FRAG=\"%.*s\" "
                        "SIGN=\"\"]",
                        GlobalSign.ver, GlobalSign.rsid, GlobalSign.sg,
                        GlobalSign.spri, payload_len, payload_index,
                        fragment_len, fragment_len, &payload[payload_index]);
                assert(sd_len < sizeof(sd));
                assert(sd[sd_len] == '\0');
                assert(sd[sd_len-1] == ']');
                assert(sd[sd_len-2] == '"');
                buffer->sd = strdup(sd);
                
                /* SD ready, now format */
                if (!format_buffer(buffer, &line, &linelen, NULL,
                        &tlsprefixlen, NULL)) {
                        DPRINTF((D_CALL|D_SIGN), "sign_send_certificate_block():"
                                " format_buffer() failed\n");
                        DELREF(buffer);
                        return 0;  /* TODO */
                }
                sign_msg_sign(line+tlsprefixlen, &signature);
                sd[sd_len-2] = '\0';
                strlcat(sd, signature, sizeof(sd));
                strlcat(sd, "\"]", sizeof(sd));

                free(buffer->sd);
                buffer->sd = strdup(sd);
                
                DPRINTF((D_CALL|D_SIGN), "sign_send_certificate_block(): "
                        "calling fprintlog()\n");

                /* log the message to the particular output */
                omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
                if (f->f_prevcount)
                        fprintlog(f, NULL, NULL);
                f->f_repeatcount = 0;
                DELREF(f->f_prevmsg);
                f->f_prevmsg = NEWREF(buffer);
                fprintlog(f, NEWREF(buffer), NULL);
                DELREF(buffer);
                DELREF(buffer);
                sign_inc_gbc();
                (void)sigsetmask(omask);
                payload_index += fragment_len;
        }
        return true;
}

/*
 * determine the SG for a message
 */
struct signature_group_t *
sign_get_sg(int pri, struct signature_group_head *SGs, struct filed *f)
{
        DPRINTF((D_CALL|D_SIGN), "sign_get_sg(%p, %p)\n", SGs, f);
        if (GlobalSign.sg == 0) {
                return TAILQ_FIRST(&GlobalSign.SigGroups);
        } else if (GlobalSign.sg == 3) {
                return f->f_sg;
        } else {
                /* TODO */
                logerror("sign_get_sg(): sg %d not implemented", GlobalSign.sg);
                return NULL;
        }
}

/*
 * create and send signature block
 */
unsigned
sign_send_signature_block(struct signature_group_t *group, struct filed *f)
{
        char sd[SIGN_MAX_SD_LENGTH];
        char *signature, *line;
        size_t sd_len, linelen, tlsprefixlen;
        int omask;
        unsigned hashcount = 0;
        unsigned sendcount = 0;
        struct string_queue *qentry, *old_qentry, *first_qentry;
        struct buf_msg *buffer;
        
        DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block(%p, %p)\n",
                group, f);

        TAILQ_FOREACH(qentry, &group->hashes, entries)
                hashcount++;

        DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block(): hashcount = %d, "
                "SIGN_HASH_NUM = %d\n", hashcount, SIGN_HASH_NUM);

        if (hashcount < SIGN_HASH_NUM)
                return 0;

        qentry = TAILQ_FIRST(&group->hashes);
        while (sendcount < hashcount && !TAILQ_EMPTY(&group->hashes)) {
                //[ssign VER="" RSID="" SG="" SPRI="" GBC="" FMN="" CNT="" HB="" SIGN=""]
                /* TODO: add redundancy and send more than once */

                /* 
                 * this basically duplicates logmsg_async_f() and
                 * part of fprintlog() because the message has to be
                 * completely formatted before it can be signed.
                 */ 
                buffer = buf_msg_new(0);
                buffer->timestamp = strdup(make_timestamp(NULL, true));
                buffer->prog = strdup("syslogd");
                buffer->recvhost = buffer->host = strdup(LocalHostName);
                buffer->pri = 110;
                buffer->flags = IGN_CONS|SIGNATURE;

                /* now the SD */
                first_qentry = TAILQ_FIRST(&group->hashes);
                sd_len = snprintf(sd, sizeof(sd), "[ssign "
                        "VER=\"%s\" RSID=\"%lld\" SG=\"%d\" "
                        "SPRI=\"%d\" GBC=\"%lld\" FMN=\"%lld\" "
                        "CNT=\"%u\" HB=\"",
                        GlobalSign.ver, GlobalSign.rsid, GlobalSign.sg,
                        group->spri, GlobalSign.gbc, first_qentry->key,
                        MIN(SIGN_MAX_HASH_NUM, hashcount));
                while (sendcount < MIN(SIGN_MAX_HASH_NUM, hashcount)) {
                        sd_len += snprintf(sd+sd_len, sizeof(sd)-sd_len,
                                "%s ", qentry->data);
                        sendcount++;

                        /* TODO: count and delete after send */
                        TAILQ_REMOVE(&group->hashes, qentry, entries);
                        old_qentry = qentry;
                        qentry = TAILQ_NEXT(old_qentry, entries);
                        FREEPTR(old_qentry->data);
                        FREEPTR(old_qentry);
                }
                /* overwrite last space and close SD */
                assert(sd_len < sizeof(sd));
                assert(sd[sd_len] == '\0');
                assert(sd[sd_len-1] == ' ');
                sd[sd_len-1] = '\0';
                sd_len = strlcat(sd, "\" SIGN=\"\"]", sizeof(sd));
                assert(sd_len < sizeof(sd));
                assert(sd[sd_len] == '\0');
                assert(sd[sd_len-1] == ']');
                assert(sd[sd_len-2] == '"');
                buffer->sd = strdup(sd);
                
                /* SD ready, now format */
                if (!format_buffer(buffer, &line, &linelen, NULL,
                        &tlsprefixlen, NULL)) {
                        DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block():"
                                " format_buffer() failed\n");
                        DELREF(buffer);
                        return 0;  /* TODO */
                }
                sign_msg_sign(line+tlsprefixlen, &signature);
                sd[sd_len-2] = '\0';
                strlcat(sd, signature, sizeof(sd));
                strlcat(sd, "\"]", sizeof(sd));

                free(buffer->sd);
                buffer->sd = strdup(sd);
                
                DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block(): calling"
                        " fprintlog(), sending %d out of %d hashes\n",
                        MIN(SIGN_MAX_HASH_NUM, hashcount), hashcount);

                /* log the message to the particular output */
                omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
                if (f->f_prevcount)
                        fprintlog(f, NULL, NULL);
                f->f_repeatcount = 0;
                DELREF(f->f_prevmsg);
                f->f_prevmsg = NEWREF(buffer);
                fprintlog(f, NEWREF(buffer), NULL);
                DELREF(buffer);
                DELREF(buffer);
                sign_inc_gbc();
                (void)sigsetmask(omask);
        }
        return sendcount;
}

void
sign_free_hashes(struct signature_group_t *group)
{
        struct string_queue *qentry, *tmp_qentry;
        
        DPRINTF((D_CALL|D_SIGN), "sign_free_hashes(%p)\n", group);
        TAILQ_FOREACH_SAFE(qentry, &group->hashes, entries, tmp_qentry) {
                TAILQ_REMOVE(&group->hashes, qentry, entries);
                FREEPTR(qentry->data);
                free(qentry);
        }
        assert(TAILQ_EMPTY(&group->hashes));
}

#define CHECK_ONE(exp) do if ((exp) != 1) {                                  \
                       DPRINTF(D_SIGN, #exp " failed in %d: %s\n", __LINE__, \
                             ERR_error_string(ERR_get_error(), NULL));       \
                       return 1;                                             \
                    } while (0)
/*
 * hash one syslog message
 */
bool
sign_msg_hash(char *line, char **hash)
{
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned char md_b64[EVP_MAX_MD_SIZE*2];  /* TODO: exact expression for b64 length? */
        unsigned int md_len = 0;

        DPRINTF((D_CALL|D_SIGN), "sign_msg_hash('%s')\n", line);
        
        CHECK_ONE(EVP_DigestInit_ex(GlobalSign.mdctx, GlobalSign.md, NULL));
        CHECK_ONE(EVP_DigestUpdate(GlobalSign.mdctx, line, strlen(line)));
        CHECK_ONE(EVP_DigestFinal_ex(GlobalSign.mdctx, md_value, &md_len));
        
        b64_ntop(md_value, md_len, (char *)md_b64, EVP_MAX_MD_SIZE*2);
        *hash = strdup((char *)md_b64);

        DPRINTF((D_CALL|D_SIGN), "sign_msg_hash() --> \"%s\"\n", *hash);
        return true;
}

/*
 * append hash to SG queue
 */
bool
sign_append_hash(char *hash, struct signature_group_t *group)
{
        DPRINTF((D_CALL|D_SIGN), "sign_append_hash('%s', %p)\n",
                hash, group);
        struct string_queue *qentry;

        /* if one SG is shared by several destinations
         * prevent duplicate entries */
        if ((qentry = TAILQ_LAST(&group->hashes, string_queue_head))
          && !strcmp(qentry->data, hash))
                return false;

        MALLOC(qentry, sizeof(*qentry));
        qentry->key = sign_assign_msg_num(group);
        qentry->data = hash;
        TAILQ_INSERT_TAIL(&group->hashes, qentry, entries);
        return true;
}

/*
 * sign one syslog message
 */
bool
sign_msg_sign(char *line, char **signature)
{
        char buf[SIGN_MAX_LENGTH+1];
        unsigned char sig_value[EVP_MAX_MD_SIZE];
        unsigned char sig_b64[EVP_MAX_MD_SIZE*2];  /* TODO: exact expression for b64 length? */
        unsigned int sig_len = 0;
        char *p, *q;

        DPRINTF((D_CALL|D_SIGN), "sign_msg_sign('%s')\n", line);
        
        /* 
         * The signature is calculated over the completely formatted
         * syslog-message, including all of the PRI, HEADER, and hashes
         * in the hash block, excluding spaces between fields, and also
         * excluding the signature field (SD Parameter Name "SIGN", "=",
         * and corresponding value).
         * 
         * -- I am not quite sure which spaces are to be removed.
         * Only the ones inside the "ssign" element or those between
         * header fields as well?
         */
        /* removes all spaces and the string SIGN="" */
        for (p = line, q = buf;
             *p && (q - buf <= SIGN_MAX_LENGTH);) {
                if (*p == ' ') p++;
                if (*p == 'S' && *(p+1) == 'I' && *(p+2) == 'G'
                 && *(p+3) == 'N' && *(p+4) == '=' && *(p+5) == '"'
                 && *(p+6) == '"') {
                        p += 7;
                        if (*p == ' ') p++;
                }
                *q++ = *p++;
        }
        *q = '\0';

        CHECK_ONE(EVP_SignInit(GlobalSign.sigctx, GlobalSign.sig));
        CHECK_ONE(EVP_SignUpdate(GlobalSign.sigctx, buf, q-buf));
        CHECK_ONE(EVP_DigestFinal_ex(GlobalSign.sigctx, sig_value, &sig_len));
        
        b64_ntop(sig_value, sig_len, (char *)sig_b64, EVP_MAX_MD_SIZE*2);
        *signature = strdup((char *)sig_b64);

        DPRINTF((D_CALL|D_SIGN), "sign_msg_sign('%s') --> '%s'\n", buf, *signature);
        return true;
}

void
sign_new_reboot_session()
{
        DPRINTF((D_CALL|D_SIGN), "sign_new_reboot_session()\n");
        GlobalSign.gbc = 0;
        /* might be useful for later analysis:
         * rebooted session IDs are sequential,
         * normal IDs are almost always not */
        GlobalSign.rsid++;
}

/* get msg_num, increment counter, check overflow */
uint_fast64_t
sign_assign_msg_num(struct signature_group_t *group)
{
        uint_fast64_t old;

        old = group->last_msg_num++;
        if (group->last_msg_num > SIGN_MAX_COUNT)
                sign_new_reboot_session();
        return old;
}


/* increment gbc, check overflow */
void
sign_inc_gbc()
{
        if (++GlobalSign.gbc > SIGN_MAX_COUNT)
                sign_new_reboot_session();
}
#endif /* !DISABLE_SIGN */