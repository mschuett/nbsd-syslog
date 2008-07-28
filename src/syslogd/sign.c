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
extern char *LocalFQDN;

/*
 * init all SGs for a given algorithm 
 */
bool
sign_global_init(unsigned alg, struct filed *Files)
{
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

        /* try PKIX/TLS keys first */
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
                DPRINTF(D_SIGN, "Got public and private key from X.509 "
                        "--> use type PKIX\n");
                GlobalSign.keytype = 'C';
                GlobalSign.privkey = privkey;
                GlobalSign.pubkey = pubkey;   
                
                /* base64 certificate encoding */
                int i2d_X509(X509 *x, unsigned char **out);
                
                der_len = i2d_X509(cert, NULL);
                if (!(ptr_der_pubkey = der_pubkey = malloc(der_len))
                 || !(pubkey_b64 = malloc(der_len*2))) {
                        free(der_pubkey);
                        logerror("malloc() failed");
                        return false;
                }
                if (i2d_X509(cert, &ptr_der_pubkey) <= 0) {
                        logerror("i2d_X509() failed");
                        return false;
                }
                b64_ntop(der_pubkey, der_len, pubkey_b64, der_len*2);
                free(der_pubkey);
                /* try to resize memory object as needed */
                GlobalSign.pubkey_b64 = realloc(pubkey_b64, strlen(pubkey_b64)+1);
                if (!GlobalSign.pubkey_b64)
                        GlobalSign.pubkey_b64 = pubkey_b64;
        }
        if (!(privkey && pubkey)) { /* PKIX not available --> generate key */
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
        }
        assert(GlobalSign.keytype == 'C' || GlobalSign.keytype == 'K');
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
                        struct signature_group_t *newsg;
                        struct filed_queue       *fq;
                        
                        //CALLOC(newsg, sizeof(*newsg));
                        newsg = calloc(1, sizeof(*newsg));
                        fq    = calloc(1, sizeof(*fq));
                        fq->f = f;
                        TAILQ_INIT(&newsg->files);
                        TAILQ_INSERT_TAIL(&newsg->files, fq, entries);
                        TAILQ_INIT(&newsg->hashes);
                        TAILQ_INSERT_TAIL(&GlobalSign.SigGroups,
                                newsg, entries);
                        newsg->last_msg_num = 1; /* cf. section 4.2.5 */
                        f->f_sg = newsg;
                } else {
                        f->f_sg = NULL;
                }
        sign_new_reboot_session();
        return true;
}

/*
 * free all SGs for a given algorithm 
 */
void
sign_global_free()
{
        struct signature_group_t *sg, *tmp_sg;
        struct filed_queue *fq, *tmp_fq;

        DPRINTF((D_CALL|D_SIGN), "sign_global_free(%p)\n", Files);
        if (!GlobalSign.rsid)  /* never initialized */
                return;

        FREEPTR(GlobalSign.pubkey);
        FREEPTR(GlobalSign.pubkey_b64);
        FREEPTR(GlobalSign.privkey);
        if(GlobalSign.mdctx) EVP_MD_CTX_destroy(GlobalSign.mdctx);        

        assert(GlobalSign.sg == 3);
        TAILQ_FOREACH_SAFE(sg, &GlobalSign.SigGroups, entries, tmp_sg) {
                if (!TAILQ_EMPTY(&sg->hashes)) {
                        sign_send_signature_block(sg, true);
                        sign_free_hashes(sg);
                }
                fq = TAILQ_FIRST(&sg->files);
                while (fq != NULL) {
                        tmp_fq = TAILQ_NEXT(fq, entries);
                        free(fq);
                        fq = tmp_fq;
                }
                TAILQ_REMOVE(&GlobalSign.SigGroups, sg, entries);
                free(sg);
        }
}

/*
 * create and send certificate block
 */
bool
sign_send_certificate_block(struct signature_group_t *sg)
{
        struct filed_queue *fq;
        struct buf_msg *buffer;
        char *timestamp, *signature, *line;
        char payload[SIGN_MAX_PAYLOAD_LENGTH];
        char sd[SIGN_MAX_SD_LENGTH];
        int omask;
        size_t payload_len, sd_len, fragment_len, linelen, tlsprefixlen;
        size_t payload_index = 0;

        if (!sg->resendcount) return false;

        DPRINTF((D_CALL|D_SIGN), "sign_send_certificate_block(%p)\n", sg);
        timestamp = make_timestamp(NULL, true);

        payload_len = snprintf(payload, sizeof(payload), "%s %c %s", timestamp,
                GlobalSign.keytype, GlobalSign.pubkey_b64);
        if (payload_len >= sizeof(payload)) {
                DPRINTF(D_SIGN, "Buffer too small for syslog-sign setup\n");
                return false;
        }

        while (payload_index < payload_len) {
                if (payload_len - payload_index <= SIGN_MAX_FRAG_LENGTH)
                        fragment_len = payload_len - payload_index;
                else
                        fragment_len = SIGN_MAX_FRAG_LENGTH;

                /* set up buffer */
                buffer = buf_msg_new(0);
                buffer->timestamp = strdup(make_timestamp(NULL, true));
                buffer->prog = strdup("syslogd");
                buffer->recvhost = buffer->host = LocalFQDN;
                buffer->pri = 110;
                buffer->flags = IGN_CONS|SIGNATURE;

                /* format SD */
                sd_len = snprintf(sd, sizeof(sd), "[ssign-cert "
                        "VER=\"%s\" RSID=\"%llu\" SG=\"%d\" "
                        "SPRI=\"%d\" TBPL=\"%d\" INDEX=\"%d\" "
                        "FLEN=\"%d\" FRAG=\"%.*s\" "
                        "SIGN=\"\"]",
                        GlobalSign.ver, GlobalSign.rsid, GlobalSign.sg,
                        GlobalSign.spri, payload_len,
                        payload_index+1 /* cf. section 5.3.2.5 */,
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
                        return false;
                        /* TODO: Don't really know how to handle this
                         * so just ignore and hope there will be another
                         * certificate block sent */
                }
                sign_msg_sign(line+tlsprefixlen, &signature);
                sd[sd_len-2] = '\0';
                strlcat(sd, signature, sizeof(sd));
                strlcat(sd, "\"]", sizeof(sd));

                free(buffer->sd);
                buffer->sd = strdup(sd);
                
                omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
                DPRINTF((D_CALL|D_SIGN), "sign_send_certificate_block(): "
                        "calling fprintlog()\n");
                TAILQ_FOREACH(fq, &sg->files, entries) {
                        struct filed *f = fq->f;
                        /* TODO: write fprintlog() wrapper for this */
                        /* TODO: do not include this in repeat counts */
                        if (f->f_prevcount)
                                fprintlog(f, NULL, NULL);
                        f->f_repeatcount = 0;
                        DELREF(f->f_prevmsg);
                        f->f_prevmsg = NEWREF(buffer);
                        fprintlog(f, NEWREF(buffer), NULL);
                        DELREF(buffer);
                        DELREF(buffer);
                }
                sign_inc_gbc();
                payload_index += fragment_len;
                (void)sigsetmask(omask);
        }
        sg->resendcount--;
        return true;
}

/*
 * determine the SG for a message
 * returns NULL if -sign not configured or no SG for this priority
 */
struct signature_group_t *
sign_get_sg(int pri, struct signature_group_head *SGs, struct filed *f)
{
        DPRINTF((D_CALL|D_SIGN), "sign_get_sg(%p, %p)\n", SGs, f);
        
        if (!GlobalSign.rsid)
                return NULL;
        
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
 * 
 * uses a sliding window for redundancy
 * if force==true then simply send all available hashes, e.g. on shutdown
 */
unsigned
sign_send_signature_block(struct signature_group_t *sg, bool force)
{
        char sd[SIGN_MAX_SD_LENGTH];
        char *signature, *line;
        size_t sd_len, linelen, tlsprefixlen;
        int omask;
        unsigned sg_num_hashes = 0;     /* hashes in SG queue */
        unsigned hashes_in_sb = 0;      /* number of hashes to send in current SB */
        unsigned hashes_sent = 0;       /* count of hashes sent */
        struct string_queue *qentry, *old_qentry;
        struct buf_msg *buffer;
        struct filed_queue *fq;

        if (!sg) return 0;
        DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block(%p, %d)\n",
                sg, force);

        TAILQ_FOREACH(qentry, &sg->hashes, entries)
                sg_num_hashes++;

        /* only act if a division is full */
        if (!sg_num_hashes || (!force && (sg_num_hashes % SIGN_HASH_DIVISION_NUM)))
                return 0;
        
        /* shortly after reboot we have shorter SBs */
        hashes_in_sb = MIN(sg_num_hashes, SIGN_HASH_NUM);
        
        DPRINTF(D_SIGN, "sign_send_signature_block(): "
                "sg_num_hashes = %d, hashes_in_sb = %d, SIGN_HASH_NUM = %d\n",
                sg_num_hashes, hashes_in_sb, SIGN_HASH_NUM);
        if (sg_num_hashes > SIGN_HASH_NUM)
                DPRINTF(D_SIGN, "sign_send_signature_block(): sg_num_hashes"
                        " > SIGN_HASH_NUM -- This should not happen!\n");

        //[ssign VER="" RSID="" SG="" SPRI="" GBC="" FMN="" CNT="" HB="" SIGN=""]
        /* 
         * this basically duplicates logmsg_async_f() and
         * part of fprintlog() because the message has to be
         * completely formatted before it can be signed.
         */ 
        buffer = buf_msg_new(0);
        buffer->timestamp = strdup(make_timestamp(NULL, true));
        buffer->prog = strdup("syslogd");
        buffer->recvhost = buffer->host = LocalFQDN;
        buffer->pri = 110;
        buffer->flags = IGN_CONS|SIGNATURE;

        /* now the SD */
        qentry = TAILQ_FIRST(&sg->hashes);
        sd_len = snprintf(sd, sizeof(sd), "[ssign "
                "VER=\"%s\" RSID=\"%lld\" SG=\"%d\" "
                "SPRI=\"%d\" GBC=\"%lld\" FMN=\"%lld\" "
                "CNT=\"%u\" HB=\"",
                GlobalSign.ver, GlobalSign.rsid, GlobalSign.sg,
                sg->spri, GlobalSign.gbc, qentry->key,
                hashes_in_sb);
        while (hashes_sent < hashes_in_sb) {
                assert(qentry);
                sd_len += snprintf(sd+sd_len, sizeof(sd)-sd_len,
                        "%s ", qentry->data);
                hashes_sent++;
                qentry = TAILQ_NEXT(qentry, entries);
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
        
        /* SD ready, now format and sign */
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
                MIN(SIGN_MAX_HASH_NUM, sg_num_hashes), sg_num_hashes);

        omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
        TAILQ_FOREACH(fq, &sg->files, entries) {
                struct filed *f = fq->f;
                /* TODO: write fprintlog() wrapper for this */
                /* TODO: do not include this in repeat counts */
                if (f->f_prevcount)
                        fprintlog(f, NULL, NULL);
                f->f_repeatcount = 0;
                DELREF(f->f_prevmsg);
                f->f_prevmsg = NEWREF(buffer);
                fprintlog(f, NEWREF(buffer), NULL);
                DELREF(buffer);
                DELREF(buffer);
        }
        sign_inc_gbc();

        /* finally drop the oldest division of hashes */
        if (sg_num_hashes >= SIGN_HASH_NUM) {
                qentry = TAILQ_FIRST(&sg->hashes);
                for (int i = 0; i < SIGN_HASH_DIVISION_NUM; i++) {
                        old_qentry = qentry;
                        qentry = TAILQ_NEXT(old_qentry, entries);
                        TAILQ_REMOVE(&sg->hashes, old_qentry, entries);
                        FREEPTR(old_qentry->data);
                        FREEPTR(old_qentry);
                }
        }
        (void)sigsetmask(omask);
        return hashes_sent;
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

        DPRINTF((D_CALL|D_SIGN), "sign_msg_sign()\n");
        
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
        /* removes the string ' SIGN=""' */
        for (p = line, q = buf;
             *p && (q - buf <= SIGN_MAX_LENGTH);) {
                //if (*p == ' ') p++;
                if (*p == ' ' && *(p+1) == 'S' && *(p+2) == 'I'
                 && *(p+3) == 'G' && *(p+4) == 'N' && *(p+5) == '='
                 && *(p+6) == '"' && *(p+7) == '"')
                        p += 8;
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
        struct signature_group_t *sg;

        DPRINTF((D_CALL|D_SIGN), "sign_new_reboot_session()\n");

        /* global counters */
        GlobalSign.gbc = 0;
        /* might be useful for later analysis:
         * rebooted session IDs are sequential,
         * normal IDs are almost always not */
        GlobalSign.rsid++;

        assert(GlobalSign.sg == 3);
        /* reset SGs and send first CBs immediately */ 
        TAILQ_FOREACH(sg, &GlobalSign.SigGroups, entries) {
                sg->resendcount = SIGN_RESENDCOUNT_CERTBLOCK;
                sg->last_msg_num = 1;
                sign_send_certificate_block(sg);
        }
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