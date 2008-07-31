/*
 * sign.c
 * syslog-sign related code for syslogd
 *
 * Martin Schütte
 */
/* 
 * Issues with the current internet draft: 
 * 1. The draft is a bit unclear on the input format for the signature,
 *    so this might have to be changed later. Cf. sign_string_sign()
 * 2. The draft only defines DSA signatures. I hope it will be extended
 *    to DSS, thus allowing DSA, RSA (ANSI X9.31) and ECDSA (ANSI X9.62)
 * 3. The draft does not define the data format for public keys in CBs.
 *    This implementation sends public keys in DER encoding.
 * 4. This current implementation uses high-level OpenSSL API.
 *    I am not sure if these completely implement the FIPS/ANSI standards.
 */
/* 
 * Limitations of this implementation:
 * - cannot use OpenPGP keys, only PKIX or DSA due to OpenSSL capabilities
 * - currently no SG 2
 * - due to the splitting and formatting this syslogd modifies messages
 *   (e.g. if it receives a message with two spaces between fields it will
 *   not forward the message unchanged). This would invalidate signatures,
 *   so all devices using syslog-sign should only emit correct syslog-protocol
 *   formatted messages.
 */
#ifndef DISABLE_SIGN
#include "syslogd.h"
#ifndef DISABLE_TLS
#include "tls_stuff.h"
#endif /* !DISABLE_TLS */
#include "sign.h"

/* definitions in syslogd.c */
extern short    Debug;
extern unsigned GlobalMsgCounter;
extern time_t   now;
extern char     timestamp[];
extern char    *LocalFQDN;
extern struct filed               *Files;
extern struct sign_global_t        GlobalSign;
extern struct tls_global_options_t tls_opt;

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
        DPRINTF((D_CALL|D_SIGN), "sign_global_init()\n");
        if (alg > 3) {
                logerror("sign_init(): invalid alg %d", alg);
                return false;
        }

        if (!sign_get_keys())
                return false;

        assert(GlobalSign.keytype == 'C' || GlobalSign.keytype == 'K');
        assert(GlobalSign.pubkey_b64 && GlobalSign.privkey && GlobalSign.pubkey);
        assert(GlobalSign.privkey->pkey.dsa->priv_key);

        GlobalSign.sg = alg;
        GlobalSign.gbc = 0;
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
                logerror("EVP_PKEY_type not supported for signing");
                return false;
        }

        if (!sign_sg_init(Files))
                return false;
        sign_new_reboot_session();
        
        DPRINTF(D_SIGN, "length values: SIGN_MAX_SD_LENGTH %d, "
                "SIGN_MAX_FRAG_LENGTH %d, SIGN_MAX_SB_LENGTH %d, "
                "SIGN_MAX_HASH_NUM %d\n", SIGN_MAX_SD_LENGTH,
                SIGN_MAX_FRAG_LENGTH, SIGN_MAX_SB_LENGTH, SIGN_MAX_HASH_NUM);

        /* set just before return, so it indicates initialization */
        GlobalSign.rsid = now;
        return true;
}

/*
 * get keys for syslog-sign
 * either from the X.509 certificate used for TLS
 * or by generating a new one
 * 
 * sets the global variables
 * GlobalSign.keytype, GlobalSign.pubkey_b64,
 * GlobalSign.privkey, and GlobalSign.pubkey
 */
bool
sign_get_keys()
{
#ifndef DISABLE_TLS
        FILE  *keyfile, *certfile;
#endif /* !DISABLE_TLS */
        EVP_PKEY *pubkey = NULL, *privkey = NULL;
        unsigned char *der_pubkey = NULL, *ptr_der_pubkey = NULL;
        char *pubkey_b64 = NULL;
        int der_len;
        errno = 0;
        
        /* try PKIX/TLS keys first */
#ifndef DISABLE_TLS
        if (tls_opt.keyfile && tls_opt.certfile
         && (keyfile = fopen(tls_opt.keyfile, "r"))
         && (certfile = fopen(tls_opt.certfile, "r"))) {
                X509 *cert;
                
                DPRINTF(D_SIGN, "Try to get keys from X.509 ...\n");
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
#endif /* !DISABLE_TLS */
        if (!(privkey && pubkey)) { /* PKIX not available --> generate key */
                DSA *dsa;

                DPRINTF(D_SIGN, "Unable to get keys from X.509 "
                        "--> use DSA with type 'K'\n");
                if (!(privkey = EVP_PKEY_new())) {
                        logerror("EVP_PKEY_new() failed");
                        return false;
                }
                dsa = DSA_generate_parameters(SIGN_GENCERT_BITS, NULL, 0,
                        NULL, NULL, NULL, NULL);
                if (!DSA_generate_key(dsa)) {
                        logerror("DSA_generate_key() failed");
                        return false;
                }
                if (!EVP_PKEY_assign_DSA(privkey, dsa)) {
                        logerror("EVP_PKEY_assign_DSA() failed");
                        return false;
                }
                GlobalSign.keytype = 'K';  /* public/private keys used */
                GlobalSign.privkey = privkey;
                GlobalSign.pubkey = privkey;

                /* pubkey base64 encoding */
                der_len = i2d_DSA_PUBKEY(dsa, NULL);
                if (!(ptr_der_pubkey = der_pubkey = malloc(der_len))
                 || !(pubkey_b64 = malloc(der_len*2))) {
                        free(der_pubkey);
                        logerror("malloc() failed");
                        return false;
                }
                if (i2d_DSA_PUBKEY(dsa, &ptr_der_pubkey) <= 0) {
                        logerror("i2d_DSA_PUBKEY() failed");
                        return false;
                }
                b64_ntop(der_pubkey, der_len, pubkey_b64, der_len*2);
                free(der_pubkey);
                /* try to resize memory object as needed */
                GlobalSign.pubkey_b64 = realloc(pubkey_b64, strlen(pubkey_b64)+1);
                if (!GlobalSign.pubkey_b64)
                        GlobalSign.pubkey_b64 = pubkey_b64;
        }
        return true;
}

/*
 * init SGs 
 */
bool
sign_sg_init(struct filed *Files)
{
        struct signature_group_t *newsg;
        struct filed_queue       *fq;

        switch (GlobalSign.sg) {
        case 0:
                /* one SG, linked to all files */
                newsg = calloc(1, sizeof(*newsg));
                newsg->last_msg_num = 1; /* cf. section 4.2.5 */
                TAILQ_INIT(&newsg->hashes);
                TAILQ_INIT(&newsg->files);
                for (struct filed *f = Files; f; f = f->f_next) {
                        if (!(f->f_flags & FFLAG_SIGN)) {
                                f->f_sg = NULL;
                                continue;
                        }
                        fq    = calloc(1, sizeof(*fq));
                        fq->f = f;
                        f->f_sg = newsg;
                        TAILQ_INSERT_TAIL(&newsg->files, fq, entries);
                }
                TAILQ_INSERT_TAIL(&GlobalSign.SigGroups,
                        newsg, entries);
                break;
        case 1:
                /* every PRI gets one SG */
                for (int i = 0; i <= (LOG_NFACILITIES<<3); i++) {
                        int fac, prilev;
                        fac = LOG_FAC(i);
                        prilev = LOG_PRI(i);

                        newsg = calloc(1, sizeof(*newsg));
                        newsg->spri = i;
                        newsg->last_msg_num = 1; /* cf. section 4.2.5 */
                        TAILQ_INIT(&newsg->hashes);
                        TAILQ_INIT(&newsg->files);
                        for (struct filed *f = Files; f; f = f->f_next) {
                                if (!(f->f_flags & FFLAG_SIGN))
                                        continue;
                                /* check priorities */
                                if (((f->f_pcmp[fac] & PRI_EQ) && (f->f_pmask[fac] == prilev))
                                     ||((f->f_pcmp[fac] & PRI_LT) && (f->f_pmask[fac] < prilev))
                                     ||((f->f_pcmp[fac] & PRI_GT) && (f->f_pmask[fac] > prilev))) {
                                        fq    = calloc(1, sizeof(*fq));
                                        fq->f = f;
                                        TAILQ_INSERT_TAIL(&newsg->files, fq, entries);
                                }
                        }
                        TAILQ_INSERT_TAIL(&GlobalSign.SigGroups,
                                newsg, entries);
                        /* possible optimization: use a
                         * struct signature_group_t *newsg[LOG_NFACILITIES<<3]
                         * for direct group lookup */
                }
                for (struct filed *f = Files; f; f = f->f_next)
                        /* f_sg is useless here */
                        f->f_sg = NULL;
                break;
        case 2:
                /* PRI ranges get one SG, boundaries given by the
                 * SPRI, indicating the largest PRI in the SG */
                /* TODO: do not know how to configure that
                 *  possibly with a list of boundary values */
                logerror("SG == 2 not implemented yet");
                return false;
                break;
        case 3:
                /* every file gets one SG */ 
                for (struct filed *f = Files; f; f = f->f_next) {
                        if (!(f->f_flags & FFLAG_SIGN)) {
                                f->f_sg = NULL;
                                continue;
                        }
                        //CALLOC(newsg, sizeof(*newsg));
                        newsg = calloc(1, sizeof(*newsg));
                        newsg->spri = f->f_file; /* not needed but shows SGs */
                        newsg->last_msg_num = 1; /* cf. section 4.2.5 */
                        fq    = calloc(1, sizeof(*fq));
                        fq->f = f;
                        f->f_sg = newsg;
                        TAILQ_INIT(&newsg->hashes);
                        TAILQ_INIT(&newsg->files);
                        TAILQ_INSERT_TAIL(&newsg->files, fq, entries);
                        TAILQ_INSERT_TAIL(&GlobalSign.SigGroups,
                                newsg, entries);
                }
                break;
        }
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

        DPRINTF((D_CALL|D_SIGN), "sign_global_free()\n");
        if (!GlobalSign.rsid)  /* never initialized */
                return;

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
        if (GlobalSign.pubkey != GlobalSign.privkey)
                FREEPTR(GlobalSign.pubkey);
        FREEPTR(GlobalSign.privkey);
        FREEPTR(GlobalSign.pubkey_b64);
        if(GlobalSign.mdctx)
                EVP_MD_CTX_destroy(GlobalSign.mdctx);
        if(GlobalSign.sigctx)
                EVP_MD_CTX_destroy(GlobalSign.sigctx);
}

/*
 * create and send certificate block
 */
bool
sign_send_certificate_block(struct signature_group_t *sg)
{
        struct filed_queue *fq;
        struct buf_msg *buffer;
        char *timestamp;
        char payload[SIGN_MAX_PAYLOAD_LENGTH];
        char sd[SIGN_MAX_SD_LENGTH];
        int omask, tmpcnt;
        size_t payload_len, sd_len, fragment_len;
        size_t payload_index = 0;

        /* do nothing if CBs already sent or if there was no message in SG */
        if (!sg->resendcount
         || ((sg->resendcount == SIGN_RESENDCOUNT_CERTBLOCK)
             && TAILQ_EMPTY(&sg->hashes)))
                return false;

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

                /* format SD */
                sd_len = snprintf(sd, sizeof(sd), "[ssign-cert "
                        "VER=\"%s\" RSID=\"%llu\" SG=\"%d\" "
                        "SPRI=\"%d\" TBPL=\"%d\" INDEX=\"%d\" "
                        "FLEN=\"%d\" FRAG=\"%.*s\" "
                        "SIGN=\"\"]",
                        GlobalSign.ver, GlobalSign.rsid, GlobalSign.sg,
                        sg->spri, payload_len, payload_index+1, /* cf. section 5.3.2.5 */
                        fragment_len, fragment_len, &payload[payload_index]);
                assert(sd_len < sizeof(sd));
                assert(sd[sd_len] == '\0');
                assert(sd[sd_len-1] == ']');
                assert(sd[sd_len-2] == '"');
                
                if (!sign_msg_sign(&buffer, sd, sizeof(sd)))
                        return 0;
                DPRINTF((D_CALL|D_SIGN), "sign_send_certificate_block(): "
                        "calling fprintlog()\n");

                omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
                TAILQ_FOREACH(fq, &sg->files, entries) {
                        /* we have to preserve the f_prevcount */
                        tmpcnt = fq->f->f_prevcount;
                        fprintlog(fq->f, buffer, NULL);
                        fq->f->f_prevcount = tmpcnt;
                }
                sign_inc_gbc();
                DELREF(buffer);
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
sign_get_sg(int pri, struct filed *f)
{
        struct signature_group_t *sg;
        DPRINTF((D_CALL|D_SIGN), "sign_get_sg(%d, %p)\n", pri, f);
        
        if (!GlobalSign.rsid)
                return NULL;
        
        switch (GlobalSign.sg) {
        case 0:
        case 3:
                return f->f_sg;
                break;
        case 1:
        case 2:
                TAILQ_FOREACH(sg, &GlobalSign.SigGroups, entries) {
                        if (sg->spri >= pri) return sg;
                }
                break;
        }
        return NULL;
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
        size_t sd_len;
        int omask, tmpcnt;
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

        /* if no CB sent so far then do now, just before first SB */
        if (sg->resendcount == SIGN_RESENDCOUNT_CERTBLOCK)
                sign_send_certificate_block(sg);
        
        /* shortly after reboot we have shorter SBs */
        hashes_in_sb = MIN(sg_num_hashes, SIGN_HASH_NUM);
        
        DPRINTF(D_SIGN, "sign_send_signature_block(): "
                "sg_num_hashes = %d, hashes_in_sb = %d, SIGN_HASH_NUM = %d\n",
                sg_num_hashes, hashes_in_sb, SIGN_HASH_NUM);
        if (sg_num_hashes > SIGN_HASH_NUM) {
                DPRINTF(D_SIGN, "sign_send_signature_block(): sg_num_hashes"
                        " > SIGN_HASH_NUM -- This should not happen!\n");
        }

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

        if (sign_msg_sign(&buffer, sd, sizeof(sd))) {
                DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block(): calling"
                        " fprintlog(), sending %d out of %d hashes\n",
                        MIN(SIGN_MAX_HASH_NUM, sg_num_hashes), sg_num_hashes);
        
                omask = sigblock(sigmask(SIGHUP)|sigmask(SIGALRM));
                TAILQ_FOREACH(fq, &sg->files, entries) {
                        tmpcnt = fq->f->f_prevcount;
                        fprintlog(fq->f, buffer, NULL);
                        fq->f->f_prevcount = tmpcnt;
                }
                sign_inc_gbc();
                DELREF(buffer);
                (void)sigsetmask(omask);
        }
        /* always drop the oldest division of hashes */
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
        return hashes_sent;
}

void
sign_free_hashes(struct signature_group_t *sg)
{
        struct string_queue *qentry, *tmp_qentry;
        
        DPRINTF((D_CALL|D_SIGN), "sign_free_hashes(%p)\n", sg);
        TAILQ_FOREACH_SAFE(qentry, &sg->hashes, entries, tmp_qentry) {
                TAILQ_REMOVE(&sg->hashes, qentry, entries);
                FREEPTR(qentry->data);
                free(qentry);
        }
        assert(TAILQ_EMPTY(&sg->hashes));
}

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
        
        SSL_CHECK_ONE(EVP_DigestInit_ex(GlobalSign.mdctx, GlobalSign.md, NULL));
        SSL_CHECK_ONE(EVP_DigestUpdate(GlobalSign.mdctx, line, strlen(line)));
        SSL_CHECK_ONE(EVP_DigestFinal_ex(GlobalSign.mdctx, md_value, &md_len));
        
        b64_ntop(md_value, md_len, (char *)md_b64, EVP_MAX_MD_SIZE*2);
        *hash = strdup((char *)md_b64);

        DPRINTF((D_CALL|D_SIGN), "sign_msg_hash() --> \"%s\"\n", *hash);
        return true;
}

/*
 * append hash to SG queue
 */
bool
sign_append_hash(char *hash, struct signature_group_t *sg)
{
        struct string_queue *qentry;

        /* if one SG is shared by several destinations
         * prevent duplicate entries */
        if ((qentry = TAILQ_LAST(&sg->hashes, string_queue_head))
          && !strcmp(qentry->data, hash)) {
                DPRINTF((D_CALL|D_SIGN), "sign_append_hash('%s', %p): "
                        "hash already in queue\n", hash, sg);
                return false;
        }

        MALLOC(qentry, sizeof(*qentry));
        qentry->key = sign_assign_msg_num(sg);
        qentry->data = hash;
        TAILQ_INSERT_TAIL(&sg->hashes, qentry, entries);
        DPRINTF((D_CALL|D_SIGN), "sign_append_hash('%s', %p): "
                "#%lld\n", hash, sg, qentry->key);
        return true;
}

/*
 * sign one syslog-sign message
 * 
 * requires a ssign or ssigt-cert SD element
 * ending with ' SIGN=""]' in sd
 * linesize is available memory (= sizeof(sd))
 * 
 * function will calculate signature and return a new buffer
 */
bool
sign_msg_sign(struct buf_msg **bufferptr, char *sd, size_t linesize)
{
        char *signature, *line;
        size_t linelen, tlsprefixlen, endptr, newlinelen;
        struct buf_msg *buffer;

        DPRINTF((D_CALL|D_SIGN), "sign_msg_sign()\n");
        endptr = strlen(sd);

        assert(endptr < linesize);
        assert(sd[endptr] == '\0');
        assert(sd[endptr-1] == ']');
        assert(sd[endptr-2] == '"');

        /* set up buffer */
        buffer = buf_msg_new(0);
        buffer->timestamp = strdup(make_timestamp(NULL, true));
        buffer->prog = strdup("syslogd");
        buffer->recvhost = buffer->host = LocalFQDN;
        buffer->pri = 110;
        buffer->flags = IGN_CONS|SIGNATURE;
        buffer->sd = sd;

        /* SD ready, now format and sign */
        if (!format_buffer(buffer, &line, &linelen, NULL,
                &tlsprefixlen, NULL)) {
                DPRINTF((D_CALL|D_SIGN), "sign_send_signature_block():"
                        " format_buffer() failed\n");
                buffer->sd = NULL;
                DELREF(buffer);
                return false;
        }
        sign_string_sign(line+tlsprefixlen, &signature);

        sd[endptr-2] = '\0';
        newlinelen = strlcat(sd, signature, linesize);
        newlinelen = strlcat(sd, "\"]", linesize);
        
        if (newlinelen >= linesize) {
                DPRINTF(D_SIGN, "sign_send_signature_block(): buffer too small\n");
                buffer->sd = NULL;
                DELREF(buffer);
                return false;
        }
        assert(newlinelen < linesize);
        DPRINTF(D_SIGN, "sign_send_signature_block(): endptr=%d, linesize=%d, newlinelen=%d, %s\n", endptr, linesize, newlinelen, sd);
        
        assert(sd[newlinelen] == '\0');
        assert(sd[newlinelen-1] == ']');
        assert(sd[newlinelen-2] == '"');

        buffer->sd = strdup(sd);
        *bufferptr = buffer;
        return true;
}

/*
 * sign one string
 */
bool
sign_string_sign(char *line, char **signature)
{
        char buf[SIGN_MAX_LENGTH+1];
        unsigned char sig_value[EVP_MAX_MD_SIZE];
        unsigned char sig_b64[EVP_MAX_MD_SIZE*2];
        unsigned int sig_len = 0;
        char *p, *q;

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

        SSL_CHECK_ONE(EVP_SignInit(GlobalSign.sigctx, GlobalSign.sig));
        SSL_CHECK_ONE(EVP_SignUpdate(GlobalSign.sigctx, buf, q-buf));
        assert(GlobalSign.privkey);
        assert(EVP_MAX_MD_SIZE > EVP_PKEY_size(GlobalSign.privkey));
        SSL_CHECK_ONE(EVP_SignFinal(GlobalSign.sigctx, sig_value, &sig_len, GlobalSign.privkey));
        
        b64_ntop(sig_value, sig_len, (char *)sig_b64, EVP_MAX_MD_SIZE*2);
        *signature = strdup((char *)sig_b64);

        DPRINTF((D_CALL|D_SIGN), "sign_string_sign('%s') --> '%s'\n", buf, *signature);
        return (bool) *signature;
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

        assert(GlobalSign.sg <= 3);
        /* reset SGs */
        TAILQ_FOREACH(sg, &GlobalSign.SigGroups, entries) {
                sg->resendcount = SIGN_RESENDCOUNT_CERTBLOCK;
                sg->last_msg_num = 1;
        }
}

/* get msg_num, increment counter, check overflow */
uint_fast64_t
sign_assign_msg_num(struct signature_group_t *sg)
{
        uint_fast64_t old;

        old = sg->last_msg_num++;
        if (sg->last_msg_num > SIGN_MAX_COUNT)
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