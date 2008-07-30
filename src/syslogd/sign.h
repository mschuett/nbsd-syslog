/*
 * sign.h
 * 
 */
#ifndef SIGN_H_
#define SIGN_H_

#include <netinet/in.h>
#include <resolv.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

/* default Signature Group value,
 * defines signature strategy:
 * 0 one global SG
 * 1 one SG per PRI
 * 2 SGs for PRI ranges
 * 3 other (SGs not defined by PRI)
 * 
 * We use '3' and assign one SG to every destination (=struct filed)
 */
#define SIGN_SG 3

/* maximum value for several counters in -sign */
#define SIGN_MAX_COUNT  9999999999

/*
 * many of these options could be made user configurable if desired,
 * but I do not see the need for that
 */

/* redundancy options */
/* 
 * note on the implementation of redundancy:
 * - certificate blocks: first CB is sent immediately on session (re)boot.
 *   resends are called by domark() until resend count is reached.
 *   alternative: put extra timer for this into signature_group_t
 *   --> for now it works. final decision when other SG algorithms are implemented
 * - signature blocks: to send every hash n times I use a sliding window.
 *   the hashes in every SB are grouped into n divisions:
 *   * the 1st hashcount/n hashes are sent for the 1st time
 *   * the 2nd hashcount/n hashes are sent for the 2nd time
 *   * ...
 *   * the n-th hashcount/n hashes are sent for the n-th time and deleted thereafter
 */ 
#define SIGN_RESENDCOUNT_CERTBLOCK  1
#define SIGN_RESENDCOUNT_HASHES     3

/* maximum length of syslog-sign messages */
#define SIGN_MAX_LENGTH 2048
// 2048 by standard, I only use smaller values to test correct fragmentation
//#define SIGN_MAX_LENGTH 512
/* the length we can use for the SD and keep the
 * message length with header below 2048 octets */
#define SIGN_MAX_SD_LENGTH (SIGN_MAX_LENGTH - 1 - HEADER_LEN_MAX)
/* the maximum length of one payload fragment:
 * max.SD len - text - max. field lengths - sig len */
#define SIGN_MAX_FRAG_LENGTH (SIGN_MAX_SD_LENGTH - 82 - 38 - GlobalSign.sig_len_b64)
/* the maximum length of one signature block:
 * max.SD len - text - max. field lens - sig len */
#define SIGN_MAX_SB_LENGTH SIGN_MAX_FRAG_LENGTH
/* the maximum number of hashes pec signature block */
#define SIGN_MAX_HASH_NUM (SIGN_MAX_SB_LENGTH / GlobalSign.md_len_b64)
/* number of hashes in one signature block */
#define SIGN_HASH_NUM_WANT 100
/* make sure to consider SIGN_MAX_HASH_NUM and
 * to have a SIGN_HASH_NUM that is a multiple of SIGN_HASH_DIVISION_NUM */
#define SIGN_HASH_DIVISION_NUM (MIN(SIGN_HASH_NUM_WANT, SIGN_MAX_HASH_NUM) / SIGN_RESENDCOUNT_HASHES)
#define SIGN_HASH_NUM (SIGN_HASH_DIVISION_NUM * SIGN_RESENDCOUNT_HASHES) 

/* the length of payload strings
 * since the payload is fragmented there is no technical limit
 * it just has to be big enough to hold big b64 encoded PKIX certificates
 */
#define SIGN_MAX_PAYLOAD_LENGTH 20480

/* length of generated DSA keys for signing */
#define SIGN_GENCERT_BITS 1024

#define SSL_CHECK_ONE(exp) do if ((exp) != 1) {                                  \
                       DPRINTF(D_SIGN, #exp " failed in %d: %s\n", __LINE__, \
                             ERR_error_string(ERR_get_error(), NULL));       \
                       return 1;                                             \
                    } while (0)

/* structs use uint_fast64_t in different places because the standard
 * requires values in interval [0:9999999999 = SIGN_MAX_COUNT] */
 
/* queue of C-Strings (here used for hashes) */
struct string_queue {
        uint_fast64_t  key;
        char          *data;
        TAILQ_ENTRY(string_queue) entries;
};
TAILQ_HEAD(string_queue_head, string_queue);

/* queue of destinations (used associate SGs and fileds) */
struct filed_queue {
        struct filed             *f;
        TAILQ_ENTRY(filed_queue) entries;
};
TAILQ_HEAD(filed_queue_head, filed_queue);

/* queue of Signature Groups */
struct signature_group_t {
        unsigned int                   spri;
        unsigned int                   resendcount;
        uint_fast64_t                  last_msg_num;
        struct string_queue_head       hashes;
        struct filed_queue_head        files;
        TAILQ_ENTRY(signature_group_t) entries;
};
TAILQ_HEAD(signature_group_head, signature_group_t);

/* all global variables for sign */
struct sign_global_t {
        /* params for signature block, named as in RFC nnnn */
        const char   *ver;
        uint_fast64_t rsid;
        unsigned int  sg;
        uint_fast64_t gbc;

        struct signature_group_head SigGroups;
        EVP_PKEY     *privkey;
        EVP_PKEY     *pubkey;
        char         *pubkey_b64;
        char          keytype;
        
        EVP_MD_CTX   *mdctx;       /* hashing context */
        const EVP_MD *md;          /* hashing method/algorithm */
        unsigned int  md_len_b64;  /* length of b64 hash value */

        EVP_MD_CTX   *sigctx;      /* signature context */
        const EVP_MD *sig;         /* signature method/algorithm */
        unsigned int  sig_len_b64; /* length of b64 signature */
};

bool sign_global_init(unsigned, struct filed*);
bool sign_sg_init(struct filed*);
bool sign_get_keys();
void sign_global_free();
struct signature_group_t *sign_get_sg(int, struct filed*);
bool sign_send_certificate_block(struct signature_group_t*);
unsigned sign_send_signature_block(struct signature_group_t*, bool);
void sign_free_hashes(struct signature_group_t*);
bool sign_msg_hash(char*, char**);
bool sign_append_hash(char*, struct signature_group_t*);
bool sign_msg_sign(struct buf_msg**, char*, size_t);
bool sign_string_sign(char*, char**);
void sign_new_reboot_session(void);
void sign_inc_gbc(void);
uint_fast64_t sign_assign_msg_num(struct signature_group_t*);

#endif /* SIGN_H_ */
