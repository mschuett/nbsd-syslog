/*
 * sign.h
 * 
 */
#ifndef SIGN_H_
#define SIGN_H_

#include <netinet/in.h>
#include <resolv.h>

/* Signature Group value
 * defines signature strategy:
 * 
 * 0 one global SG
 * 1 one SG per PRI
 * 2 SGs for PRI ranges
 * 3 other (SGs not defined by PRI)
 * 
 * We use '3' and assign one SG to every destination (=struct filed)
 */
#define SIGN_SG 3

#define SIGN_MAX_COUNT  9999999999
/* maximum length of syslog-sign messages */
#define SIGN_MAX_LENGTH 2048
/* the length we can use for the SD and keep the
 * message length with header below 2048 octets */
#define SIGN_MAX_SD_LENGTH (SIGN_MAX_LENGTH - 100)
/* the maximum length of one payload fragment:
 * max.SD len - text - max. field lens - sig len */
#define SIGN_MAX_FRAG_LENGTH (SIGN_MAX_SD_LENGTH - 82 - 38 - GlobalSign.sig_len_b64)
/* the maximum length of one signature block:
 * max.SD len - text - max. field lens - sig len */
#define SIGN_MAX_SB_LENGTH SIGN_MAX_FRAG_LENGTH
/* the maximum number of hashes pec signature block */
#define SIGN_MAX_HASH_NUM (SIGN_MAX_SB_LENGTH / GlobalSign.md_len_b64)
/* send signature block after this number of messages */
#define SIGN_HASH_NUM MIN(10, (SIGN_MAX_HASH_NUM-3))

/* queue of C-Strings (here used for hashes) */
struct string_queue {
        uint_fast64_t  key;
        char          *data;
        TAILQ_ENTRY(string_queue) entries;
};
TAILQ_HEAD(string_queue_head, string_queue);

/* use uint_fast64_t in different places because the standard
 * requires values in interval [0:9999999999 = SIGN_MAX_COUNT] */

/* queue of Signature Groups */
struct signature_group_t {
        unsigned                       spri;
        uint_fast64_t                  last_msg_num;
        struct string_queue_head       hashes;
        TAILQ_ENTRY(signature_group_t) entries;
};
TAILQ_HEAD(signature_group_head, signature_group_t);

/* all global variables for sign */
struct sign_global_t {
        /* params for signature block, named as in RFC nnnn */
        const char   *ver;
        uint_fast64_t rsid;
        unsigned      sg;
        unsigned      spri;
        uint_fast64_t gbc;

        struct signature_group_head SigGroups;
        EVP_PKEY     *privkey;
        EVP_PKEY     *pubkey;
        char         *pubkey_b64;
        char          keytype;
        
        EVP_MD_CTX   *mdctx;       /* hashing context */
        const EVP_MD *md;          /* hashing method/algorithm */
        unsigned      md_len_b64;  /* length of b64 hash value */

        EVP_MD_CTX   *sigctx;      /* signature context */
        const EVP_MD *sig;         /* signature method/algorithm */
        unsigned      sig_len_b64; /* length of b64 signature */
};

bool sign_global_init(unsigned, struct filed*);
void sign_global_free(struct filed*);
struct signature_group_t *sign_get_sg(int, struct signature_group_head*, struct filed*);
bool sign_send_certificate_block(struct filed*);
unsigned sign_send_signature_block(struct signature_group_t*, struct filed*);
void sign_free_hashes(struct signature_group_t*);
bool sign_msg_hash(char*, char**);
bool sign_append_hash(char*, struct signature_group_t*);
bool sign_msg_sign(char*, char**);
void sign_new_reboot_session(void);
void sign_inc_gbc(void);
uint_fast64_t sign_assign_msg_num(struct signature_group_t*);

#endif /* SIGN_H_ */
