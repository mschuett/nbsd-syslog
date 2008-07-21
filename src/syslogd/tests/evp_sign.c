/*
 * evp_sign.c
 * First tries to transmit b64 encoded keys and check a signature
 *
 * Martin Schütte
 */
 
#include <stdio.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/x509.h>

#define BUFSIZE 2048
#define DSA_KEYSIZE 256

/* check OpenSSL return codes */
#define CHECK_ONE(exp) do if ((exp) != 1) {                                 \
                          printf(#exp " failed in %d: %s\n", __LINE__,      \
                                 ERR_error_string(ERR_get_error(), NULL));  \
                          return 1;                                         \
                       } while (0)
#define CHECK_PTR(exp) do if ((exp) == NULL) {                              \
                          printf(#exp " failed in %d: %s\n", __LINE__,      \
                                 ERR_error_string(ERR_get_error(), NULL));  \
                          return 1;                                         \
                       } while (0)

/* print binary data */
#define PRINT_HEX(name, addr, len) do {                 \
            printf("%s: ", name);                       \
            for (int i = 0; i < len; i++) {             \
               printf("%02X", (unsigned int) addr[i]);  \
            } printf("\n");                             \
        } while (0)

/* 
 * The OpenSSL docs mention "the newer EVP_VerifyDigest*() functions"
 * but I cannot find them in my openssl-0.9.8h :-(
 */


int
sign_msg_hash(unsigned char *line, unsigned char **hash)
{
        const EVP_MD *md;
        EVP_MD_CTX mdctx;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned char md_b64[EVP_MAX_MD_SIZE*2];
        unsigned int md_len;
        
        OpenSSL_add_all_digests();
        md = EVP_sha1();
        
        EVP_MD_CTX_init(&mdctx);
        CHECK_ONE(EVP_DigestInit_ex(&mdctx, md, NULL));
        CHECK_ONE(EVP_DigestUpdate(&mdctx, line, strlen((char *)line)));
        CHECK_ONE(EVP_DigestFinal_ex(&mdctx, md_value, &md_len));
        EVP_MD_CTX_cleanup(&mdctx);
        
        b64_ntop(md_value, md_len, (char *)md_b64, BUFSIZE);
        *hash = (unsigned char *)strdup((char *)md_b64);
        PRINT_HEX("Hash (DER)", md_value, md_len);
        printf("hash (b64): %s\n", *hash);
        return 0;
}

int
sign(EVP_PKEY *key, unsigned char *hash, unsigned char **signature)
{
        EVP_MD_CTX mdctx;
        const EVP_MD *md;
        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned char md_b64[EVP_MAX_MD_SIZE*2];
        unsigned int md_len;

        OpenSSL_add_all_digests();
        md = EVP_dss1();    /* DSA with SHA-1 */

        EVP_MD_CTX_init(&mdctx);
        CHECK_ONE(EVP_SignInit_ex(&mdctx, md, NULL));
        CHECK_ONE(EVP_SignUpdate(&mdctx, hash, strlen((char *)hash)));
        CHECK_ONE(EVP_SignFinal(&mdctx, md_value, &md_len, key));
        EVP_MD_CTX_cleanup(&mdctx);
        
        b64_ntop(md_value, md_len, (char *)md_b64, BUFSIZE);
        *signature = (unsigned char *)strdup((char *)md_b64);
        PRINT_HEX("Signature (DER)", md_value, md_len);
        printf("signature (b64): %s\n", *signature);

        return 0;
}

int
make_dsa(unsigned char **b64_pubkey, EVP_PKEY **key)
{
        unsigned char *der_pubkey = NULL, *ptr_der_pubkey = NULL;
        int der_len;
        DSA *dsa;
       
        CHECK_PTR(*key = EVP_PKEY_new()); 
        
        dsa = DSA_generate_parameters(DSA_KEYSIZE,
                NULL, 0, NULL, NULL, NULL, NULL);
        
        CHECK_ONE(DSA_generate_key(dsa));
        CHECK_ONE(EVP_PKEY_assign_DSA(*key, dsa));

        der_len = i2d_PUBKEY(*key, NULL);
        if (!(ptr_der_pubkey = der_pubkey = OPENSSL_malloc(der_len))) {
                printf("OPENSSL_malloc() failed\n");
                return 1;
        }
        if (i2d_PUBKEY(*key, &ptr_der_pubkey) <= 0) {
                printf("i2d_PUBKEY() failed\n");
                return 1;
        }

        *b64_pubkey = OPENSSL_malloc(der_len*2);
        b64_ntop(der_pubkey, der_len, (char *)*b64_pubkey, der_len*2);
        PRINT_HEX("public key (DER)", der_pubkey, der_len);
        printf("dsa public key(b64): %s\n", *b64_pubkey);

        return 0;
}


int
decode_pubkey(unsigned char *b64_pubkey, EVP_PKEY **key)
{
        unsigned char der_pubkey[BUFSIZE];
        const unsigned char *ptr_der_pubkey = &der_pubkey[0];
        long der_len;
       
        printf("decode_pubkey(%s)\n", b64_pubkey);
        der_len = b64_pton((char *)b64_pubkey, der_pubkey, BUFSIZE);

        printf("calling d2i_PUBKEY(NULL, %p, %ld)\n", ptr_der_pubkey, der_len);
        CHECK_PTR(*key = d2i_PUBKEY(NULL, &ptr_der_pubkey, der_len)); 
        PRINT_HEX("public key (DER)", der_pubkey, der_len);

        return 0;
}

int
check_sig(EVP_PKEY *key, unsigned char *b64_hash, unsigned char *b64_signature)
{
        EVP_MD_CTX mdctx;
        const EVP_MD *md;
        unsigned char der_sig[BUFSIZE], der_hash[BUFSIZE];
        long der_siglen, der_hashlen;
        int rc;
        
        
        der_hashlen = b64_pton((char *)b64_hash, der_hash, BUFSIZE);
        der_siglen = b64_pton((char *)b64_signature, der_sig, BUFSIZE);

        PRINT_HEX("recvd Hash (DER)", der_hash, der_hashlen);
        PRINT_HEX("recvd Sig (DER)", der_sig, der_siglen);
        
        md = EVP_dss1();    /* DSA with SHA-1 */
        EVP_MD_CTX_init(&mdctx);
        CHECK_ONE(EVP_VerifyInit(&mdctx, md));
        CHECK_ONE(EVP_VerifyUpdate(&mdctx, der_hash, der_hashlen));
        rc = EVP_VerifyFinal(&mdctx, der_sig, der_siglen, key);
        EVP_MD_CTX_cleanup(&mdctx);

        return rc;
        /* 1 for a correct signature,
         * 0 for failure and
         * -1 if some other error occurred
         */
}


int
makesig(unsigned char **pubkey, unsigned char **message, unsigned char **hash, unsigned char **signature)
{
        EVP_PKEY *key;
        *message = (unsigned char *)strdup("Hello World!");

        make_dsa(pubkey, &key);
        sign_msg_hash(*message, hash);
        sign(key, *hash, signature);
        return 0;
        
}

int
testsig(unsigned char *pubkey, unsigned char *message, unsigned char *hash, unsigned char *signature)
{
        EVP_PKEY *key;
        decode_pubkey(pubkey, &key);

        return check_sig(key, hash, signature);
}


int
main()
{
        unsigned char *pubkey, *message, *hash, *signature;
        int rc;
        
        if (!RAND_status())
                printf("Unable to initialize OpenSSL PRNG");
        else {
                printf("Initializing PRNG\n");
        }
        OpenSSL_add_all_digests();
        ERR_load_crypto_strings();

        (void)makesig(&pubkey, &message, &hash, &signature);
        rc = testsig(pubkey, message, hash, signature);
        if (rc == 1)
                printf("PASS\n");
        else if (rc == 0)
                printf("FAIL\n");
        else if (rc < 0)
                printf("ERROR, rc = %d\n", rc);
        else if (rc > 1)
                printf("UNKNOWN rc = %d\n", rc);
        return rc;
}
