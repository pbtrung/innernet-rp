/* Test-only oracle: independent OpenSSL and leancrypto ML-KEM/X448 endpoints.
 * Fixed seeds are public test material. Never compile this into a product. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <leancrypto/lc_init.h>
#include <leancrypto/lc_kyber.h>
#include <leancrypto/lc_x448.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define REQUIRE(expression) do { if (!(expression)) { \
    fprintf(stderr, "independent crypto check failed at line %d\n", __LINE__); \
    return 1; } } while (0)

static int hybrid_interop(EVP_PKEY *kem, const struct lc_kyber_1024_pk *pk,
                          const struct lc_kyber_1024_sk *sk) {
    unsigned char private[56], ephemeral_private[56], public[56], ephemeral_public[56];
    unsigned char kem_ct[1568], kem_ss[32], xss[56];
    size_t size, ct_size, ss_size;
    EVP_PKEY_CTX *ctx;
    struct lc_kyber_x448_pk hybrid_pk = {0};
    struct lc_kyber_x448_sk hybrid_sk = {0};
    struct lc_kyber_x448_ct hybrid_ct = {0};
    struct lc_kyber_x448_ss hybrid_ss = {0};
    unsigned char *k, *x; size_t kl, xl;
    memset(private, 0x11, sizeof(private));
    memset(ephemeral_private, 0x42, sizeof(ephemeral_private));
    EVP_PKEY *recipient = EVP_PKEY_new_raw_private_key_ex(NULL, "X448", NULL, private, 56);
    EVP_PKEY *ephemeral = EVP_PKEY_new_raw_private_key_ex(NULL, "X448", NULL, ephemeral_private, 56);
    REQUIRE(recipient && ephemeral);
    size = 56;
    REQUIRE(EVP_PKEY_get_raw_public_key(recipient, public, &size) > 0 && size == 56);
    size = 56;
    REQUIRE(EVP_PKEY_get_raw_public_key(ephemeral, ephemeral_public, &size) > 0 && size == 56);
    REQUIRE(lc_kyber_x448_pk_load(&hybrid_pk, pk->pk, 1568, public, 56) == 0);
    REQUIRE(lc_kyber_x448_sk_load(&hybrid_sk, sk->sk, 3168, private, 56) == 0);

    /* Independent OpenSSL encapsulation -> leancrypto's combined decapsulation. */
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, kem, NULL);
    REQUIRE(ctx && EVP_PKEY_encapsulate_init(ctx, NULL) > 0);
    ct_size = 1568; ss_size = 32;
    REQUIRE(EVP_PKEY_encapsulate(ctx, kem_ct, &ct_size, kem_ss, &ss_size) > 0);
    REQUIRE(ct_size == 1568 && ss_size == 32);
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, ephemeral, NULL);
    REQUIRE(ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, recipient) > 0);
    size = 56;
    REQUIRE(EVP_PKEY_derive(ctx, xss, &size) > 0 && size == 56);
    EVP_PKEY_CTX_free(ctx);
    REQUIRE(lc_kyber_x448_ct_load(&hybrid_ct, kem_ct, 1568, ephemeral_public, 56) == 0);
    REQUIRE(lc_kyber_x448_dec(&hybrid_ss, &hybrid_ct, &hybrid_sk) == 0);
    REQUIRE(lc_kyber_x448_ss_ptr(&k, &kl, &x, &xl, &hybrid_ss) == 0);
    REQUIRE(kl == 32 && xl == 56 && !CRYPTO_memcmp(k, kem_ss, kl) && !CRYPTO_memcmp(x, xss, xl));

    /* leancrypto's combined encapsulation -> independent OpenSSL decapsulation. */
    REQUIRE(lc_kyber_x448_enc(&hybrid_ct, &hybrid_ss, &hybrid_pk) == 0);
    REQUIRE(lc_kyber_x448_ct_ptr(&k, &kl, &x, &xl, &hybrid_ct) == 0);
    REQUIRE(kl == 1568 && xl == 56);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, kem, NULL);
    REQUIRE(ctx && EVP_PKEY_decapsulate_init(ctx, NULL) > 0);
    ss_size = 32;
    REQUIRE(EVP_PKEY_decapsulate(ctx, kem_ss, &ss_size, k, kl) > 0 && ss_size == 32);
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(ephemeral);
    ephemeral = EVP_PKEY_new_raw_public_key_ex(NULL, "X448", NULL, x, xl);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, recipient, NULL);
    REQUIRE(ephemeral && ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, ephemeral) > 0);
    size = 56;
    REQUIRE(EVP_PKEY_derive(ctx, xss, &size) > 0 && size == 56);
    REQUIRE(lc_kyber_x448_ss_ptr(&k, &kl, &x, &xl, &hybrid_ss) == 0);
    REQUIRE(kl == 32 && xl == 56 && !CRYPTO_memcmp(k, kem_ss, kl) && !CRYPTO_memcmp(x, xss, xl));
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(recipient); EVP_PKEY_free(ephemeral);
    OPENSSL_cleanse(private, sizeof(private)); OPENSSL_cleanse(ephemeral_private, sizeof(ephemeral_private));
    OPENSSL_cleanse(kem_ss, sizeof(kem_ss)); OPENSSL_cleanse(xss, sizeof(xss));
    OPENSSL_cleanse(&hybrid_sk, sizeof(hybrid_sk)); OPENSSL_cleanse(&hybrid_ss, sizeof(hybrid_ss));
    return 0;
}

int main(void) {
    unsigned char seed[64], pub[1568], priv[3168], ciphertext[1568], secret[56];
    struct lc_kyber_1024_pk lp;
    struct lc_kyber_1024_sk ls;
    struct lc_kyber_1024_ct ct;
    struct lc_kyber_1024_ss ss;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx;
    size_t size, ct_size, ss_size;
    for (size_t i = 0; i < sizeof(seed); ++i) seed[i] = (unsigned char)i;
    REQUIRE(lc_init(LC_INIT_NON_PQC_ENABLED) == 0);
    REQUIRE(lc_kyber_1024_keypair_from_seed(&lp, &ls, seed, sizeof(seed)) == 0);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-1024", NULL);
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof(seed)),
        OSSL_PARAM_END
    };
    REQUIRE(ctx && EVP_PKEY_fromdata_init(ctx) > 0);
    REQUIRE(EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) > 0);
    EVP_PKEY_CTX_free(ctx);
    REQUIRE(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                           pub, sizeof(pub), &size) > 0);
    REQUIRE(size == sizeof(pub) && !memcmp(pub, &lp, size));
    REQUIRE(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
                                           priv, sizeof(priv), &size) > 0);
    REQUIRE(size == sizeof(priv) && !memcmp(priv, &ls, size));
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    REQUIRE(ctx && EVP_PKEY_encapsulate_init(ctx, NULL) > 0);
    ct_size = sizeof(ciphertext); ss_size = 32;
    REQUIRE(EVP_PKEY_encapsulate(ctx, ciphertext, &ct_size, secret, &ss_size) > 0);
    REQUIRE(ct_size == sizeof(ct) && ss_size == sizeof(ss));
    memcpy(&ct, ciphertext, sizeof(ct));
    REQUIRE(lc_kyber_1024_dec(&ss, &ct, &ls) == 0);
    REQUIRE(!CRYPTO_memcmp(secret, &ss, sizeof(ss)));
    EVP_PKEY_CTX_free(ctx);
    REQUIRE(lc_kyber_1024_enc(&ct, &ss, &lp) == 0);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    REQUIRE(ctx && EVP_PKEY_decapsulate_init(ctx, NULL) > 0);
    ss_size = 32;
    REQUIRE(EVP_PKEY_decapsulate(ctx, secret, &ss_size, ct.ct, sizeof(ct)) > 0);
    REQUIRE(ss_size == sizeof(ss) && !CRYPTO_memcmp(secret, &ss, sizeof(ss)));
    EVP_PKEY_CTX_free(ctx);
    REQUIRE(hybrid_interop(key, &lp, &ls) == 0);
    EVP_PKEY_free(key);

    struct lc_x448_sk xs;
    struct lc_x448_pk base = { .pk = {5} }, xp;
    struct lc_x448_ss xpub, xshared;
    memcpy(xs.sk, seed, sizeof(xs));
    REQUIRE(lc_x448_ss(&xpub, &base, &xs) == 0);
    key = EVP_PKEY_new_raw_private_key_ex(NULL, "X448", NULL, xs.sk, sizeof(xs));
    size = 56;
    REQUIRE(key && EVP_PKEY_get_raw_public_key(key, pub, &size) > 0);
    REQUIRE(size == sizeof(xpub) && !memcmp(pub, &xpub, size));
    memset(seed, 0x42, sizeof(seed));
    EVP_PKEY *peer = EVP_PKEY_new_raw_private_key_ex(NULL, "X448", NULL, seed, 56);
    size = sizeof(xp);
    REQUIRE(peer && EVP_PKEY_get_raw_public_key(peer, xp.pk, &size) > 0);
    REQUIRE(size == sizeof(xp) && lc_x448_ss(&xshared, &xp, &xs) == 0);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    REQUIRE(ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, peer) > 0);
    size = sizeof(secret);
    REQUIRE(EVP_PKEY_derive(ctx, secret, &size) > 0);
    REQUIRE(size == sizeof(xshared) && !CRYPTO_memcmp(secret, &xshared, size));
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key); EVP_PKEY_free(peer);
    OPENSSL_cleanse(seed, sizeof(seed)); OPENSSL_cleanse(priv, sizeof(priv));
    OPENSSL_cleanse(&ls, sizeof(ls)); OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(&ss, sizeof(ss)); OPENSSL_cleanse(&xs, sizeof(xs));
    OPENSSL_cleanse(&xshared, sizeof(xshared));
    puts("Independent ML-KEM-1024/X448 combined-API interoperability passed.");
    return 0;
}
