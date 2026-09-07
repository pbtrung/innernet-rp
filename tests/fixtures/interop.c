/* Test-only oracle: independent OpenSSL and leancrypto ML-KEM/X448 endpoints.
 * Fixed seeds are public test material. Never compile this into a product. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <leancrypto/lc_init.h>
#include <leancrypto/lc_kyber_1024.h>
#include <leancrypto/lc_x448.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

#define REQUIRE(expression) do { if (!(expression)) { \
    fprintf(stderr, "independent crypto check failed at line %d\n", __LINE__); \
    return 1; } } while (0)

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
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key);

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
    puts("Independent ML-KEM-1024 and X448 interoperability passed.");
    return 0;
}
