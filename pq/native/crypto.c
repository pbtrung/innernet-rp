/* Narrow ABI bridge; algorithms come exclusively from system shared libraries. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <leancrypto/lc_kyber.h>
#include <leancrypto/lc_hash_drbg.h>
#include <leancrypto/lc_sha3.h>
#include <leancrypto/lc_hmac.h>
#include <leancrypto/lc_hkdf.h>
#include <leancrypto/lc_init.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

_Static_assert(sizeof(struct lc_kyber_1024_pk) == 1568, "ML-KEM public ABI");
_Static_assert(sizeof(struct lc_kyber_1024_sk) == 3168, "ML-KEM private ABI");
_Static_assert(sizeof(struct lc_kyber_1024_ct) == 1568, "ML-KEM ciphertext ABI");
_Static_assert(sizeof(struct lc_kyber_1024_x448_pk) == 1624, "hybrid public ABI");
_Static_assert(sizeof(struct lc_kyber_1024_x448_sk) == 3224, "hybrid private ABI");
_Static_assert(sizeof(struct lc_kyber_1024_x448_ct) == 1624, "hybrid ciphertext ABI");
_Static_assert(sizeof(struct lc_kyber_1024_x448_ss) == 88, "hybrid secret ABI");

int pq_init(void) { return lc_init(LC_INIT_NON_PQC_ENABLED); }

/* Export algorithm components, never generic enum/union memory or padding. */
static int export_public(uint8_t *kem, uint8_t *x448, struct lc_kyber_x448_pk *pk) {
    uint8_t *k, *x; size_t kl, xl;
    if (lc_kyber_x448_pk_type(pk) != LC_KYBER_1024 ||
        lc_kyber_x448_pk_ptr(&k, &kl, &x, &xl, pk) || kl != 1568 || xl != 56) return -1;
    memcpy(kem, k, kl); memcpy(x448, x, xl);
    return 0;
}
static int export_shared(uint8_t *kem, uint8_t *x448, struct lc_kyber_x448_ss *ss) {
    uint8_t *k, *x; size_t kl, xl;
    const uint8_t zero[56] = {0};
    if (lc_kyber_x448_ss_type(ss) != LC_KYBER_1024 ||
        lc_kyber_x448_ss_ptr(&k, &kl, &x, &xl, ss) || kl != 32 || xl != 56 ||
        !CRYPTO_memcmp(x, zero, sizeof(zero))) return -1;
    memcpy(kem, k, kl); memcpy(x448, x, xl);
    return 0;
}

int pq_hybrid_keygen(uint8_t *pk, uint8_t *xpk, uint8_t *sk, uint8_t *xsk,
                     const uint8_t *seed) {
    struct lc_kyber_x448_pk p = {0};
    struct lc_kyber_x448_sk s = {0};
    struct lc_rng_ctx *rng = NULL;
    uint8_t *k, *x; size_t kl, xl;
    /* A local library DRBG allows fallible OS entropy and test injection without
     * replacing leancrypto's process-global RNG used by encapsulation. */
    int ret = lc_drbg_hash_alloc(&rng);
    if (ret) goto done;
    ret = lc_rng_seed(rng, seed, 64, (const uint8_t *)"innernet hybrid identity", 24);
    if (ret) goto done;
    ret = lc_kyber_x448_keypair(&p, &s, rng, LC_KYBER_1024);
    if (ret) goto done;
    ret = export_public(pk, xpk, &p);
    if (ret) goto done;
    ret = lc_kyber_x448_sk_ptr(&k, &kl, &x, &xl, &s);
    if (ret || kl != 3168 || xl != 56) { ret = -1; goto done; }
    memcpy(sk, k, kl); memcpy(xsk, x, xl);
done:
    if (rng) lc_rng_zero_free(rng);
    OPENSSL_cleanse(&s, sizeof(s));
    return ret;
}

int pq_hybrid_public(uint8_t *pk, uint8_t *xpk, const uint8_t *sk, const uint8_t *xsk) {
    struct lc_kyber_x448_pk p = {0};
    struct lc_kyber_x448_sk s = {0};
    int ret = lc_kyber_x448_sk_load(&s, sk, 3168, xsk, 56);
    if (!ret) ret = lc_kyber_x448_pk_from_sk(&p, &s);
    if (!ret) ret = export_public(pk, xpk, &p);
    OPENSSL_cleanse(&s, sizeof(s));
    return ret;
}

int pq_hybrid_enc(uint8_t *ct, uint8_t *ss, uint8_t *xss,
                  const uint8_t *pk, const uint8_t *xpk) {
    struct lc_kyber_x448_pk p = {0};
    struct lc_kyber_x448_ct c = {0};
    struct lc_kyber_x448_ss s = {0};
    uint8_t *k, *x; size_t kl, xl;
    int ret = lc_kyber_x448_pk_load(&p, pk, 1568, xpk, 56);
    if (!ret) ret = lc_kyber_x448_enc(&c, &s, &p);
    if (!ret) ret = export_shared(ss, xss, &s);
    if (!ret) {
        ret = lc_kyber_x448_ct_ptr(&k, &kl, &x, &xl, &c);
        if (ret || kl != 1568 || xl != 56) ret = -1;
        else { memcpy(ct, k, kl); memcpy(ct + 1568, x, xl); }
    }
    OPENSSL_cleanse(&s, sizeof(s));
    return ret;
}

int pq_hybrid_dec(uint8_t *ss, uint8_t *xss, const uint8_t *ct,
                  const uint8_t *sk, const uint8_t *xsk) {
    struct lc_kyber_x448_sk s = {0};
    struct lc_kyber_x448_ct c = {0};
    struct lc_kyber_x448_ss shared = {0};
    int ret = lc_kyber_x448_sk_load(&s, sk, 3168, xsk, 56);
    if (!ret) ret = lc_kyber_x448_ct_load(&c, ct, 1568, ct + 1568, 56);
    if (!ret) ret = lc_kyber_x448_dec(&shared, &c, &s);
    if (!ret) ret = export_shared(ss, xss, &shared);
    OPENSSL_cleanse(&s, sizeof(s)); OPENSSL_cleanse(&shared, sizeof(shared));
    return ret;
}

/* Reject low-order public points at registration, without consuming entropy.
 * This public validation scalar is never an identity or exchange secret. */
int pq_x448_validate(const uint8_t *pk) {
    const uint8_t scalar[56] = {5}, zero[56] = {0};
    uint8_t out[56]; size_t len = sizeof(out);
    EVP_PKEY *private = EVP_PKEY_new_raw_private_key_ex(NULL, "X448", NULL, scalar, 56);
    EVP_PKEY *public = EVP_PKEY_new_raw_public_key_ex(NULL, "X448", NULL, pk, 56);
    EVP_PKEY_CTX *ctx = private ? EVP_PKEY_CTX_new_from_pkey(NULL, private, NULL) : NULL;
    int ok = ctx && public && EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_derive_set_peer(ctx, public) > 0 && EVP_PKEY_derive(ctx, out, &len) > 0 &&
        len == 56 && CRYPTO_memcmp(out, zero, 56);
    OPENSSL_cleanse(out, sizeof(out));
    EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(private); EVP_PKEY_free(public);
    return ok ? 0 : -1;
}

int pq_hash(uint8_t *out, const uint8_t *data, size_t len) {
    return lc_hash(lc_sha3_256, data, len, out);
}
int pq_hmac(uint8_t *out, const uint8_t *key, const uint8_t *data, size_t len) {
    return lc_hmac(lc_sha3_256, key, 32, data, len, out);
}
int pq_hkdf(uint8_t *out, const uint8_t *ikm, const uint8_t *salt,
            const uint8_t *info, size_t len) {
    return lc_hkdf(lc_sha3_256, ikm, 120, salt, 32, info, len, out, 32);
}

/* Import only validated P-521 scalars/points; all sizes are fixed by Rust. */
static EVP_PKEY *signing_key(const uint8_t *sk, const uint8_t *pk) {
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    BN_CTX *bnctx = BN_CTX_new();
    BIGNUM *scalar = sk ? BN_bin2bn(sk, 66, NULL) : NULL;
    uint8_t public_bytes[67];
    if (!group || !point || !bnctx) goto done;
    if (sk) {
        if (!scalar || BN_is_zero(scalar) ||
            BN_cmp(scalar, EC_GROUP_get0_order(group)) >= 0) goto done;
        BN_set_flags(scalar, BN_FLG_CONSTTIME);
        if (!EC_POINT_mul(group, point, scalar, NULL, NULL, bnctx)) goto done;
    } else {
        if (!pk || (pk[0] != 2 && pk[0] != 3) ||
            !EC_POINT_oct2point(group, point, pk, 67, bnctx)) goto done;
    }
    if (EC_POINT_is_at_infinity(group, point) ||
        EC_POINT_is_on_curve(group, point, bnctx) != 1 ||
        EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED,
                          public_bytes, sizeof(public_bytes), bnctx) != 67) goto done;
    if (!sk && CRYPTO_memcmp(public_bytes, pk, 67)) goto done;
    bld = OSSL_PARAM_BLD_new();
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!bld || !ctx || !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp521r1", 0) ||
        !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, public_bytes, 67) ||
        (sk && !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, scalar))) goto done;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params || EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, sk ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(key); key = NULL;
    }
done:
    BN_clear_free(scalar); BN_CTX_free(bnctx); EC_POINT_clear_free(point); EC_GROUP_free(group);
    OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(bld); EVP_PKEY_CTX_free(ctx);
    return key;
}

int pq_sign_public(uint8_t *out, const uint8_t *sk) {
    EVP_PKEY *key = signing_key(sk, NULL);
    size_t len = 67;
    int ok = key && EVP_PKEY_set_utf8_string_param(key, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
                                                "compressed") > 0 &&
        EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, out, len, &len) > 0 && len == 67;
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}
int pq_sign_validate(const uint8_t *pk) {
    EVP_PKEY *key = signing_key(NULL, pk);
    int ok = key != NULL;
    EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

static int scalar_valid(const BIGNUM *value, const BIGNUM *order) {
    return value && !BN_is_negative(value) && !BN_is_zero(value) && BN_cmp(value, order) < 0;
}

int pq_sign(uint8_t *out, const uint8_t *sk, const uint8_t *data, size_t len) {
    EVP_PKEY *key = signing_key(sk, NULL);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ECDSA_SIG *sig = NULL;
    BIGNUM *order = NULL, *half = NULL, *normalized = NULL;
    const BIGNUM *r = NULL, *s = NULL;
    uint8_t der[160]; size_t derlen = sizeof(der);
    const uint8_t *cursor = der;
    unsigned int nonce_type = 1; /* OpenSSL RFC 6979, SHA-512 from DigestSign. */
    OSSL_PARAM params[] = { OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
                            OSSL_PARAM_END };
    int ok = 0;
    if (!key || !ctx || EVP_DigestSignInit_ex(ctx, NULL, "SHA512", NULL, NULL, key, params) <= 0 ||
        EVP_DigestSign(ctx, der, &derlen, data, len) <= 0) goto done;
    sig = d2i_ECDSA_SIG(NULL, &cursor, (long)derlen);
    if (!sig || cursor != der + derlen ||
        !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_ORDER, &order)) goto done;
    ECDSA_SIG_get0(sig, &r, &s);
    half = BN_dup(order); normalized = BN_dup(s);
    if (!half || !normalized || !BN_rshift1(half, half) ||
        !scalar_valid(r, order) || !scalar_valid(s, order)) goto done;
    if (BN_cmp(s, half) > 0 && !BN_sub(normalized, order, s)) goto done;
    ok = BN_bn2binpad(r, out, 66) == 66 && BN_bn2binpad(normalized, out + 66, 66) == 66;
done:
    OPENSSL_cleanse(der, sizeof(der)); BN_clear_free(normalized); BN_free(half); BN_free(order);
    ECDSA_SIG_free(sig); EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    return ok ? 0 : -1;
}

int pq_verify(const uint8_t *raw, const uint8_t *pk, const uint8_t *data, size_t len) {
    EVP_PKEY *key = signing_key(NULL, pk);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(raw, 66, NULL), *s = BN_bin2bn(raw + 66, 66, NULL);
    BIGNUM *order = NULL, *half = NULL;
    uint8_t der[160], *cursor = der;
    int ok = 0, derlen;
    if (!key || !ctx || !sig || !EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_ORDER, &order) ||
        !scalar_valid(r, order) || !scalar_valid(s, order)) goto done;
    half = BN_dup(order);
    if (!half || !BN_rshift1(half, half) || BN_cmp(s, half) > 0 || !ECDSA_SIG_set0(sig, r, s)) goto done;
    r = NULL; s = NULL;
    derlen = i2d_ECDSA_SIG(sig, &cursor);
    if (derlen <= 0 || derlen > (int)sizeof(der)) goto done;
    ok = EVP_DigestVerifyInit_ex(ctx, NULL, "SHA512", NULL, NULL, key, NULL) > 0 &&
        EVP_DigestVerify(ctx, der, (size_t)derlen, data, len) == 1;
done:
    BN_free(r); BN_free(s); BN_free(order); BN_free(half);
    ECDSA_SIG_free(sig); EVP_MD_CTX_free(ctx); EVP_PKEY_free(key);
    return ok ? 0 : -1;
}
