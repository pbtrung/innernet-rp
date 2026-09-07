/* Narrow ABI bridge; algorithms come exclusively from system shared libraries. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <string.h>
#include <leancrypto/lc_kyber_1024.h>
#include <leancrypto/lc_x448.h>
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

int pq_init(void) { return lc_init(LC_INIT_NON_PQC_ENABLED); }

int pq_kem_keygen(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    struct lc_kyber_1024_pk p;
    struct lc_kyber_1024_sk s;
    int ret = lc_kyber_1024_keypair_from_seed(&p, &s, seed, 64);
    if (!ret) { memcpy(pk, p.pk, sizeof(p)); memcpy(sk, s.sk, sizeof(s)); }
    OPENSSL_cleanse(&s, sizeof(s));
    return ret;
}

int pq_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    struct lc_kyber_1024_pk p;
    struct lc_kyber_1024_ct c;
    struct lc_kyber_1024_ss s;
    memcpy(p.pk, pk, sizeof(p));
    int ret = lc_kyber_1024_enc(&c, &s, &p);
    if (!ret) { memcpy(ct, c.ct, sizeof(c)); memcpy(ss, s.ss, sizeof(s)); }
    OPENSSL_cleanse(&s, sizeof(s));
    return ret;
}

int pq_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    struct lc_kyber_1024_sk s;
    struct lc_kyber_1024_ct c;
    struct lc_kyber_1024_ss shared;
    memcpy(s.sk, sk, sizeof(s)); memcpy(c.ct, ct, sizeof(c));
    int ret = lc_kyber_1024_dec(&shared, &c, &s);
    if (!ret) memcpy(ss, shared.ss, sizeof(shared));
    OPENSSL_cleanse(&s, sizeof(s)); OPENSSL_cleanse(&shared, sizeof(shared));
    return ret;
}

int pq_x448_public(uint8_t *pk, const uint8_t *sk) {
    struct lc_x448_sk s;
    const struct lc_x448_pk base = { .pk = {5} }; /* RFC 7748 base point. */
    struct lc_x448_ss p;
    memcpy(s.sk, sk, sizeof(s));
    int ret = lc_x448_ss(&p, &base, &s);
    if (!ret) memcpy(pk, p.ss, sizeof(p));
    OPENSSL_cleanse(&s, sizeof(s));
    return ret;
}

int pq_x448(uint8_t *out, const uint8_t *pk, const uint8_t *sk) {
    struct lc_x448_sk s;
    struct lc_x448_pk p;
    struct lc_x448_ss shared;
    memcpy(s.sk, sk, sizeof(s)); memcpy(p.pk, pk, sizeof(p));
    int ret = lc_x448_ss(&shared, &p, &s);
    if (!ret) memcpy(out, shared.ss, sizeof(shared));
    OPENSSL_cleanse(&s, sizeof(s)); OPENSSL_cleanse(&shared, sizeof(shared));
    return ret;
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
