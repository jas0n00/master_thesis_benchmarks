// rsa_bench.c — OpenSSL keygen + SymCrypt PKCS#1 v1.5 (NO ASN.1) sign/verify + CSV logging
// CSV format: ALG,LIB,OP,US,CYC,OPS

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>

#include "symcrypt.h"

#ifndef ITERS
#define ITERS 1000
#endif

// --------- Timing Utilities ---------
static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline uint64_t now_cycles(void) { return __rdtsc(); }
#define HAVE_RDTSC 1
#else
static inline uint64_t now_cycles(void) { return 0; }
#define HAVE_RDTSC 0
#endif

// --------- RSA Keygen (OpenSSL 3.x) ---------
static EVP_PKEY *gen_rsa(int bits) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_RSA_BITS, &bits);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, "SHA256", 0);
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

// --------- Import to SymCrypt ---------
static int import_to_symcrypt(EVP_PKEY *pkey, int bits, PSYMCRYPT_RSAKEY *out) {
    BIGNUM *tmpN = NULL, *tmpE = NULL, *tmpP = NULL, *tmpQ = NULL;

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &tmpN)) return 0;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &tmpE)) return 0;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &tmpP)) return 0;
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &tmpQ)) return 0;

    BIGNUM *bnN = BN_dup(tmpN);
    BIGNUM *bnE = BN_dup(tmpE);
    BIGNUM *bnP = BN_dup(tmpP);
    BIGNUM *bnQ = BN_dup(tmpQ);

    BN_free(tmpN);
    BN_free(tmpE);
    BN_free(tmpP);
    BN_free(tmpQ);

    if (!bnN || !bnE || !bnP || !bnQ) {
        if (bnN) BN_free(bnN);
        if (bnE) BN_free(bnE);
        if (bnP) BN_free(bnP);
        if (bnQ) BN_free(bnQ);
        return 0;
    }

    size_t mod_len = (size_t)BN_num_bytes(bnN);
    size_t prime_len = mod_len / 2;

    BYTE *n = calloc(mod_len, 1);
    BYTE *p = calloc(prime_len, 1);
    BYTE *q = calloc(prime_len, 1);
    if (!n || !p || !q) return 0;

    BN_bn2binpad(bnN, n, mod_len);
    BN_bn2binpad(bnP, p, prime_len);
    BN_bn2binpad(bnQ, q, prime_len);

    BYTE ebuf[8] = {0};
    BN_bn2binpad(bnE, ebuf, 8);
    UINT64 e64 = 0;
    for (int i = 0; i < 8; i++) e64 = (e64 << 8) | ebuf[i];

    BN_free(bnN);
    BN_free(bnE);
    BN_free(bnP);
    BN_free(bnQ);

    SYMCRYPT_RSA_PARAMS params = {0};
    params.nBitsOfModulus = bits;
    params.nPrimes = 2;
    params.nPubExp = 1;

    *out = SymCryptRsakeyAllocate(&params, SYMCRYPT_FLAG_RSAKEY_SIGN);
    UINT64 pubExpArr[1] = {e64};
    PCBYTE primes[2] = {p, q};
    SIZE_T primesLen[2] = {prime_len, prime_len};

    SYMCRYPT_ERROR sc = SymCryptRsakeySetValue(
        n, mod_len,
        pubExpArr, 1,
        primes, primesLen, 2,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_FLAG_RSAKEY_SIGN | SYMCRYPT_FLAG_KEY_NO_FIPS,
        *out);

    free(n);
    free(p);
    free(q);

    return sc == SYMCRYPT_NO_ERROR;
}

// --------- Benchmark ---------
static void bench(int bits, const char *name) {
    // --- Measure OpenSSL keygen ---
    uint64_t t0 = now_ns(), c0 = now_cycles();
    EVP_PKEY *pkey = gen_rsa(bits);
    uint64_t t1 = now_ns(), c1 = now_cycles();

    if (!pkey) {
        fprintf(stderr, "OpenSSL keygen failed for RSA-%s\n", name);
        return;
    }

    double us_k = (double)(t1 - t0) / 1000.0;
    printf("RSA-%s,SymCrypt,keygen,%.2f,%" PRIu64 ",%.2f\n",
           name, us_k, (uint64_t)(HAVE_RDTSC ? (c1 - c0) : 0), 1e6 / us_k);

    // --- Import into SymCrypt ---
    PSYMCRYPT_RSAKEY skey = NULL;
    if (!import_to_symcrypt(pkey, bits, &skey)) {
        fprintf(stderr, "SymCrypt key import failed for RSA-%s\n", name);
        EVP_PKEY_free(pkey);
        return;
    }

    BYTE msg[32];
    memset(msg, 0xA5, sizeof(msg));

    SIZE_T siglen = 0;
    SymCryptRsaPkcs1Sign(
        skey, msg, sizeof(msg),
        NULL, 0,
        SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        NULL, 0, &siglen);

    BYTE *sig = malloc(siglen);
    if (!sig) {
        SymCryptRsakeyFree(skey);
        EVP_PKEY_free(pkey);
        return;
    }

    uint64_t ns_s = 0, ns_v = 0, cy_s = 0, cy_v = 0;

    // --- Sign ---
    for (int i = 0; i < ITERS; i++) {
        SIZE_T w;
        uint64_t t0s = now_ns(), c0s = now_cycles();
        SymCryptRsaPkcs1Sign(
            skey, msg, sizeof(msg),
            NULL, 0,
            SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            sig, siglen, &w);
        uint64_t c1s = now_cycles(), t1s = now_ns();
        ns_s += (t1s - t0s);
        cy_s += (c1s - c0s);
    }

    // --- Verify ---
    for (int i = 0; i < ITERS; i++) {
        uint64_t t0v = now_ns(), c0v = now_cycles();
        SymCryptRsaPkcs1Verify(
            skey, msg, sizeof(msg),
            sig, siglen,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            NULL, 0, SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1);
        uint64_t c1v = now_cycles(), t1v = now_ns();
        ns_v += (t1v - t0v);
        cy_v += (c1v - c0v);
    }

    double us_s = (double)ns_s / ITERS / 1000.0;
    double us_v = (double)ns_v / ITERS / 1000.0;

    printf("RSA-%s,SymCrypt,sign,%.2f,%" PRIu64 ",%.2f\n",
           name, us_s, (uint64_t)(HAVE_RDTSC ? cy_s / ITERS : 0), 1e6 / us_s);

    printf("RSA-%s,SymCrypt,verify,%.2f,%" PRIu64 ",%.2f\n",
           name, us_v, (uint64_t)(HAVE_RDTSC ? cy_v / ITERS : 0), 1e6 / us_v);

    free(sig);
    SymCryptRsakeyFree(skey);
    EVP_PKEY_free(pkey);
}

// --------- Main ---------
int main(void) {
    bench(2048, "2048");
    bench(3072, "3072");
    bench(4096, "4096");
    return 0;
}

