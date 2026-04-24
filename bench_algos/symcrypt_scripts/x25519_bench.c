// x25519_bench.c - SymCrypt X25519 benchmark (CSV: ALG,LIB,OP,US,CYC,OPS)

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <symcrypt.h>

static inline uint64_t rdtsc() {
    unsigned hi, lo;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline double now_us() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 1000;

    const PCSYMCRYPT_ECURVE_PARAMS params = SymCryptEcurveParamsCurve25519;
    PSYMCRYPT_ECURVE curve = SymCryptEcurveAllocate(params, 0);
    PSYMCRYPT_ECKEY a = SymCryptEckeyAllocate(curve);
    PSYMCRYPT_ECKEY b = SymCryptEckeyAllocate(curve);

    BYTE secA[32];
    SIZE_T cbSecret = 32;

    double us_key = 0, us_dh = 0;
    uint64_t cyc_key = 0, cyc_dh = 0;

    // Header
    printf("ALG,LIB,OP,US,CYC,OPS\n");

    // KEYGEN bench
    for (int i = 0; i < iters; i++) {
        uint64_t c0 = rdtsc();
        double t0 = now_us();

        SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, a);

        double t1 = now_us();
        uint64_t c1 = rdtsc();
        us_key += (t1 - t0);
        cyc_key += (c1 - c0);
    }

    // Pre-generate Bob’s static key for DH loop
    SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, b);

    // DH bench
    for (int i = 0; i < iters; i++) {
        uint64_t c0 = rdtsc();
        double t0 = now_us();

        SymCryptEcDhSecretAgreement(
            a, b,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0,
            secA, cbSecret
        );

        double t1 = now_us();
        uint64_t c1 = rdtsc();
        us_dh += (t1 - t0);
        cyc_dh += (c1 - c0);
    }

    double avg_key = us_key / iters;
    double avg_dh  = us_dh / iters;
    uint64_t avg_c_key = cyc_key / iters;
    uint64_t avg_c_dh  = cyc_dh / iters;

    // Print CSV rows
    printf("X25519,SymCrypt,keygen,%.2f,%" PRIu64 ",%.2f\n",
           avg_key, avg_c_key, 1e6 / avg_key);

    printf("X25519,SymCrypt,dh,%.2f,%" PRIu64 ",%.2f\n",
           avg_dh, avg_c_dh, 1e6 / avg_dh);

    SymCryptEckeyFree(a);
    SymCryptEckeyFree(b);
    SymCryptEcurveFree(curve);
    return 0;
}

