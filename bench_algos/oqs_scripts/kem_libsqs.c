// kem_liboqs.c — liboqs KEM benchmark
// CSV output: ALG,LIB,OP,US,CYC,OPS
// Measures microseconds and CPU cycles per operation, averages over N iterations.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

#if defined(_WIN32)
#include <intrin.h>
#else
#include <x86intrin.h> // for __rdtsc()
#endif

// -------------------- Timing Helpers --------------------

// Return current time in microseconds
static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

// Return current CPU timestamp counter
static inline unsigned long long now_cycles(void) {
    return __rdtsc();
}

// -------------------- Benchmark Function --------------------

static void bench_kem(const char *alg, int iters) {
    OQS_KEM *kem = OQS_KEM_new(alg);
    if (!kem) {
        fprintf(stderr, "Algorithm %s not available.\n", alg);
        return;
    }

    size_t pk = kem->length_public_key;
    size_t sk = kem->length_secret_key;
    size_t ct = kem->length_ciphertext;
    size_t ss = kem->length_shared_secret;

    uint8_t *pkbuf = malloc(pk);
    uint8_t *skbuf = malloc(sk);
    uint8_t *ctbuf = malloc(ct);
    uint8_t *ss1   = malloc(ss);
    uint8_t *ss2   = malloc(ss);

    if (!pkbuf || !skbuf || !ctbuf || !ss1 || !ss2) {
        fprintf(stderr, "Memory allocation failed for %s\n", alg);
        goto cleanup;
    }

    double key_us = 0, enc_us = 0, dec_us = 0;
    unsigned long long key_cyc = 0, enc_cyc = 0, dec_cyc = 0;

    for (int i = 0; i < iters; i++) {
        // Keygen
        unsigned long long c0 = now_cycles();
        double t0 = now_us();
        OQS_KEM_keypair(kem, pkbuf, skbuf);
        key_us += now_us() - t0;
        key_cyc += now_cycles() - c0;

        // Encaps
        c0 = now_cycles();
        t0 = now_us();
        OQS_KEM_encaps(kem, ctbuf, ss1, pkbuf);
        enc_us += now_us() - t0;
        enc_cyc += now_cycles() - c0;

        // Decaps
        c0 = now_cycles();
        t0 = now_us();
        OQS_KEM_decaps(kem, ss2, ctbuf, skbuf);
        dec_us += now_us() - t0;
        dec_cyc += now_cycles() - c0;
    }

    // Averages
    key_us /= iters; enc_us /= iters; dec_us /= iters;
    key_cyc /= iters; enc_cyc /= iters; dec_cyc /= iters;

    // Throughput (operations per second)
    double key_ops = 1e6 / key_us;
    double enc_ops = 1e6 / enc_us;
    double dec_ops = 1e6 / dec_us;

    // Output CSV rows: ALG,LIB,OP,US,CYC,OPS
    printf("%s,liboqs,keygen,%.2f,%llu,%.2f\n", alg, key_us, key_cyc, key_ops);
    printf("%s,liboqs,encaps,%.2f,%llu,%.2f\n", alg, enc_us, enc_cyc, enc_ops);
    printf("%s,liboqs,decaps,%.2f,%llu,%.2f\n", alg, dec_us, dec_cyc, dec_ops);

cleanup:
    free(pkbuf);
    free(skbuf);
    free(ctbuf);
    free(ss1);
    free(ss2);
    OQS_KEM_free(kem);
}

// -------------------- Main --------------------

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 1000;

    printf("ALG,LIB,OP,US,CYC,OPS\n");

    bench_kem(OQS_KEM_alg_kyber_512,  iters);
    bench_kem(OQS_KEM_alg_kyber_768,  iters);
    bench_kem(OQS_KEM_alg_kyber_1024, iters);

    return 0;
}

