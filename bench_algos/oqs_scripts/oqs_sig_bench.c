// oqs_sig_bench.c — liboqs signature benchmark
// CSV output: ALG,LIB,OP,US,CYC,OPS
// Supports ML-DSA (Dilithium) and Falcon families.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <oqs/oqs.h>

// Read time-stamp counter (x86-64)
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

static void bench_sig(const char *alg, int iters) {
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        fprintf(stderr, "%s not available in liboqs build.\n", alg);
        return;
    }

    size_t pk = sig->length_public_key;
    size_t sk = sig->length_secret_key;
    size_t maxsig = sig->length_signature;

    uint8_t *pkbuf  = malloc(pk);
    uint8_t *skbuf  = malloc(sk);
    uint8_t *sigbuf = malloc(maxsig);
    if (!pkbuf || !skbuf || !sigbuf) {
        fprintf(stderr, "Memory allocation failed for %s\n", alg);
        goto cleanup;
    }

    const uint8_t msg[] = "benchmark-msg";
    size_t msglen = sizeof(msg) - 1;
    size_t siglen = 0;

    double key_us = 0, sign_us = 0, verify_us = 0;
    uint64_t key_cycles = 0, sign_cycles = 0, verify_cycles = 0;

    // Warm-up (ignore errors)
    OQS_SIG_keypair(sig, pkbuf, skbuf);
    OQS_SIG_sign(sig, sigbuf, &siglen, msg, msglen, skbuf);
    OQS_SIG_verify(sig, msg, msglen, sigbuf, siglen, pkbuf);

    for (int i = 0; i < iters; i++) {
        double t0;
        uint64_t c0, c1;

        // --- Keygen ---
        c0 = rdtsc();
        t0 = now_us();
        OQS_STATUS st_key = OQS_SIG_keypair(sig, pkbuf, skbuf);
        c1 = rdtsc();
        if (st_key == OQS_SUCCESS) {
            key_us += now_us() - t0;
            key_cycles += (c1 - c0);
        }

        // --- Sign ---
        c0 = rdtsc();
        t0 = now_us();
        OQS_STATUS st_sign = OQS_SIG_sign(sig, sigbuf, &siglen, msg, msglen, skbuf);
        c1 = rdtsc();
        if (st_sign == OQS_SUCCESS) {
            sign_us += now_us() - t0;
            sign_cycles += (c1 - c0);
        }

        // --- Verify ---
        c0 = rdtsc();
        t0 = now_us();
        OQS_STATUS st_ver = OQS_SIG_verify(sig, msg, msglen, sigbuf, siglen, pkbuf);
        c1 = rdtsc();
        if (st_ver == OQS_SUCCESS) {
            verify_us += now_us() - t0;
            verify_cycles += (c1 - c0);
        }
    }

    // Averages (only if success)
    if (key_us > 0) key_us /= iters;
    if (sign_us > 0) sign_us /= iters;
    if (verify_us > 0) verify_us /= iters;

    uint64_t key_cyc_avg    = (iters > 0) ? key_cycles / iters : 0;
    uint64_t sign_cyc_avg   = (iters > 0) ? sign_cycles / iters : 0;
    uint64_t verify_cyc_avg = (iters > 0) ? verify_cycles / iters : 0;

    double key_ops  = (key_us > 0) ? 1e6 / key_us : 0;
    double sign_ops = (sign_us > 0) ? 1e6 / sign_us : 0;
    double ver_ops  = (verify_us > 0) ? 1e6 / verify_us : 0;

    // CSV output
    printf("%s,liboqs,keygen,%.2f,%lu,%.2f\n",  alg, key_us,  (unsigned long)key_cyc_avg,  key_ops);
    printf("%s,liboqs,sign,%.2f,%lu,%.2f\n",   alg, sign_us, (unsigned long)sign_cyc_avg, sign_ops);
    printf("%s,liboqs,verify,%.2f,%lu,%.2f\n", alg, verify_us,(unsigned long)verify_cyc_avg, ver_ops);

cleanup:
    free(pkbuf);
    free(skbuf);
    free(sigbuf);
    OQS_SIG_free(sig);
}

int main(int argc, char **argv) {
    int iters = (argc > 1) ? atoi(argv[1]) : 1000;

    printf("ALG,LIB,OP,US,CYC,OPS\n");

    // Use canonical liboqs names (not MLDSA-X)
    bench_sig(OQS_SIG_alg_ml_dsa_44, iters);   // MLDSA-1
    bench_sig(OQS_SIG_alg_ml_dsa_65, iters);   // MLDSA-2
    bench_sig(OQS_SIG_alg_ml_dsa_87, iters);   // MLDSA-3
    bench_sig(OQS_SIG_alg_falcon_512, iters);
    bench_sig(OQS_SIG_alg_falcon_1024, iters);

    return 0;
}

