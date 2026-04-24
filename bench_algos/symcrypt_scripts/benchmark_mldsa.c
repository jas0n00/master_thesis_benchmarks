#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <symcrypt.h>

static inline uint64_t rdtsc() {
    unsigned hi, lo;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double now_usec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

void bench_mldsa(SYMCRYPT_MLDSA_PARAMS params, size_t iters) {
    PSYMCRYPT_MLDSAKEY key = SymCryptMlDsakeyAllocate(params);
    if (!key) { fprintf(stderr,"FAIL alloc\n"); exit(1); }

    SIZE_T sigLen = 0;
    SymCryptMlDsaSizeofSignatureFromParams(params, &sigLen);

    BYTE *sig = malloc(sigLen);
    const BYTE msg[] = "SymCrypt MLDSA benchmark";
    SIZE_T msgLen = sizeof(msg) - 1;

    uint64_t t0, t1, c0;
    double us_key=0, us_sig=0, us_ver=0;
    uint64_t cyc_key=0, cyc_sig=0, cyc_ver=0;

    for(size_t i=0;i<iters;i++) {
        // Keygen
        t0 = now_usec(); c0 = rdtsc();
        SymCryptMlDsakeyGenerate(key, 0);
        t1 = now_usec(); cyc_key += (rdtsc()-c0);
        us_key += (t1-t0);

        // Sign
        t0 = now_usec(); c0 = rdtsc();
        SymCryptMlDsaSign(key, msg, msgLen, NULL, 0, 0, sig, sigLen);
        t1 = now_usec(); cyc_sig += (rdtsc()-c0);
        us_sig += (t1-t0);

        // Verify
        t0 = now_usec(); c0 = rdtsc();
        SymCryptMlDsaVerify(key, msg, msgLen, NULL, 0, sig, sigLen, 0);
        t1 = now_usec(); cyc_ver += (rdtsc()-c0);
        us_ver += (t1-t0);
    }

    us_key/=iters; us_sig/=iters; us_ver/=iters;
    cyc_key/=iters; cyc_sig/=iters; cyc_ver/=iters;

    for (int stage=0; stage<3; stage++) {
        const char* op = (stage==0)?"keygen":(stage==1)?"sign":"verify";
        double us = (stage==0)?us_key:(stage==1)?us_sig:us_ver;
        uint64_t cyc = (stage==0)?cyc_key:(stage==1)?cyc_sig:cyc_ver;
        double ops = 1e6/us;

        // CSV: ALG,LIB,OP,US,CYC,OPS
        printf("MLDSA-%d,SymCrypt,%s,%.2f,%lu,%.2f\n",
               (int)params, op, us, cyc, ops);
    }

    free(sig);
    SymCryptMlDsakeyFree(key);
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? atoi(argv[1]) : 1000;

    // Print CSV header once
    printf("ALG,LIB,OP,US,CYC,OPS\n");

    bench_mldsa(SYMCRYPT_MLDSA_PARAMS_MLDSA44, iters);
    bench_mldsa(SYMCRYPT_MLDSA_PARAMS_MLDSA65, iters);
    bench_mldsa(SYMCRYPT_MLDSA_PARAMS_MLDSA87, iters);
    return 0;
}

