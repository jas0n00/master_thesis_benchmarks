// mlkem_bench.c - SymCrypt ML-KEM benchmark (CSV: ALG,LIB,OP,US,CYC,OPS)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <symcrypt.h>
#include <inttypes.h>

// ML-KEM sizes (bytes) — not used in CSV but kept for reference
#define MLKEM512_PK   800
#define MLKEM512_SK   1632
#define MLKEM512_CT   768

#define MLKEM768_PK   1184
#define MLKEM768_SK   2400
#define MLKEM768_CT   1088

#define MLKEM1024_PK  1568
#define MLKEM1024_SK  3168
#define MLKEM1024_CT  1568

static inline uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec*1000000ULL + ts.tv_nsec/1000ULL;
}

static inline uint64_t rdtsc(void)
{
    unsigned lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static void bench_kem(
        SYMCRYPT_MLKEM_PARAMS params,
        const char *name,
        int iters)
{
    PSYMCRYPT_MLKEMKEY key = SymCryptMlKemkeyAllocate(params);
    BYTE ss_enc[32], ss_dec[32];
    SIZE_T ctLen;
    SymCryptMlKemSizeofCiphertextFromParams(params, &ctLen);
    BYTE *ct = malloc(ctLen);

    uint64_t t0, t1, c0, c1;
    double us_k = 0, us_e = 0, us_d = 0;
    uint64_t cyc_k = 0, cyc_e = 0, cyc_d = 0;

    for (int i = 0; i < iters; i++)
    {
        // KEYGEN
        t0 = now_us(); c0 = rdtsc();
        SymCryptMlKemkeyGenerate(key, 0);
        c1 = rdtsc(); t1 = now_us();
        us_k += (t1 - t0);
        cyc_k += (c1 - c0);

        // ENC
        t0 = now_us(); c0 = rdtsc();
        SymCryptMlKemEncapsulate(key, ss_enc, sizeof(ss_enc), ct, ctLen);
        c1 = rdtsc(); t1 = now_us();
        us_e += (t1 - t0);
        cyc_e += (c1 - c0);

        // DEC
        t0 = now_us(); c0 = rdtsc();
        SymCryptMlKemDecapsulate(key, ct, ctLen, ss_dec, sizeof(ss_dec));
        c1 = rdtsc(); t1 = now_us();
        us_d += (t1 - t0);
        cyc_d += (c1 - c0);
    }

    us_k /= iters; us_e /= iters; us_d /= iters;
    cyc_k /= iters; cyc_e /= iters; cyc_d /= iters;

    // Output CSV rows (ALG,LIB,OP,US,CYC,OPS)
    printf("%s,SymCrypt,keygen,%.2f,%" PRIu64 ",%.2f\n",
           name, us_k, cyc_k, 1e6/us_k);
    printf("%s,SymCrypt,encaps,%.2f,%" PRIu64 ",%.2f\n",
           name, us_e, cyc_e, 1e6/us_e);
    printf("%s,SymCrypt,decaps,%.2f,%" PRIu64 ",%.2f\n",
           name, us_d, cyc_d, 1e6/us_d);

    free(ct);
    SymCryptMlKemkeyFree(key);
}

int main(int argc, char **argv)
{
    int iters = (argc > 1) ? atoi(argv[1]) : 500;

    // CSV header (only once)
    printf("ALG,LIB,OP,US,CYC,OPS\n");

    bench_kem(SYMCRYPT_MLKEM_PARAMS_MLKEM512,  "MLKEM512",  iters);
    bench_kem(SYMCRYPT_MLKEM_PARAMS_MLKEM768,  "MLKEM768",  iters);
    bench_kem(SYMCRYPT_MLKEM_PARAMS_MLKEM1024, "MLKEM1024", iters);

    return 0;
}

