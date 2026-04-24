// ecdsa_bench.c - SymCrypt ECDSA benchmark (CSV: ALG,LIB,OP,US,CYC,OPS)
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <x86intrin.h>
#include <symcrypt.h>

static inline uint64_t rdtsc(void) { return __rdtsc(); }

static inline uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000ULL;
}

static void bench_curve(PCSYMCRYPT_ECURVE_PARAMS params, const char *name, int iters)
{
    SYMCRYPT_ERROR sc;
    BYTE msgHash[SYMCRYPT_SHA256_RESULT_SIZE];
    BYTE sig[144];
    SIZE_T cbSig = sizeof(sig);

    SymCryptSha256((PCBYTE)"test message", 12, msgHash);

    PSYMCRYPT_ECURVE curve = SymCryptEcurveAllocate(params, 0);
    if (!curve) { fprintf(stderr, "ERROR: curve alloc\n"); return; }

    uint64_t t_s, t_e, c_s, c_e;
    double us_key=0.0, us_sig=0.0, us_ver=0.0;
    uint64_t cyc_key=0,  cyc_sig=0,  cyc_ver=0;

    for (int i = 0; i < iters; i++)
    {
        PSYMCRYPT_ECKEY key = SymCryptEckeyAllocate(curve);
        if (!key) { fprintf(stderr, "ERROR: key alloc\n"); SymCryptEcurveFree(curve); return; }

        // KEYGEN
        t_s = now_us(); c_s = rdtsc();
        sc = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDSA, key);
        c_e = rdtsc(); t_e = now_us();
        if (sc != SYMCRYPT_NO_ERROR) { fprintf(stderr, "ERROR: keygen\n"); SymCryptEckeyFree(key); SymCryptEcurveFree(curve); return; }
        us_key += (double)(t_e - t_s);
        cyc_key += (c_e - c_s);

        // SIGN
        cbSig = sizeof(sig);
        t_s = now_us(); c_s = rdtsc();
        sc = SymCryptEcDsaSign(key, msgHash, sizeof(msgHash),
                               SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, sig, cbSig);
        c_e = rdtsc(); t_e = now_us();
        if (sc != SYMCRYPT_NO_ERROR) { fprintf(stderr, "ERROR: sign\n"); SymCryptEckeyFree(key); SymCryptEcurveFree(curve); return; }
        us_sig += (double)(t_e - t_s);
        cyc_sig += (c_e - c_s);

        // VERIFY
        t_s = now_us(); c_s = rdtsc();
        sc = SymCryptEcDsaVerify(key, msgHash, sizeof(msgHash),
                                 sig, cbSig, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
        c_e = rdtsc(); t_e = now_us();
        if (sc != SYMCRYPT_NO_ERROR) { fprintf(stderr, "ERROR: verify\n"); SymCryptEckeyFree(key); SymCryptEcurveFree(curve); return; }
        us_ver += (double)(t_e - t_s);
        cyc_ver += (c_e - c_s);

        SymCryptEckeyFree(key);
    }

    us_key /= iters; us_sig /= iters; us_ver /= iters;
    cyc_key /= iters; cyc_sig /= iters; cyc_ver /= iters;

    // CSV rows (ALG,LIB,OP,US,CYC,OPS)
    printf("ECDSA-%s,SymCrypt,keygen,%.2f,%" PRIu64 ",%.2f\n",
           name, us_key, cyc_key, 1e6 / us_key);
    printf("ECDSA-%s,SymCrypt,sign,%.2f,%" PRIu64 ",%.2f\n",
           name, us_sig, cyc_sig, 1e6 / us_sig);
    printf("ECDSA-%s,SymCrypt,verify,%.2f,%" PRIu64 ",%.2f\n",
           name, us_ver, cyc_ver, 1e6 / us_ver);

    SymCryptEcurveFree(curve);
}

int main(int argc, char **argv)
{
    int iters = (argc > 1) ? atoi(argv[1]) : 200;

    // Print CSV header once
    printf("ALG,LIB,OP,US,CYC,OPS\n");

    bench_curve(SymCryptEcurveParamsNistP256, "P256", iters);
    bench_curve(SymCryptEcurveParamsNistP384, "P384", iters);
    bench_curve(SymCryptEcurveParamsNistP521, "P521", iters);
    return 0;
}

