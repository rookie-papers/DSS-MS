#include "../include/PF_CLSS_DV.h"
#include <iostream>
#include <benchmark/benchmark.h>

using namespace std;

// =====================================================================
// Singleton random-number initializer
// =====================================================================
static void InitRNGs()
{
    static bool initialized = false;
    if (!initialized)
    {
        initState(PF_CLSS_DV::state_gmp);
        initRNG(&PF_CLSS_DV::rng);
        initialized = true;
    }
}

// =====================================================================
// Correctness test: Setup -> VerKeyGen -> PartialKeyGen -> SinKeyGen
//                  -> Sign -> Sanitize -> Verify
// =====================================================================
// int main() {
//     InitRNGs();
//     cout << "=== Running PF_CLSS_DV Correctness Test ===" << endl;

//     string ID_O = "SignerOrg_Alpha";
//     string ID_V = "VerifierOrg_Beta";

//     // 1. Setup
//     cout << "[+] Setup..." << endl;
//     auto [pp, msk] = PF_CLSS_DV::Setup();
//     cout << "    q = ";
//     show_mpz(pp.q.get_mpz_t());

//     // 2. Verifier key generation
//     cout << "[+] VerKeyGen..." << endl;
//     auto VK = PF_CLSS_DV::VerKeyGen(pp);
//     cout << "    Verifier PK_V generated." << endl;

//     // 3. Partial key generation (KGC)
//     cout << "[+] PartialKeyGen for ID_O=" << ID_O << "..." << endl;
//     auto pak = PF_CLSS_DV::PartialKeyGen(pp, msk, ID_O);
//     cout << "    Partial key (R, d) generated." << endl;

//     // 4. Signer key generation
//     cout << "[+] SinKeyGen..." << endl;
//     auto [PK_O, SK_O] = PF_CLSS_DV::SinKeyGen(pp, ID_O, pak);
//     cout << "    Signer keys generated." << endl;

//     // 5. Define original message
//     PF_CLSS_DV::Message M{"Sensitive payload part 1", "Audit trail part 2"};
//     cout << "[+] Original message: m1=\"" << M.m1 << "\", m2=\"" << M.m2 << "\"" << endl;

//     // 6. Sign
//     cout << "[+] Signing..." << endl;
//     auto [sig, at] = PF_CLSS_DV::Sign(pp, ID_O, SK_O, M, VK.PK_V);
//     cout << "    Signature (u1, u2, T1, T2) and AuthToken AT1 generated." << endl;

//     // 7. Verify original signature
//     cout << "[+] Verifying original signature..." << endl;
//     bool pass_orig = PF_CLSS_DV::Verify(pp, ID_O, PK_O, VK, M, sig);
//     cout << "    Original verify: " << (pass_orig ? "PASS" : "FAIL") << endl;

//     // 8. Sanitize: replace m1
//     string m1_prime = "Sanitized payload part 1";
//     cout << "[+] Sanitizing: m1 -> \"" << m1_prime << "\"..." << endl;
//     auto [M_prime, sig_prime] = PF_CLSS_DV::Sanitize(pp, ID_O, M, sig, at, m1_prime);
//     cout << "    Sanitized message: m1=\"" << M_prime.m1 << "\", m2=\"" << M_prime.m2 << "\"" << endl;

//     // 9. Verify sanitized signature
//     cout << "[+] Verifying sanitized signature..." << endl;
//     bool pass_san = PF_CLSS_DV::Verify(pp, ID_O, PK_O, VK, M_prime, sig_prime);
//     cout << "    Sanitized verify: " << (pass_san ? "PASS" : "FAIL") << endl;

//     // 10. Negative test: tampered message should fail
//     cout << "[+] Negative test: tampered message..." << endl;
//     PF_CLSS_DV::Message M_bad{"Tampered payload", M.m2};
//     bool pass_bad = PF_CLSS_DV::Verify(pp, ID_O, PK_O, VK, M_bad, sig_prime);
//     cout << "    Tampered verify: " << (pass_bad ? "FAIL (should not pass)" : "PASS (correctly rejected)") << endl;

//     // Summary
//     cout << endl;
//     if (pass_orig && pass_san && !pass_bad) {
//         cout << "=== ALL TESTS PASSED ===" << endl;
//     } else {
//         cout << "=== SOME TESTS FAILED ===" << endl;
//         return 1;
//     }

//     return 0;
// }

// =====================================================================
// Google Benchmark macros
// =====================================================================

static void BM_Setup(benchmark::State &state)
{
    InitRNGs();
    for (auto _ : state)
    {
        auto [pp, msk] = PF_CLSS_DV::Setup();
    }
}
BENCHMARK(BM_Setup);

static void BM_VerKeyGen(benchmark::State &state)
{
    InitRNGs();
    auto [pp, msk] = PF_CLSS_DV::Setup();
    for (auto _ : state)
    {
        auto VK = PF_CLSS_DV::VerKeyGen(pp);
    }
}
BENCHMARK(BM_VerKeyGen);

static void BM_PartialKeyGen(benchmark::State &state)
{
    InitRNGs();
    auto [pp, msk] = PF_CLSS_DV::Setup();
    string ID_O = "BenchSigner";
    for (auto _ : state)
    {
        auto pak = PF_CLSS_DV::PartialKeyGen(pp, msk, ID_O);
    }
}
BENCHMARK(BM_PartialKeyGen);

static void BM_SinKeyGen(benchmark::State &state)
{
    InitRNGs();
    auto [pp, msk] = PF_CLSS_DV::Setup();
    string ID_O = "BenchSigner";
    auto pak = PF_CLSS_DV::PartialKeyGen(pp, msk, ID_O);
    for (auto _ : state)
    {
        auto [PK_O, SK_O] = PF_CLSS_DV::SinKeyGen(pp, ID_O, pak);
    }
}
BENCHMARK(BM_SinKeyGen);

static void BM_Sign(benchmark::State &state)
{
    InitRNGs();
    auto [pp, msk] = PF_CLSS_DV::Setup();
    string ID_O = "BenchSigner";
    auto VK = PF_CLSS_DV::VerKeyGen(pp);
    auto pak = PF_CLSS_DV::PartialKeyGen(pp, msk, ID_O);
    auto [PK_O, SK_O] = PF_CLSS_DV::SinKeyGen(pp, ID_O, pak);
    PF_CLSS_DV::Message M{"bench_m1", "bench_m2"};
    for (auto _ : state)
    {
        auto [sig, at] = PF_CLSS_DV::Sign(pp, ID_O, SK_O, M, VK.PK_V);
    }
}
BENCHMARK(BM_Sign);

static void BM_Sanitize(benchmark::State &state)
{
    InitRNGs();
    auto [pp, msk] = PF_CLSS_DV::Setup();
    string ID_O = "BenchSigner";
    auto VK = PF_CLSS_DV::VerKeyGen(pp);
    auto pak = PF_CLSS_DV::PartialKeyGen(pp, msk, ID_O);
    auto [PK_O, SK_O] = PF_CLSS_DV::SinKeyGen(pp, ID_O, pak);
    PF_CLSS_DV::Message M{"bench_m1", "bench_m2"};
    auto [sig, at] = PF_CLSS_DV::Sign(pp, ID_O, SK_O, M, VK.PK_V);
    string m1_prime = "sanitized_m1";
    for (auto _ : state)
    {
        auto [M_prime, sig_prime] = PF_CLSS_DV::Sanitize(pp, ID_O, M, sig, at, m1_prime);
    }
}
BENCHMARK(BM_Sanitize);

static void BM_Verify(benchmark::State &state)
{
    InitRNGs();
    auto [pp, msk] = PF_CLSS_DV::Setup();
    string ID_O = "BenchSigner";
    auto VK = PF_CLSS_DV::VerKeyGen(pp);
    auto pak = PF_CLSS_DV::PartialKeyGen(pp, msk, ID_O);
    auto [PK_O, SK_O] = PF_CLSS_DV::SinKeyGen(pp, ID_O, pak);
    PF_CLSS_DV::Message M{"bench_m1", "bench_m2"};
    auto [sig, at] = PF_CLSS_DV::Sign(pp, ID_O, SK_O, M, VK.PK_V);
    for (auto _ : state)
    {
        bool ok = PF_CLSS_DV::Verify(pp, ID_O, PK_O, VK, M, sig);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_Verify);

// Uncomment the following line to run benchmarks instead of the correctness test:
BENCHMARK_MAIN();
