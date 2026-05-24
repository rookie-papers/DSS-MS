#include "../include/iut_k_san.h"
#include <iostream>
#include <benchmark/benchmark.h>
using namespace std;

// ============================================================
// RNG singleton initializer
// ============================================================
static void InitRNGs()
{
    static bool initialized = false;
    if (!initialized)
    {
        initState(IUT::state_gmp);
        initRNG(&IUT::rng);
        initState(VRS::state_gmp);
        initRNG(&VRS::rng);
        initState(EQS::state_gmp);
        initRNG(&EQS::rng);
        initState(PKE::state_gmp);
        initRNG(&PKE::rng);
        initialized = true;
    }
}

// ============================================================
// Correctness Test
// ============================================================
void TestCorrectness()
{
    InitRNGs();
    cout << "=== Running IUT-k-SAN Correctness Test ===" << endl;

    size_t n = 2; // number of message blocks
    size_t k = 2; // number of sanitizers

    // 1. Setup
    cout << "[+] Setup..." << endl;
    auto pp = IUT::Setup(n, k);

    // 2. Generate signer key
    cout << "[+] Generating signer keys..." << endl;
    auto skS = IUT::KGen_S(pp, n + k);

    // 3. Generate sanitizer keys
    cout << "[+] Generating sanitizer keys (k=" << k << ")..." << endl;
    vector<IUT::IUT_SanitizerKey> PKZ(k);
    for (size_t i = 0; i < k; i++)
    {
        PKZ[i] = IUT::KGen_Z(pp);
    }

    // 4. Message blocks
    vector<string> m = {"Hello", "World"};

    // 5. Access control matrix A (k x n)
    vector<vector<int>> A = {
        {1, 0}, // sanitizer 0 can modify block 0
        {0, 1}  // sanitizer 1 can modify block 1
    };

    // 6. Sign
    cout << "[+] Signing message..." << endl;
    auto sig = IUT::Sign(pp, skS, PKZ, m, A);

    // 7. Verify original signature
    cout << "[+] Verifying original signature..." << endl;
    IUT::IUT_SignerKey pkS_pub;
    pkS_pub.pk_EQS = skS.pk_EQS;
    pkS_pub.pk_SP = skS.pk_SP;
    pkS_pub.sk_EQS = skS.sk_EQS;
    pkS_pub.sk_SP = skS.sk_SP;

    bool ok1 = IUT::Verify(pp, pkS_pub, PKZ, m, sig);
    cout << "Original Verify: " << (ok1 ? "PASS" : "FAIL") << endl;

    // 8. Sanitize (sanitizer 0 modifies block 0)
    cout << "[+] Sanitizing message..." << endl;
    vector<string> m_prime = {"Modified", "World"};
    vector<int> MOD_indices = {0};

    IUT::IUT_Signature sig_san;
    try
    {
        sig_san = IUT::Sanitize(pp, PKZ[0], pkS_pub, PKZ, m, MOD_indices, m_prime, sig);
    }
    catch (const exception &e)
    {
        cerr << "Sanitize failed: " << e.what() << endl;
        return;
    }

    // 9. Verify sanitized signature
    cout << "[+] Verifying sanitized signature..." << endl;
    bool ok2 = IUT::Verify(pp, pkS_pub, PKZ, m_prime, sig_san);
    cout << "Sanitized Verify: " << (ok2 ? "PASS" : "FAIL") << endl;

    // 10. Prove (signer proves they signed)
    cout << "[+] Generating proof of origin..." << endl;
    auto pi = IUT::Prove(skS, PKZ, m_prime, sig_san);

    // 11. Judge
    cout << "[+] Judging signature origin..." << endl;
    int judge_result = IUT::Judge(pkS_pub, PKZ, m_prime, sig_san, pi);
    if (judge_result == 1)
    {
        cout << "Judge Result: SIGNER (1) -- PASS" << endl;
    }
    else if (judge_result == 0)
    {
        cout << "Judge Result: SANITIZER (0) -- expected for sanitized sig" << endl;
    }
    else
    {
        cout << "Judge Result: INVALID (-1) -- FAIL" << endl;
    }

    // 12. Prove with original (non-sanitized) signature
    cout << "[+] Proving original signature origin..." << endl;
    auto pi_orig = IUT::Prove(skS, PKZ, m, sig);
    int judge_orig = IUT::Judge(pkS_pub, PKZ, m, sig, pi_orig);
    if (judge_orig == 1)
    {
        cout << "Original Judge Result: SIGNER (1) -- PASS" << endl;
    }
    else
    {
        cout << "Original Judge Result: " << judge_orig << " -- UNEXPECTED" << endl;
    }

    cout << "=== IUT-k-SAN Correctness Test Complete ===" << endl;
}

// int main() {
//     TestCorrectness();
//     return 0;
// }

// ============================================================
// Benchmarks (commented out; uncomment BENCHMARK_MAIN() to run)
// ============================================================
static void BM_Setup(benchmark::State &state)
{
    InitRNGs();
    size_t n = 2;
    size_t k = state.range(0);
    for (auto _ : state)
    {
        auto pp = IUT::Setup(n, k);
    }
}
BENCHMARK(BM_Setup)->Arg(2)->Arg(4)->Arg(8);

static void BM_Sign(benchmark::State &state)
{
    InitRNGs();
    size_t n = 2;
    size_t k = state.range(0);
    auto pp = IUT::Setup(n, k);
    auto skS = IUT::KGen_S(pp, n + k);
    vector<IUT::IUT_SanitizerKey> PKZ(k);
    for (size_t i = 0; i < k; i++)
        PKZ[i] = IUT::KGen_Z(pp);
    vector<string> m(n);
    for (size_t i = 0; i < n; i++)
        m[i] = "block_" + to_string(i);
    vector<vector<int>> A(k, vector<int>(n, 1));
    for (auto _ : state)
    {
        auto sig = IUT::Sign(pp, skS, PKZ, m, A);
    }
}
BENCHMARK(BM_Sign)->Arg(2)->Arg(4)->Iterations(20);

static void BM_Verify(benchmark::State &state)
{
    InitRNGs();
    size_t n = 2;
    size_t k = state.range(0);
    auto pp = IUT::Setup(n, k);
    auto skS = IUT::KGen_S(pp, n + k);
    vector<IUT::IUT_SanitizerKey> PKZ(k);
    for (size_t i = 0; i < k; i++)
        PKZ[i] = IUT::KGen_Z(pp);
    vector<string> m(n);
    for (size_t i = 0; i < n; i++)
        m[i] = "block_" + to_string(i);
    vector<vector<int>> A(k, vector<int>(n, 1));
    auto sig = IUT::Sign(pp, skS, PKZ, m, A);
    IUT::IUT_SignerKey pkS_pub;
    pkS_pub.pk_EQS = skS.pk_EQS;
    pkS_pub.pk_SP = skS.pk_SP;
    pkS_pub.sk_EQS = skS.sk_EQS;
    pkS_pub.sk_SP = skS.sk_SP;
    for (auto _ : state)
    {
        bool ok = IUT::Verify(pp, pkS_pub, PKZ, m, sig);
    }
}
BENCHMARK(BM_Verify)->Arg(2)->Arg(4)->Iterations(20);

static void BM_Sanitize(benchmark::State &state)
{
    InitRNGs();
    size_t n = 2;
    size_t k = state.range(0);
    auto pp = IUT::Setup(n, k);
    auto skS = IUT::KGen_S(pp, n + k);
    vector<IUT::IUT_SanitizerKey> PKZ(k);
    for (size_t i = 0; i < k; i++)
        PKZ[i] = IUT::KGen_Z(pp);
    vector<string> m(n);
    for (size_t i = 0; i < n; i++)
        m[i] = "block_" + to_string(i);
    vector<vector<int>> A(k, vector<int>(n, 1));
    auto sig = IUT::Sign(pp, skS, PKZ, m, A);
    IUT::IUT_SignerKey pkS_pub;
    pkS_pub.pk_EQS = skS.pk_EQS;
    pkS_pub.pk_SP = skS.pk_SP;
    pkS_pub.sk_EQS = skS.sk_EQS;
    pkS_pub.sk_SP = skS.sk_SP;
    vector<string> m_prime = m;
    m_prime[0] = "MODIFIED";
    vector<int> MOD_indices = {0};
    for (auto _ : state)
    {
        auto sig_san = IUT::Sanitize(pp, PKZ[0], pkS_pub, PKZ, m, MOD_indices, m_prime, sig);
    }
}
BENCHMARK(BM_Sanitize)->Arg(2)->Arg(4)->Iterations(20);


static void BM_Prove(benchmark::State &state)
{
    InitRNGs();
    size_t n = 2;
    size_t k = state.range(0);
    auto pp = IUT::Setup(n, k);
    auto skS = IUT::KGen_S(pp, n + k);
    vector<IUT::IUT_SanitizerKey> PKZ(k);
    for (size_t i = 0; i < k; i++)
        PKZ[i] = IUT::KGen_Z(pp);
    vector<string> m(n);
    for (size_t i = 0; i < n; i++)
        m[i] = "block_" + to_string(i);
    vector<vector<int>> A(k, vector<int>(n, 1));
    auto sig = IUT::Sign(pp, skS, PKZ, m, A);
    
    for (auto _ : state)
    {
        auto pi = IUT::Prove(skS, PKZ, m, sig);
    }
}
BENCHMARK(BM_Prove)->Arg(2)->Arg(4)->Iterations(20);

static void BM_Judge(benchmark::State &state)
{
    InitRNGs();
    size_t n = 2;
    size_t k = state.range(0);
    auto pp = IUT::Setup(n, k);
    auto skS = IUT::KGen_S(pp, n + k);
    vector<IUT::IUT_SanitizerKey> PKZ(k);
    for (size_t i = 0; i < k; i++)
        PKZ[i] = IUT::KGen_Z(pp);
    vector<string> m(n);
    for (size_t i = 0; i < n; i++)
        m[i] = "block_" + to_string(i);
    vector<vector<int>> A(k, vector<int>(n, 1));
    auto sig = IUT::Sign(pp, skS, PKZ, m, A);
    auto pi = IUT::Prove(skS, PKZ, m, sig);

    IUT::IUT_SignerKey pkS_pub;
    pkS_pub.pk_EQS = skS.pk_EQS;
    pkS_pub.pk_SP = skS.pk_SP;
    pkS_pub.sk_EQS = skS.sk_EQS;
    pkS_pub.sk_SP = skS.sk_SP;

    for (auto _ : state)
    {
        int res = IUT::Judge(pkS_pub, PKZ, m, sig, pi);
    }
}
BENCHMARK(BM_Judge)->Arg(2)->Arg(4)->Iterations(20);

BENCHMARK_MAIN();