#include "measure.h"

#include "iut_k_san.h"
#include "PF_CLSS_DV.h"

namespace Experiment {
namespace {

void InitRNGs() {
    static const bool initialized = [] {
        initState(IUT::state_gmp);
        initRNG(&IUT::rng);
        initState(VRS::state_gmp);
        initRNG(&VRS::rng);
        initState(EQS::state_gmp);
        initRNG(&EQS::rng);
        initState(PKE::state_gmp);
        initRNG(&PKE::rng);
        initState(PF_CLSS_DV::state_gmp);
        initRNG(&PF_CLSS_DV::rng);
        return true;
    }();
    (void)initialized;
}

void Record(Csv& csv, const std::string& id, const std::string& scheme,
    const std::string& sanitizers, const std::string& algorithm, const std::vector<Sample>& samples) {
    for (const auto& sample : samples)
        csv.Row({id, scheme, algorithm, "2", sanitizers, "256", std::to_string(sample.repeat),
            std::to_string(sample.iterations), std::to_string(sample.us), "NA", "measured",
            scheme == "PF-CLSS-DV" ? "native single instance; designated verifier" : "one edited block"});
}

void Iut(Csv& csv, const std::string& id, int repeats, int iterations, std::size_t count) {
    auto pp = IUT::Setup(2, count);
    auto signer = IUT::KGen_S(pp, 2 + count);
    std::vector<IUT::IUT_SanitizerKey> members(count);
    for (auto& member : members) {
        do {
            PKE::KGenPKE_full(3072, member.pk_ZE, member.sk_ZE);
        } while (mpz_sizeinbase(member.pk_ZE.n.get_mpz_t(), 2) != 3072);
        auto ring = VRS::V_Gen(pp.vrs_pp);
        member.pk_ZP = std::move(ring.first);
        member.sk_ZP = std::move(ring.second);
    }
    std::vector<std::string> original{std::string(128, 'a'), std::string(128, 'b')};
    auto edited = original;
    edited[0][0] = 'x';
    std::vector<std::vector<int>> allowed(count, {1, 0});
    std::vector<int> changes{0};
    auto signature = IUT::Sign(pp, signer, members, original, allowed);
    auto sanitized = IUT::Sanitize(pp, members.front(), signer, members, original, changes, edited, signature);
    Require(IUT::Verify(pp, signer, members, original, signature), "IUT original signature failed verification");
    Require(IUT::Verify(pp, signer, members, edited, sanitized), "IUT sanitized signature failed verification");
    const auto k = std::to_string(count);
    Record(csv, id, "IUT-k-SAN", k, "Sign", Measure(repeats, iterations,
        [&] { return IUT::Sign(pp, signer, members, original, allowed); }));
    Record(csv, id, "IUT-k-SAN", k, "Sanitize", Measure(repeats, iterations,
        [&] { return signature; },
        [&](auto& input) { return IUT::Sanitize(pp, members.front(), signer, members, original, changes, edited, input); }));
    Record(csv, id, "IUT-k-SAN", k, "Verify", Measure(repeats, iterations,
        [&] { return IUT::Verify(pp, signer, members, edited, sanitized); }));
    const auto bytes = (2 * 2 + 4 * count + 7) * 49 + (2 + count + 2) * 96
        + (2 * count + 3) * 32 + count * (2 + count) * 768;
    csv.Row({id, "IUT-k-SAN", "Signature", "2", k, "256", "NA", "NA", "NA", std::to_string(bytes),
        "formula", "32-byte scalar; 49-byte G1; 96-byte G2; 3072-bit Paillier modulus"});
}

void Pf(Csv& csv, const std::string& id, int repeats, int iterations) {
    using namespace PF_CLSS_DV;
    const std::string identity = "DSS benchmark signer";
    const auto [pp, master] = Setup();
    const auto verifier = VerKeyGen(pp);
    const auto partial = PartialKeyGen(pp, master, identity);
    const auto [publicKey, privateKey] = SinKeyGen(pp, identity, partial);
    const Message original{std::string(128, 'a'), std::string(128, 'b')};
    auto replacement = original.m1;
    replacement[0] = 'x';
    const auto [signature, token] = Sign(pp, identity, privateKey, original, verifier.PK_V);
    const auto [edited, sanitized] = Sanitize(pp, identity, original, signature, token, replacement);
    Require(Verify(pp, identity, publicKey, verifier, original, signature), "PF original signature failed verification");
    Require(Verify(pp, identity, publicKey, verifier, edited, sanitized), "PF sanitized signature failed verification");
    Record(csv, id, "PF-CLSS-DV", "NA", "Sign", Measure(repeats, iterations,
        [&] { return Sign(pp, identity, privateKey, original, verifier.PK_V); }));
    Record(csv, id, "PF-CLSS-DV", "NA", "Sanitize", Measure(repeats, iterations,
        [&] { return Sanitize(pp, identity, original, signature, token, replacement); }));
    Record(csv, id, "PF-CLSS-DV", "NA", "Verify", Measure(repeats, iterations,
        [&] { return Verify(pp, identity, publicKey, verifier, edited, sanitized); }));
    csv.Row({id, "PF-CLSS-DV", "Signature", "2", "NA", "256", "NA", "NA", "NA", "162",
        "formula", "native two-block signature; authorization token is a separate scalar"});
}

} // namespace

void RunBaselines(Csv& csv, const std::string& runId, int repetitions, int iterations) {
    InitRNGs();
    Iut(csv, runId, repetitions, iterations, 2);
    Pf(csv, runId, repetitions, iterations);
    BenchEcmss(&csv, runId, repetitions, iterations);
    BenchLsans(&csv, runId, repetitions, iterations);
    BenchPgus(&csv, runId, repetitions, iterations);
}

void CheckNewBaselines() {
    BenchEcmss(nullptr, "", 0, 0);
    BenchLsans(nullptr, "", 0, 0);
    BenchPgus(nullptr, "", 0, 0);
}

} // namespace Experiment
