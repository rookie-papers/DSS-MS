/**
 * @file PGUS_SBS/src/benchmark.cpp
 * @brief PGUS-SBS blind-issuance and sanitization benchmark.
 * @details Checks the two-block construction with one editable block and records stage costs.
 */
#include "PGUS_SBS.h"
#include "measure.h"

namespace Experiment {

/**
 * @brief Checks blind issuance, one sanitization, and trace outcomes before measurement.
 * 1. Prepare a signer, a sanitizer, and a two-block message with ADM = {0} in zero-based indexing.
 * 2. Issue sigma through Extract, Sign, and Derive, then produce sigma_prime through Sanit.
 * 3. Check that the issued and sanitized pairs verify.
 * 4. Check rejection of the old message, a forbidden edit, a second adaptation, and corrupted inputs.
 * 5. Check the trace outcomes for distinct signatures under the same issue, a linked pair, and a signer-sanitizer pair.
 * 6. Measure the primitive stages, full local issuance, one sanitization, verification, and tracing.
 * 7. Record |Enc(sigma_prime)| and report |Enc(sigma)| for the issued signature.
 */
void BenchPgus(Csv* csv, const std::string& id, int repeats, int iterations) {
    using namespace PGUS_SBS;
    // 1. Prepare a signer, a sanitizer, and a two-block message with ADM = {0} in zero-based indexing.
    const auto pp = SPSEQ::Setup();
    const auto [signer, sk] = KGenSig(2);
    const auto [san, dk] = KGenSan();
    const Message message{std::string(128, 'a'), std::string(128, 'b')};
    const std::vector<bool> allowed{true, false};
    const std::vector<Modification> changes{{0, "x" + message[0].substr(1)}};
    // 2. Issue sigma through Extract, Sign, and Derive, then produce sigma_prime through Sanit.
    const auto state = Extract(san, message, allowed);
    const auto inner = Sign(pp, signer, sk, san, state.request);
    const auto signature = Derive(state, inner);
    const auto changed = Sanit(pp, signer, san, dk, message, signature, changes);
    // 3. Check that the issued and sanitized pairs verify.
    Require(Verify(pp, signer, san, message, signature), "PGUS-SBS issued signature failed verification");
    Require(changed && changed->first[0] == changes[0].second && changed->first[1] == message[1] &&
            Verify(pp, signer, san, changed->first, changed->second), "PGUS-SBS sanitized signature failed verification");
    // 4. Check rejection of the old message, a forbidden edit, a second adaptation, and corrupted inputs.
    Require(!Verify(pp, signer, san, message, changed->second) &&
            !Sanit(pp, signer, san, dk, message, signature, {{1, "forbidden"}}) &&
            !Sanit(pp, signer, san, dk, changed->first, changed->second, changes),
            "PGUS-SBS accepted an invalid message, edit or second rerandomization");
    auto corrupt = signature;
    corrupt.data.ciphertext.body[0] ^= 1;
    Require(!Sanit(pp, signer, san, dk, message, corrupt, changes), "PGUS-SBS accepted a corrupted ciphertext");
    auto invalid = changed->second;
    invalid.inner.ring.response[0] = ComparisonCurve::Mod(invalid.inner.ring.response[0] + 1);
    Require(!Verify(pp, signer, san, changed->first, invalid), "PGUS-SBS accepted an invalid ring signature");
    // 5. Check the trace outcomes for distinct signatures under the same issue, a linked pair, and a signer-sanitizer pair.
    const auto again = Derive(state, Sign(pp, signer, sk, san, state.request));
    Require(Verify(pp, signer, san, message, again) &&
            Trace(signer, san, signature, again) == TRS::Result::Signer &&
            Trace(signer, san, signature, signature) == TRS::Result::Invalid &&
            Trace(signer, san, signature, changed->second) == TRS::Result::Independent,
            "PGUS-SBS trace results are inconsistent");
    if (!csv) return;
    // 6. Measure the primitive stages, full local issuance, one sanitization, verification, and tracing.
    BaselineRows out(*csv, id, "PGUS-SBS", "1");
    out.Timing("Setup", Measure(repeats, iterations, [] { return SPSEQ::Setup(); }), "SPSEQ common reference string");
    out.Timing("KGenSig", Measure(repeats, iterations, [] { return KGenSig(2); }), "SPSEQ and TRS key generation");
    out.Timing("KGenSan", Measure(repeats, iterations, [] { return KGenSan(); }), "Cramer-Shoup and TRS key generation");
    out.Timing("Extract", Measure(repeats, iterations, [&] { return Extract(san, message, allowed); }),
        "user side; two 128-byte blocks and one editable block");
    out.Timing("Sign", Measure(repeats, iterations, [&] { return Sign(pp, signer, sk, san, state.request); }),
        "signer side only; two KSD SPSEQ signatures plus Fujisaki-Suzuki TRS");
    out.Timing("Derive", Measure(repeats, iterations, [&] { return std::make_pair(state, inner); },
        [](auto& input) { return Derive(std::move(input.first), std::move(input.second)); }),
        "user side; assembling owned input after blind signing");
    out.Timing("Issue", Measure(repeats, iterations, [&] {
        auto fresh = Extract(san, message, allowed);
        auto response = Sign(pp, signer, sk, san, fresh.request);
        return Derive(std::move(fresh), std::move(response));
    }), "local Extract + Sign + Derive; excludes communication");
    out.Timing("Sanitize", Measure(repeats, iterations, [&] {
        return Sanit(pp, signer, san, dk, message, signature, changes);
    }), "one edit; two SPSEQ ChgRep calls, Cramer-Shoup/AES-GCM decrypt and encrypt, and TRS");
    out.Timing("Verify", Measure(repeats, iterations, [&] {
        return Verify(pp, signer, san, changed->first, changed->second);
    }), "post-sanitization; SPSEQ, block pairing equations, and TRS checks");
    out.Timing("Trace", Measure(repeats, iterations, [&] { return Trace(signer, san, signature, again); }),
        "two preverified signatures by signer, same issue and ring");
    // 7. Record |Enc(sigma_prime)| and report |Enc(sigma)| for the issued signature.
    out.Signature(EncodeSignature(changed->second).size(),
        "serialized sanitized signature; initial issued signature with SPSEQ adaptation tags is " +
        std::to_string(EncodeSignature(signature).size()) + " bytes");
}

} // namespace Experiment
