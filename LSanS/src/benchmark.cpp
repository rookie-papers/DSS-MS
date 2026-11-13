/**
 * @file LSanS/src/benchmark.cpp
 * @brief LSanS certificate-derivation benchmark.
 * @details Checks the CA anchor and vehicle signature before recording one-vehicle timings.
 */
#include "LSanS.h"
#include "measure.h"

namespace Experiment {

/**
 * @brief Checks and measures the baseline LSanS certificate workflow.
 * 1. Generate X and distinct Q_i, then register the vehicle keys.
 * 2. Issue and derive a certificate for Q_1 and check both signature layers.
 * 3. Check that Trace identifies Q_1 and Link distinguishes Q_1 from Q_2.
 * 4. Check rejection of changed immutable data, a mismatched vehicle, and an inadmissible slot.
 * 5. Measure key generation, issuance, derivation, verification, tracing, and linking.
 * 6. Record |Enc(R0, s0, R1, s1)| in bytes.
 */
void BenchLsans(Csv* csv, const std::string& id, int repeats, int iterations) {
    using namespace LSanS;
    // 1. Generate X and distinct Q_i, then register the vehicle keys.
    const auto ca = KeyGen(), vehicle = KeyGen(), other = KeyGen();
    Registry registry;
    Require(registry.Register(1, vehicle.publicKey) && registry.Register(2, other.publicKey),
            "LSanS registration failed");
    const auto fixed = std::string(248, 'a');
    // 2. Issue and derive a certificate for Q_1 and check both signature layers.
    const auto master = Sign(ca, registry, 1, fixed, 1000, 1);
    const auto changed = Sanit(ca.publicKey, vehicle, master, 1001);
    Require(changed && Verify(ca.publicKey, *changed), "LSanS derived verification failed");
    // 3. Check that Trace identifies Q_1 and Link distinguishes Q_1 from Q_2.
    const auto next = Sanit(ca.publicKey, vehicle, master, 1002);
    const auto otherMaster = Sign(ca, registry, 2, fixed, 1000, 1);
    const auto otherChanged = Sanit(ca.publicKey, other, otherMaster, 1001);
    Require(next && otherChanged && Link(ca.publicKey, *changed, *next) == true &&
            Link(ca.publicKey, *changed, *otherChanged) == false, "LSanS Link failed");
    const auto traced = Trace(ca.publicKey, *changed);
    Require(traced && ComparisonCurve::Equal(*traced, vehicle.publicKey), "LSanS Trace failed");
    // 4. Check rejection of changed immutable data, a mismatched vehicle, and an inadmissible slot.
    auto bad = *changed;
    bad.fields.fixed[0] = 'x';
    Require(!Verify(ca.publicKey, bad) && !Sanit(ca.publicKey, other, master, 1001) &&
            !Sanit(ca.publicKey, vehicle, master, 2001), "LSanS accepted invalid input");
    if (!csv) return;
    // 5. Measure key generation, issuance, derivation, verification, tracing, and linking.
    BaselineRows out(*csv, id, "LSanS", "1");
    out.Timing("KGenSig", Measure(repeats, iterations, [] { return KeyGen(); }), "CA key");
    out.Timing("KGenSan", Measure(repeats, iterations, [] { return KeyGen(); }), "vehicle key");
    out.Timing("Sign", Measure(repeats, iterations, [&] { return Sign(ca, registry, 1, fixed, 1000, 1); }),
        "one registered vehicle; 248-byte fixed part and 8-byte editable slot");
    out.Timing("Sanitize", Measure(repeats, iterations, [&] { return Sanit(ca.publicKey, vehicle, master, 1001); }),
        "policy and CA anchor checks included; one editable slot");
    out.Timing("Verify", Measure(repeats, iterations, [&] { return Verify(ca.publicKey, *changed); }),
        "policy, CA anchor and vehicle proof checks included");
    out.Timing("Trace", Measure(repeats, iterations, [&] { return Trace(ca.publicKey, *changed); }),
        "includes derived certificate verification");
    out.Timing("Link", Measure(repeats, iterations, [&] { return Link(ca.publicKey, *changed, *next); }),
        "two derived certificates for the same vehicle");
    // 6. Record |Enc(R0, s0, R1, s1)| in bytes.
    out.Signature(EncodeSignature(*changed).size(),
        "two 49-byte commitments and two 48-byte responses; vehicle public key adds 49 bytes");
}
} // namespace Experiment
