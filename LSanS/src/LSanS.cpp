/**
 * @file LSanS/src/LSanS.cpp
 * @brief LSanS CA issuance, vehicle derivation, and verification.
 * @details Implements Algorithms 1-4 with the benchmark slot policy and encoding.
 */
#include "LSanS.h"

namespace LSanS {
using namespace ComparisonCurve;
namespace {

/**
 * @brief Recognizes the two benchmark policy identifiers.
 * 1. Accept iff Adm is in {1, 2}.
 */
bool KnownPolicy(std::uint8_t policy) {
    // 1. Accept iff Adm is in {1, 2}.
    return policy == 1 || policy == 2;
}

/**
 * @brief Checks the slot against the benchmark policy.
 * 1. Accept iff Adm is known and floor(slot / 1000) = Adm.
 */
bool Admissible(std::uint8_t policy, std::uint64_t slot) {
    // 1. Accept iff Adm is known and floor(slot / 1000) = Adm.
    return KnownPolicy(policy) && slot / 1000 == policy;
}

/**
 * @brief Computes the domain-separated challenge for a certificate layer.
 * The CA field is BE16(length) || fixed. The vehicle field is BE64(slot).
 * 1. B = domain || Enc(R) || Enc(field) || Enc(Q_i) || BE8(Adm).
 * 2. e = HashToZp(B).
 */
mpz_class Challenge(ECP commitment, const Master& fields, bool variable) {
    // 1. B = domain || Enc(R) || Enc(field) || Enc(Q_i) || BE8(Adm).
    std::string input = variable ? "LSanS/SAN/v1" : "LSanS/CA/v1";
    input += DSS::EncodePoint(commitment);
    if (variable) Number(input, fields.slot, 8);
    else {
        Number(input, fields.fixed.size(), 2);
        input += fields.fixed;
    }
    input += DSS::EncodePoint(fields.vehicle);
    Number(input, fields.policy, 1);
    // 2. e = HashToZp(B).
    return HashToZp(input);
}

/**
 * @brief Checks a commitment and response before verification.
 * 1. Accept iff R is in G1, R != 0, and 0 <= s < q.
 */
bool Valid(const Signature& signature) {
    // 1. Accept iff R is in G1, R != 0, and 0 <= s < q.
    return ComparisonCurve::Valid(signature.commitment) && signature.response >= 0 && signature.response < Order();
}

/**
 * @brief Checks the master fields used by the verification equations.
 * 1. Require |fixed| <= 512, known Adm, nonzero X and Q_i in G1, and a valid (R0, s0).
 */
bool Valid(ECP ca, const Master& master) {
    // 1. Require |fixed| <= 512, known Adm, nonzero X and Q_i in G1, and a valid (R0, s0).
    return master.fixed.size() <= 512 && KnownPolicy(master.policy) &&
           ComparisonCurve::Valid(ca) && ComparisonCurve::Valid(master.vehicle) && Valid(master.anchor);
}

/**
 * @brief Computes the Schnorr signature for one layer.
 * 1. r is sampled from Z_q^*.
 * 2. R = r * G.
 * 3. s = (r - e * secret) mod q, with e = Challenge(R, fields, layer).
 */
Signature SignPart(const mpz_class& secret, const Master& fields, bool variable) {
    // 1. r is sampled from Z_q^*.
    const auto nonce = Sample(true);
    // 2. R = r * G.
    const auto commitment = Mul(G1(), nonce);
    // 3. s = (r - e * secret) mod q, with e = Challenge(R, fields, layer).
    return {commitment, Mod(nonce - Challenge(commitment, fields, variable) * secret)};
}

/**
 * @brief Checks the Schnorr equation for one certificate layer.
 * 1. R_check = s * G + e * PK, with e = Challenge(R, fields, layer).
 * 2. Accept iff R_check = R.
 */
bool VerifyPart(ECP key, const Master& fields, const Signature& signature, bool variable) {
    // 1. R_check = s * G + e * PK, with e = Challenge(R, fields, layer).
    const auto expected = Add(Mul(G1(), signature.response),
                              Mul(key, Challenge(signature.commitment, fields, variable)));
    // 2. Accept iff R_check = R.
    return Equal(expected, signature.commitment);
}

} // namespace

/**
 * @brief Registers a validated vehicle point for an unused identifier.
 * 1. If Q_i is nonzero in G1 and i is unregistered, set registry[i] = Q_i.
 */
bool Registry::Register(std::uint64_t vehicleId, ECP key) {
    // 1. If Q_i is nonzero in G1 and i is unregistered, set registry[i] = Q_i.
    return ComparisonCurve::Valid(key) && entries_.emplace(vehicleId, key).second;
}

/**
 * @brief Retrieves a previously registered vehicle point.
 * 1. Q_i = registry[i].
 */
ECP Registry::KeyFor(std::uint64_t vehicleId) const {
    // 1. Q_i = registry[i].
    return entries_.at(vehicleId);
}

/**
 * @brief Issues the CA anchor in Algorithm 1.
 * The CA secret is x. The initial slot is carried in the master certificate.
 * 1. Require |m_fix| <= 512 and known Adm.
 * 2. Bind the certificate fields to Q_i = registry[vehicleId].
 * 3. (R0, s0) = SignPart(x, (m_fix, Q_i, Adm), CA).
 */
Master Sign(const Key& ca, const Registry& registry, std::uint64_t vehicleId,
            std::string fixed, std::uint64_t slot, std::uint8_t policy) {
    // 1. Require |m_fix| <= 512 and known Adm.
    if (fixed.size() > 512 || !KnownPolicy(policy))
        throw std::invalid_argument("Invalid LSanS fixed field or policy");
    ECP infinity;
    ECP_inf(&infinity);
    // 2. Bind the certificate fields to Q_i = registry[vehicleId].
    Master master{std::move(fixed), slot, registry.KeyFor(vehicleId), policy, {infinity, 0}};
    // 3. (R0, s0) = SignPart(x, (m_fix, Q_i, Adm), CA).
    master.anchor = SignPart(ca.secret, master, false);
    return master;
}

/**
 * @brief Derives a vehicle certificate in Algorithm 2.
 * 1. Require valid master fields, an admissible new slot, a valid CA anchor, and vehicle.PK = Q_i.
 * 2. m_var_prime = slot.
 * 3. (R1, s1) = SignPart(d_i, (m_var_prime, Q_i, Adm), vehicle).
 */
std::optional<Derived> Sanit(ECP ca, const Key& vehicle, const Master& master, std::uint64_t slot) {
    // 1. Require valid master fields, an admissible new slot, a valid CA anchor, and vehicle.PK = Q_i.
    if (!Valid(ca, master) || !Admissible(master.policy, slot) ||
        !VerifyPart(ca, master, master.anchor, false) || !Equal(vehicle.publicKey, master.vehicle))
        return std::nullopt;
    // 2. m_var_prime = slot.
    auto updated = master;
    updated.slot = slot;
    // 3. (R1, s1) = SignPart(d_i, (m_var_prime, Q_i, Adm), vehicle).
    auto signature = SignPart(vehicle.secret, updated, true);
    return Derived{std::move(updated), std::move(signature)};
}

/**
 * @brief Verifies a derived certificate in Algorithm 3.
 * 1. Accept iff the fields and policy are valid and both R0 = s0 * G + e0 * X and R1 = s1 * G + e1 * Q_i.
 */
bool Verify(ECP ca, const Derived& derived) {
    const auto& fields = derived.fields;
    // 1. Accept iff the fields and policy are valid and both R0 = s0 * G + e0 * X and R1 = s1 * G + e1 * Q_i.
    return Valid(ca, fields) && Valid(derived.variable) && Admissible(fields.policy, fields.slot) &&
           VerifyPart(ca, fields, fields.anchor, false) &&
           VerifyPart(fields.vehicle, fields, derived.variable, true);
}

/**
 * @brief Extracts the certified vehicle key in Algorithm 4.
 * 1. Reject if Verify(X, certificate) fails.
 * 2. Return Q_i.
 */
std::optional<ECP> Trace(ECP ca, const Derived& derived) {
    // 1. Reject if Verify(X, certificate) fails.
    if (!Verify(ca, derived)) return std::nullopt;
    // 2. Return Q_i.
    return derived.fields.vehicle;
}

/**
 * @brief Determines whether two valid certificates bind the same vehicle.
 * 1. Q_a = Trace(X, a) and Q_b = Trace(X, b).
 * 2. Reject if either trace fails.
 * 3. Return (Q_a = Q_b).
 */
std::optional<bool> Link(ECP ca, const Derived& a, const Derived& b) {
    // 1. Q_a = Trace(X, a) and Q_b = Trace(X, b).
    const auto first = Trace(ca, a);
    const auto second = Trace(ca, b);
    // 2. Reject if either trace fails.
    if (!first || !second) return std::nullopt;
    // 3. Return (Q_a = Q_b).
    return Equal(*first, *second);
}

/**
 * @brief Encodes the anchor and vehicle signature for size accounting.
 * 1. S = Enc49(R0) || BE48(s0) || Enc49(R1) || BE48(s1).
 */
std::string EncodeSignature(const Derived& derived) {
    // 1. S = Enc49(R0) || BE48(s0) || Enc49(R1) || BE48(s1).
    return DSS::EncodePoint(derived.fields.anchor.commitment) + ScalarBytes(derived.fields.anchor.response, 48) +
           DSS::EncodePoint(derived.variable.commitment) + ScalarBytes(derived.variable.response, 48);
}

} // namespace LSanS
