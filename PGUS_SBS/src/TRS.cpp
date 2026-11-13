/**
 * @file PGUS_SBS/src/TRS.cpp
 * @brief Two-member Fujisaki-Suzuki traceable ring signatures.
 * @details Uses additive G1 notation and a fixed empty issue for the PGUS comparison.
 */
#include "Primitives.h"

namespace PGUS_SBS::TRS {
using namespace ComparisonCurve;
namespace {

/**
 * @brief Encodes the issue and the ordered ring.
 * 1. L = Field(empty_issue) || Enc(Y_signer) || Enc(Y_sanitizer).
 */
std::string EncodeTag(const Ring& ring) {
    // 1. L = Field(empty_issue) || Enc(Y_signer) || Enc(Y_sanitizer).
    std::string bytes;
    Field(bytes, "");
    for (auto key : ring) bytes += DSS::EncodePoint(key);
    return bytes;
}

/**
 * @brief Binds a message to its ring tag.
 * 1. B = L || Field(M).
 */
std::string Bind(const std::string& tag, std::string_view message) {
    // 1. B = L || Field(M).
    auto input = tag;
    Field(input, message);
    return input;
}

/**
 * @brief Evaluates the trace line at a ring position.
 * The implementation uses zero-based j.
 * 1. P_j = A0 + (j + 1)*A1.
 */
ECP LineAt(ECP intercept, ECP slope, std::size_t member) {
    // 1. P_j = A0 + (j + 1)*A1.
    return Add(intercept, member == 0 ? slope : Add(slope, slope));
}

/**
 * @brief Hashes the proof transcript to the ring challenge.
 * 1. c = HashScalar(domain || B || Enc(A0) || Enc(A1) || Enc(a) || Enc(b)).
 */
mpz_class Challenge(std::string input, ECP intercept, ECP slope, const Ring& a, const Ring& b) {
    // 1. c = HashScalar(domain || B || Enc(A0) || Enc(A1) || Enc(a) || Enc(b)).
    input.insert(0, "PGUS/TRS/challenge/v1");
    input += DSS::EncodePoint(intercept) + DSS::EncodePoint(slope);
    for (auto p : a) input += DSS::EncodePoint(p);
    for (auto p : b) input += DSS::EncodePoint(p);
    return HashScalar(input);
}

/**
 * @brief Checks a canonical subgroup scalar.
 * 1. Accept iff 0 <= n < q.
 */
bool Scalar(const mpz_class& n) {
    // 1. Accept iff 0 <= n < q.
    return n >= 0 && n < Order();
}

} // namespace

/**
 * @brief Produces a ring signature using the signer or sanitizer witness.
 * The zero-based member index is i. The arrays challenge and response hold c and z.
 * 1. h = H_tag(L) and A0 = H_message(L || Field(M)).
 * 2. A1 = (i + 1)^(-1) * (x_i*h - A0).
 * 3. Sample nonce w and the simulated c_j, z_j for the other member j.
 * 4. a_i = w*G1 and b_i = w*h.
 * 5. a_j = z_j*G1 + c_j*Y_j and b_j = z_j*h + c_j*P_j.
 * 6. c_i = Challenge(L, M, A0, A1, a, b) - c_j mod q.
 * 7. z_i = w - c_i*x_i mod q.
 */
Signature Sign(const Ring& ring, std::size_t member, const mpz_class& secret, std::string_view message) {
    if (member >= ring.size()) throw std::invalid_argument("Invalid TRS member");
    // 1. h = H_tag(L) and A0 = H_message(L || Field(M)).
    const auto tag = EncodeTag(ring);
    const auto input = Bind(tag, message);
    const auto h = HashG1("PGUS/TRS/tag/v1", tag);
    const auto a0 = HashG1("PGUS/TRS/message/v1", input);
    // 2. A1 = (i + 1)^(-1) * (x_i*h - A0).
    const auto slope = Mul(Sub(Mul(h, secret), a0), Inv(mpz_class(member + 1)));
    // 3. Sample nonce w and the simulated c_j, z_j for the other member j.
    const auto nonce = Sample();
    const auto other = 1 - member;
    Signature sig{slope, {}, {}};
    sig.challenge[other] = Sample();
    sig.response[other] = Sample();
    Ring a, b;
    // 4. a_i = w*G1 and b_i = w*h.
    a[member] = Mul(G1(), nonce);
    b[member] = Mul(h, nonce);
    // 5. a_j = z_j*G1 + c_j*Y_j and b_j = z_j*h + c_j*P_j.
    a[other] = Add(Mul(G1(), sig.response[other]), Mul(ring[other], sig.challenge[other]));
    b[other] = Add(Mul(h, sig.response[other]), Mul(LineAt(a0, slope, other), sig.challenge[other]));
    // 6. c_i = Challenge(L, M, A0, A1, a, b) - c_j mod q.
    sig.challenge[member] = Mod(Challenge(input, a0, slope, a, b) - sig.challenge[other]);
    // 7. z_i = w - c_i*x_i mod q.
    sig.response[member] = Mod(nonce - sig.challenge[member] * secret);
    return sig;
}

/**
 * @brief Reconstructs the ring proof and checks its total challenge.
 * 1. Require subgroup points and distinct nonidentity public keys Y_0 and Y_1.
 * 2. h = H_tag(L) and A0 = H_message(L || Field(M)).
 * 3. Require canonical c_i and z_i, then reconstruct a_i = z_i*G1 + c_i*Y_i and b_i = z_i*h + c_i*P_i.
 * 4. Accept iff Challenge(L, M, A0, A1, a, b) = (c_0 + c_1) mod q.
 */
bool Verify(const Ring& ring, std::string_view message, const Signature& sig) {
    // 1. Require subgroup points and distinct nonidentity public keys Y_0 and Y_1.
    auto slope = sig.slope;
    if ((!ECP_isinf(&slope) && !Valid(slope)) || !Valid(ring[0]) || !Valid(ring[1]) ||
        Equal(ring[0], ring[1])) return false;
    // 2. h = H_tag(L) and A0 = H_message(L || Field(M)).
    const auto tag = EncodeTag(ring);
    const auto input = Bind(tag, message);
    const auto h = HashG1("PGUS/TRS/tag/v1", tag);
    const auto a0 = HashG1("PGUS/TRS/message/v1", input);
    Ring a, b;
    for (std::size_t i = 0; i < ring.size(); ++i) {
        // 3. Require canonical c_i and z_i, then reconstruct a_i = z_i*G1 + c_i*Y_i and b_i = z_i*h + c_i*P_i.
        if (!Scalar(sig.challenge[i]) || !Scalar(sig.response[i])) return false;
        a[i] = Add(Mul(G1(), sig.response[i]), Mul(ring[i], sig.challenge[i]));
        b[i] = Add(Mul(h, sig.response[i]), Mul(LineAt(a0, slope, i), sig.challenge[i]));
    }
    // 4. Accept iff Challenge(L, M, A0, A1, a, b) = (c_0 + c_1) mod q.
    return Challenge(input, a0, slope, a, b) == Mod(sig.challenge[0] + sig.challenge[1]);
}

/**
 * @brief Compares trace lines from two previously verified transcripts.
 * 1. Reconstruct the two intercepts A0_a and A0_b for the same ring and issue.
 * 2. Compare P_i_a = P_i_b at both ring positions.
 * 3. Two matches give Linked, one gives its member, and zero gives Independent.
 */
Result Trace(const Ring& ring, std::string_view a, const Signature& sigA,
             std::string_view b, const Signature& sigB) {
    // 1. Reconstruct the two intercepts A0_a and A0_b for the same ring and issue.
    const auto tag = EncodeTag(ring);
    const auto a0 = HashG1("PGUS/TRS/message/v1", Bind(tag, a));
    const auto b0 = HashG1("PGUS/TRS/message/v1", Bind(tag, b));
    // 2. Compare P_i_a = P_i_b at both ring positions.
    const bool first = Equal(LineAt(a0, sigA.slope, 0), LineAt(b0, sigB.slope, 0));
    const bool second = Equal(LineAt(a0, sigA.slope, 1), LineAt(b0, sigB.slope, 1));
    // 3. Two matches give Linked, one gives its member, and zero gives Independent.
    if (first && second) return Result::Linked;
    if (first) return Result::Signer;
    if (second) return Result::Sanitizer;
    return Result::Independent;
}

/**
 * @brief Encodes the ring signature for size accounting.
 * 1. tau_bytes = Enc(A1) || BE32_bytes(c_0) || BE32_bytes(c_1) || BE32_bytes(z_0) || BE32_bytes(z_1).
 */
std::string Encode(const Signature& signature) {
    // 1. tau_bytes = Enc(A1) || BE32_bytes(c_0) || BE32_bytes(c_1) || BE32_bytes(z_0) || BE32_bytes(z_1).
    auto output = DSS::EncodePoint(signature.slope);
    for (const auto& c : signature.challenge) output += ScalarBytes(c);
    for (const auto& s : signature.response) output += ScalarBytes(s);
    return output;
}

} // namespace PGUS_SBS::TRS
