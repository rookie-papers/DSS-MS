/**
 * @file PGUS_SBS/src/SPSEQ.cpp
 * @brief Khalili-Slamanig-Dakhilalian signatures on equivalence classes.
 * @details Implements the malleable proof in Figure 2 and the tagged SPSEQ construction in Figure 3.
 */
#include "Primitives.h"

#include <algorithm>

namespace PGUS_SBS::SPSEQ {
using namespace ComparisonCurve;
namespace {

/**
 * @brief Samples the benchmark rank-one matrix column.
 * 1. A = (1, a)^T, with a sampled from Z_q.
 */
ScalarPair MatrixColumn() {
    // 1. A = (1, a)^T, with a sampled from Z_q.
    return {mpz_class(1), Sample()};
}

/**
 * @brief Scales an encoded two-coordinate vector.
 * 1. s*[v] = (s*v_0, s*v_1).
 */
template <class Point>
std::array<Point, 2> Scale(std::array<Point, 2> pair, const mpz_class& s) {
    // 1. s*[v] = (s*v_0, s*v_1).
    return {Mul(pair[0], s), Mul(pair[1], s)};
}

/**
 * @brief Adds two encoded vectors in the same group.
 * 1. [a] + [b] = (a_0 + b_0, a_1 + b_1).
 */
template <class Point>
std::array<Point, 2> Sum(std::array<Point, 2> a, std::array<Point, 2> b) {
    // 1. [a] + [b] = (a_0 + b_0, a_1 + b_1).
    return {Add(a[0], b[0]), Add(a[1], b[1])};
}

/**
 * @brief Computes a scalar inner product.
 * 1. a^T*b = (a_0*b_0 + a_1*b_1) mod q.
 */
mpz_class Dot(const ScalarPair& a, const ScalarPair& b) {
    // 1. a^T*b = (a_0*b_0 + a_1*b_1) mod q.
    return Mod(a[0] * b[0] + a[1] * b[1]);
}

/**
 * @brief Checks G1 membership for a proof coordinate.
 * 1. Accept iff p = 0 or p is a nonidentity G1 point.
 */
bool InGroup(ECP p) {
    // 1. Accept iff p = 0 or p is a nonidentity G1 point.
    return ECP_isinf(&p) || Valid(p);
}
/**
 * @brief Checks G2 membership for a proof coordinate.
 * 1. Accept iff p = 0 or p is a nonidentity G2 point.
 */
bool InGroup(ECP2 p) {
    // 1. Accept iff p = 0 or p is a nonidentity G2 point.
    return ECP2_isinf(&p) || Valid(p);
}

/**
 * @brief Checks both coordinates of an encoded vector.
 * 1. Accept iff both coordinates are in the required subgroup.
 */
template <class Point>
bool ValidPair(std::array<Point, 2> pair) {
    // 1. Accept iff both coordinates are in the required subgroup.
    return InGroup(pair[0]) && InGroup(pair[1]);
}

/**
 * @brief Applies the secret matrix to a G1 word.
 * 1. [u]_1 = K0^T * [word]_1.
 */
G1Pair LinearK0(const std::array<ScalarPair, 2>& k0, G1Pair word) {
    // 1. [u]_1 = K0^T * [word]_1.
    return {Add(Mul(word[0], k0[0][0]), Mul(word[1], k0[1][0])),
            Add(Mul(word[0], k0[0][1]), Mul(word[1], k0[1][1]))};
}

/**
 * @brief Builds the two proof branches for a word in the first span.
 * Figure 2 PPro with word = witness*A0. Encodings in G1 and G2 follow the operand types.
 * 1. Sample s0 and s1 from Z_q.
 * 2. C0 = s0*D + witness*z0, C1 = s1*D, Pi0 = s0*A0, Pi1 = s1*A1 - v*word.
 */
ProofPart Prove(const Parameters& pp, G1Pair word, const mpz_class& witness, const mpz_class& v,
                const std::array<G2Pair, 2>& z) {
    // 1. Sample s0 and s1 from Z_q.
    const auto s0 = Sample(), s1 = Sample();
    // 2. C0 = s0*D + witness*z0, C1 = s1*D, Pi0 = s0*A0, Pi1 = s1*A1 - v*word.
    const auto hidden = Scale(word, Mod(-v));
    return {{Sum(Scale(pp.d, s0), Scale(z[0], witness)), Scale(pp.d, s1)},
            {Scale(pp.branches[0], s0), Sum(Scale(pp.branches[1], s1), hidden)}};
}

/**
 * @brief Verifies the QA-NIZK relation shared by both proof parts.
 * In Figure 2, qaBase and qaCommit store the G1 QA-NIZK basis and commitments.
 * 1. Require valid G2 encodings for z0, z1, and pi.
 * 2. z_sum = z0 + z1.
 * 3. For each i, require e(A_QA_i, pi) = prod_j e(C_QA_ij, z_sum_j).
 */
bool VerifyCommon(const Parameters& pp, const Signature& sig) {
    // 1. Require valid G2 encodings for z0, z1, and pi.
    if (!ValidPair(sig.z[0]) || !ValidPair(sig.z[1]) || !InGroup(sig.pi)) return false;
    // 2. z_sum = z0 + z1.
    const auto z = Sum(sig.z[0], sig.z[1]);
    // 3. For each i, require e(A_QA_i, pi) = prod_j e(C_QA_ij, z_sum_j).
    for (std::size_t i = 0; i < 2; ++i)
        if (!PairEqual({{pp.qaBase[i], sig.pi}}, {{pp.qaCommit[i][0], z[0]}, {pp.qaCommit[i][1], z[1]}}))
            return false;
    return true;
}

/**
 * @brief Checks the Figure 2 equations for one word.
 * 1. Require group membership of word, C_b, and Pi_b.
 * 2. For each b, i, j, require e(A_b_i, C_b_j) = e(Pi_b_i, D_j) * e(word_i, z_b_j).
 */
bool VerifyPart(const Parameters& pp, G1Pair word, const ProofPart& proof,
                const std::array<G2Pair, 2>& z) {
    // 1. Require group membership of word, C_b, and Pi_b.
    if (!ValidPair(word)) return false;
    for (std::size_t b = 0; b < 2; ++b) {
        if (!ValidPair(proof.c[b]) || !ValidPair(proof.pi[b])) return false;
        // 2. For each b, i, j, require e(A_b_i, C_b_j) = e(Pi_b_i, D_j) * e(word_i, z_b_j).
        for (std::size_t row = 0; row < 2; ++row)
            for (std::size_t col = 0; col < 2; ++col)
                if (!PairEqual({{pp.branches[b][row], proof.c[b][col]}},
                               {{proof.pi[b][row], pp.d[col]}, {word[row], z[b][col]}}))
                    return false;
    }
    return true;
}

/**
 * @brief Checks the Figure 3 linear pairing relation.
 * The auxiliary tag uses an empty message product.
 * 1. Require both coordinates of the linear value in G1.
 * 2. RHS = prod_j e(word_j, (K0*A)_j) * prod_i e(m_i, (K*A)_i).
 * 3. Accept iff prod_j e(value_j, A_j) = RHS.
 */
bool VerifyLinear(const PublicKey& key, G1Pair value, G1Pair word, const std::vector<ECP>& message) {
    // 1. Require both coordinates of the linear value in G1.
    if (!ValidPair(value)) return false;
    // 2. RHS = prod_j e(word_j, (K0*A)_j) * prod_i e(m_i, (K*A)_i).
    std::vector<std::pair<ECP, ECP2>> terms{{word[0], key.k0a[0]}, {word[1], key.k0a[1]}};
    for (std::size_t i = 0; i < message.size(); ++i) terms.emplace_back(message[i], key.ka[i]);
    // 3. Accept iff prod_j e(value_j, A_j) = RHS.
    return PairEqual({{value[0], key.a[0]}, {value[1], key.a[1]}}, terms);
}

/**
 * @brief Appends a G1 proof vector to the transcript.
 * 1. out = out || Enc(P_0) || Enc(P_1).
 */
void Append(std::string& out, G1Pair pair) {
    // 1. out = out || Enc(P_0) || Enc(P_1).
    for (auto p : pair) out += DSS::EncodePoint(p);
}

/**
 * @brief Appends a G2 proof vector to the transcript.
 * 1. out = out || Enc(Q_0) || Enc(Q_1).
 */
void Append(std::string& out, G2Pair pair) {
    // 1. out = out || Enc(Q_0) || Enc(Q_1).
    for (auto p : pair) out += PointBytes(p);
}

/**
 * @brief Appends both proof branches to the transcript.
 * 1. out = out || Enc(C0) || Enc(C1) || Enc(Pi0) || Enc(Pi1).
 */
void Append(std::string& out, const ProofPart& part) {
    // 1. out = out || Enc(C0) || Enc(C1) || Enc(Pi0) || Enc(Pi1).
    for (auto c : part.c) Append(out, c);
    for (auto pi : part.pi) Append(out, pi);
}

} // namespace

/**
 * @brief Generates the common reference string for Figures 2 and 3.
 * 1. Sample rank-one columns A0, A1, D, A_QA and secret vector k_QA in Z_q^2.
 * 2. Sample z outside span(D) and set m = D + z mod q.
 * 3. Publish [A0]_1, [A1]_1, [A_QA]_1, and [C_QA_ij = A_QA_i*k_QA_j]_1.
 * 4. Publish [D]_2, [z]_2, and [p = m^T*k_QA]_2.
 */
Parameters Setup() {
    // 1. Sample rank-one columns A0, A1, D, A_QA and secret vector k_QA in Z_q^2.
    const auto a0 = MatrixColumn(), a1 = MatrixColumn(), d = MatrixColumn(), qa = MatrixColumn();
    const ScalarPair secret{Sample(), Sample()};
    // 2. Sample z outside span(D) and set m = D + z mod q.
    ScalarPair z;
    do { z = {Sample(), Sample()}; } while (Mod(z[1] - d[1] * z[0]) == 0);
    const ScalarPair m{Mod(d[0] + z[0]), Mod(d[1] + z[1])};
    const auto g1 = G1();
    const auto g2 = G2();
    Parameters pp;
    // 3. Publish [A0]_1, [A1]_1, [A_QA]_1, and [C_QA_ij = A_QA_i*k_QA_j]_1.
    pp.branches = {G1Pair{Mul(g1, a0[0]), Mul(g1, a0[1])}, G1Pair{Mul(g1, a1[0]), Mul(g1, a1[1])}};
    pp.qaBase = {Mul(g1, qa[0]), Mul(g1, qa[1])};
    for (std::size_t i = 0; i < 2; ++i)
        pp.qaCommit[i] = {Mul(pp.qaBase[i], secret[0]), Mul(pp.qaBase[i], secret[1])};
    // 4. Publish [D]_2, [z]_2, and [p = m^T*k_QA]_2.
    pp.d = {Mul(g2, d[0]), Mul(g2, d[1])};
    pp.z = {Mul(g2, z[0]), Mul(g2, z[1])};
    pp.p = Mul(g2, Dot(m, secret));
    return pp;
}

/**
 * @brief Generates the signer matrices and their G2 verification images.
 * 1. Require n >= 2 and sample the rank-one column A.
 * 2. Sample K0 in Z_q^(2x2) and publish [A]_2 and [K0*A]_2.
 * 3. Sample each K_i in Z_q^2 and publish [K_i*A]_2.
 */
std::pair<PublicKey, SecretKey> KeyGen(std::size_t blocks) {
    // 1. Require n >= 2 and sample the rank-one column A.
    if (blocks < 2) throw std::invalid_argument("SPSEQ requires at least two coordinates");
    const auto a = MatrixColumn();
    const auto g = G2();
    // 2. Sample K0 in Z_q^(2x2) and publish [A]_2 and [K0*A]_2.
    SecretKey secret{{ScalarPair{Sample(), Sample()}, ScalarPair{Sample(), Sample()}}, {}};
    PublicKey pub{{Mul(g, a[0]), Mul(g, a[1])},
                  {Mul(g, Dot(secret.k0[0], a)), Mul(g, Dot(secret.k0[1], a))}, {}};
    // 3. Sample each K_i in Z_q^2 and publish [K_i*A]_2.
    for (std::size_t i = 0; i < blocks; ++i) {
        secret.k.push_back({Sample(), Sample()});
        pub.ka.push_back(Mul(g, Dot(secret.k.back(), a)));
    }
    return {std::move(pub), std::move(secret)};
}

/**
 * @brief Creates an SPSEQ signature and one-use adaptation tag.
 * Figure 3 Sign. The tag stores u2, w, and the proof for w.
 * 1. Require the message dimension to match the rows of K.
 * 2. Sample r1, r2 in Z_q and v in Z_q^*, then set t = r1*A0, w = r2*A0, z0 = v*z, z1 = v*D.
 * 3. u1 = K0^T*t + K^T*M.
 * 4. u2 = K0^T*w and pi = v*p. Prove t and w with the shared z0, z1 and pi.
 */
Signature Sign(const Parameters& pp, const SecretKey& key, const std::vector<ECP>& message) {
    // 1. Require the message dimension to match the rows of K.
    if (message.size() != key.k.size()) throw std::invalid_argument("SPSEQ message length mismatch");
    // 2. Sample r1, r2 in Z_q and v in Z_q^*, then set t = r1*A0, w = r2*A0, z0 = v*z, z1 = v*D.
    const auto r1 = Sample(), r2 = Sample(), v = Sample(true);
    const auto t = Scale(pp.branches[0], r1), w = Scale(pp.branches[0], r2);
    const std::array<G2Pair, 2> z{Scale(pp.z, v), Scale(pp.d, v)};
    // 3. u1 = K0^T*t + K^T*M.
    auto u = LinearK0(key.k0, t);
    for (std::size_t i = 0; i < message.size(); ++i) {
        u[0] = Add(u[0], Mul(message[i], key.k[i][0]));
        u[1] = Add(u[1], Mul(message[i], key.k[i][1]));
    }
    // 4. u2 = K0^T*w and pi = v*p. Prove t and w with the shared z0, z1 and pi.
    return {u, t, Prove(pp, t, r1, v, z), z, Mul(pp.p, v),
            Tag{LinearK0(key.k0, w), w, Prove(pp, w, r2, v, z)}};
}

/**
 * @brief Checks the SPSEQ signature and optional tag.
 * 1. Check message dimensions and points, the common proof, the proof for t, and the linear relation for u1.
 * 2. If the tag is present, check the proof for w and the linear relation for u2 with an empty message.
 */
bool Verify(const Parameters& pp, const PublicKey& key, const std::vector<ECP>& message, const Signature& sig) {
    // 1. Check message dimensions and points, the common proof, the proof for t, and the linear relation for u1.
    if (message.size() != key.ka.size() ||
        !std::all_of(message.begin(), message.end(), [](ECP p) { return Valid(p); }) ||
        !VerifyCommon(pp, sig) || !VerifyPart(pp, sig.t, sig.part, sig.z) ||
        !VerifyLinear(key, sig.u, sig.t, message)) return false;
    // 2. If the tag is present, check the proof for w and the linear relation for u2 with an empty message.
    return !sig.tag || (VerifyPart(pp, sig.tag->w, sig.tag->part, sig.z) &&
                       VerifyLinear(key, sig.tag->u, sig.tag->w, {}));
}

/**
 * @brief Adapts a signature for the representative scale*M.
 * Figure 3 ChgRep. The SBS caller scales the representative itself.
 * 1. Require a valid signature with its tag and a nonzero scale.
 * 2. Sample psi and alpha from Z_q^*.
 * 3. u1_prime = scale*u1 + psi*u2 and t_prime = scale*t + psi*w.
 * 4. For each branch b, sample beta_b from Z_q^* and set z_b_prime = alpha*z_b.
 * 5. C_b_prime = alpha*scale*C1_b + alpha*psi*C2_b + beta_b*D.
 * 6. Pi_b_prime = alpha*scale*Pi1_b + alpha*psi*Pi2_b + beta_b*A_b.
 * 7. pi_prime = alpha*pi. Return the adapted signature with an empty tag.
 */
std::optional<Signature> ChangeRep(const Parameters& pp, const PublicKey& key,
    const std::vector<ECP>& message, const Signature& sig, const mpz_class& scale) {
    // 1. Require a valid signature with its tag and a nonzero scale.
    if (!sig.tag || scale == 0 || !Verify(pp, key, message, sig)) return std::nullopt;
    // 2. Sample psi and alpha from Z_q^*.
    const auto psi = Sample(true), alpha = Sample(true);
    Signature out;
    // 3. u1_prime = scale*u1 + psi*u2 and t_prime = scale*t + psi*w.
    out.u = Sum(Scale(sig.u, scale), Scale(sig.tag->u, psi));
    out.t = Sum(Scale(sig.t, scale), Scale(sig.tag->w, psi));
    for (std::size_t b = 0; b < 2; ++b) {
        // 4. For each branch b, sample beta_b from Z_q^* and set z_b_prime = alpha*z_b.
        const auto beta = Sample(true);
        out.z[b] = Scale(sig.z[b], alpha);
        // 5. C_b_prime = alpha*scale*C1_b + alpha*psi*C2_b + beta_b*D.
        out.part.c[b] = Sum(Sum(Scale(sig.part.c[b], Mod(alpha * scale)),
                                Scale(sig.tag->part.c[b], Mod(alpha * psi))), Scale(pp.d, beta));
        // 6. Pi_b_prime = alpha*scale*Pi1_b + alpha*psi*Pi2_b + beta_b*A_b.
        out.part.pi[b] = Sum(Sum(Scale(sig.part.pi[b], Mod(alpha * scale)),
                                 Scale(sig.tag->part.pi[b], Mod(alpha * psi))), Scale(pp.branches[b], beta));
    }
    // 7. pi_prime = alpha*pi. Return the adapted signature with an empty tag.
    out.pi = Mul(sig.pi, alpha);
    return out;
}

/**
 * @brief Encodes the verification key for the SBS transcript.
 * 1. out = BE32(n) || Enc(A) || Enc(K0*A) || Enc(K*A).
 */
std::string Encode(const PublicKey& key) {
    // 1. out = BE32(n) || Enc(A) || Enc(K0*A) || Enc(K*A).
    std::string output;
    Number(output, key.ka.size(), 4);
    Append(output, key.a);
    Append(output, key.k0a);
    for (auto p : key.ka) output += PointBytes(p);
    return output;
}

/**
 * @brief Encodes the signature and optional adaptation tag.
 * 1. out = Enc(u1) || Enc(t) || Enc(proof_t) || Enc(z0) || Enc(z1) || Enc(pi).
 * 2. Append a tag-presence byte and, when present, Enc(u2) || Enc(w) || Enc(proof_w).
 */
std::string Encode(const Signature& signature) {
    // 1. out = Enc(u1) || Enc(t) || Enc(proof_t) || Enc(z0) || Enc(z1) || Enc(pi).
    std::string output;
    Append(output, signature.u);
    Append(output, signature.t);
    Append(output, signature.part);
    for (auto z : signature.z) Append(output, z);
    output += PointBytes(signature.pi);
    // 2. Append a tag-presence byte and, when present, Enc(u2) || Enc(w) || Enc(proof_w).
    Number(output, signature.tag.has_value(), 1);
    if (signature.tag) {
        Append(output, signature.tag->u);
        Append(output, signature.tag->w);
        Append(output, signature.tag->part);
    }
    return output;
}

} // namespace PGUS_SBS::SPSEQ
