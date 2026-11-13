/**
 * @file PGUS_SBS/src/PGUS_SBS.cpp
 * @brief PGUS sanitizable blind signature construction.
 * @details Implements blind issuance in Figure 3 and sanitization, verification, and tracing in Figure 4.
 */
#include "PGUS_SBS.h"

namespace PGUS_SBS {
using namespace ComparisonCurve;
namespace {

/**
 * @brief Encodes the sanitizer public key for SBS transcripts.
 * 1. pk_san_bytes = Enc(pk_PKE) || Enc(pk_TRS).
 */
std::string Encode(const SanitizerPublic& key) {
    // 1. pk_san_bytes = Enc(pk_PKE) || Enc(pk_TRS).
    return PKE::Encode(key.enc) + DSS::EncodePoint(key.tr);
}

/**
 * @brief Binds a message block to its position and sanitizer key.
 * The implementation indexes blocks from zero and hashes one-based positions.
 * 1. B = BE32(i + 1) || Field(pk_san) || Field(m_i).
 * 2. H_i = HashG2("PGUS-SBS/H", B).
 */
ECP2 BlockHash(const SanitizerPublic& san, std::size_t i, std::string_view block) {
    // 1. B = BE32(i + 1) || Field(pk_san) || Field(m_i).
    std::string input;
    Number(input, i + 1, 4);
    Field(input, Encode(san));
    Field(input, block);
    // 2. H_i = HashG2("PGUS-SBS/H", B).
    return HashG2("PGUS-SBS/H", std::move(input));
}

/**
 * @brief Binds both SPSEQ signatures and the parties to the TRS message.
 * 1. M_TRS = Field(pk_sig) || Field(pk_san) || Field(mu) || Field(eta).
 */
std::string RingMessage(const SignerPublic& signer, const SanitizerPublic& san,
                        const SPSEQ::Signature& mu, const SPSEQ::Signature& eta) {
    // 1. M_TRS = Field(pk_sig) || Field(pk_san) || Field(mu) || Field(eta).
    std::string output;
    Field(output, SPSEQ::Encode(signer.sp) + DSS::EncodePoint(signer.tr));
    Field(output, Encode(san));
    Field(output, SPSEQ::Encode(mu));
    Field(output, SPSEQ::Encode(eta));
    return output;
}

/**
 * @brief Encodes the admissibility vector for encryption.
 * 1. plaintext = BE32_bytes(zeta_1) || ... || BE32_bytes(zeta_n).
 */
std::string EncodeScalars(const std::vector<mpz_class>& values) {
    std::string plaintext;
    // 1. plaintext = BE32_bytes(zeta_1) || ... || BE32_bytes(zeta_n).
    for (const auto& v : values) plaintext += ScalarBytes(v);
    return plaintext;
}

/**
 * @brief Recovers a canonical scalar vector from the plaintext.
 * 1. Require |plaintext| = 32 * n bytes.
 * 2. Decode each 32-byte scalar zeta_i and reject if zeta_i >= q.
 */
std::optional<std::vector<mpz_class>> DecodeScalars(std::string_view bytes, std::size_t size) {
    // 1. Require |plaintext| = 32 * n bytes.
    if (bytes.size() != size * 32) return std::nullopt;
    std::vector<mpz_class> values;
    values.reserve(size);
    while (!bytes.empty()) {
        // 2. Decode each 32-byte scalar zeta_i and reject if zeta_i >= q.
        auto v = Integer(bytes.substr(0, 32));
        if (v >= Order()) return std::nullopt;
        values.push_back(std::move(v));
        bytes.remove_prefix(32);
    }
    return values;
}

/**
 * @brief Checks the dimensions of an SBS signature.
 * 1. Require |M| = |X| = |Y| = |h| = |K*A| = n >= 2, with ciphertext lengths (32*n, 12, 16).
 */
bool Shape(const SignerPublic& signer, const Message& message, const UserState& data) {
    const auto n = message.size();
    // 1. Require |M| = |X| = |Y| = |h| = |K*A| = n >= 2, with ciphertext lengths (32*n, 12, 16).
    return n >= 2 && n == signer.sp.ka.size() && n == data.request.x.size() &&
           n == data.request.y.size() && n == data.h.size() &&
           data.ciphertext.body.size() == 32 * n && data.ciphertext.nonce.size() == 12 &&
           data.ciphertext.tag.size() == 16;
}

} // namespace

/**
 * @brief Generates the signer keys in Figure 3.
 * 1. (spk_sig, ssk_sig) = SPSEQ.KeyGen(n).
 * 2. (tpk_sig, tsk_sig) = TRS.KeyGen().
 */
std::pair<SignerPublic, SignerSecret> KGenSig(std::size_t blocks) {
    // 1. (spk_sig, ssk_sig) = SPSEQ.KeyGen(n).
    auto [pk, sk] = SPSEQ::KeyGen(blocks);
    // 2. (tpk_sig, tsk_sig) = TRS.KeyGen().
    const auto tr = KeyGen();
    return {{std::move(pk), tr.publicKey}, {std::move(sk), tr.secret}};
}

/**
 * @brief Generates the sanitizer keys in Figure 3.
 * 1. (epk_san, esk_san) = PKE.KeyGen().
 * 2. (tpk_san, tsk_san) = TRS.KeyGen().
 */
std::pair<SanitizerPublic, SanitizerSecret> KGenSan() {
    // 1. (epk_san, esk_san) = PKE.KeyGen().
    auto [pk, sk] = PKE::KeyGen();
    // 2. (tpk_san, tsk_san) = TRS.KeyGen().
    const auto tr = KeyGen();
    return {{pk, tr.publicKey}, {std::move(sk), tr.secret}};
}

/**
 * @brief Builds the blinded signing request in Figure 3.
 * The local x variable stores X_i. Only (X, Y) is sent to the signer.
 * 1. Require n >= 2 and |allowed| = n.
 * 2. For each i, sample x_i and y_i from Z_q^*.
 * 3. X_i = x_i * G1, Y_i = y_i * X_i, h_i = y_i * H_i(m_i).
 * 4. zeta_i = y_i if i is admissible, and 0 otherwise.
 * 5. c = PKE.Enc(epk_san, EncodeScalars(zeta)).
 */
UserState Extract(const SanitizerPublic& san, const Message& message, const std::vector<bool>& allowed) {
    // 1. Require n >= 2 and |allowed| = n.
    if (message.size() < 2 || allowed.size() != message.size())
        throw std::invalid_argument("Invalid PGUS message or admissibility");
    UserState state;
    std::vector<mpz_class> zeta;
    for (std::size_t i = 0; i < message.size(); ++i) {
        // 2. For each i, sample x_i and y_i from Z_q^*.
        const auto x = Mul(G1(), Sample(true));
        const auto y = Sample(true);
        // 3. X_i = x_i * G1, Y_i = y_i * X_i, h_i = y_i * H_i(m_i).
        state.request.x.push_back(x);
        state.request.y.push_back(Mul(x, y));
        state.h.push_back(Mul(BlockHash(san, i, message[i]), y));
        // 4. zeta_i = y_i if i is admissible, and 0 otherwise.
        zeta.push_back(allowed[i] ? y : mpz_class(0));
    }
    // 5. c = PKE.Enc(epk_san, EncodeScalars(zeta)).
    state.ciphertext = PKE::Encrypt(san.enc, EncodeScalars(zeta));
    return state;
}

/**
 * @brief Signs the blinded vectors in Figure 3.
 * 1. Require X and Y to have n nonidentity G1 coordinates.
 * 2. mu = SPSEQ.Sign(ssk_sig, X) and eta = SPSEQ.Sign(ssk_sig, Y).
 * 3. tau = TRS.Sign(tsk_sig, ring, M_TRS(mu, eta)).
 */
Inner Sign(const SPSEQ::Parameters& pp, const SignerPublic& signer, const SignerSecret& secret,
           const SanitizerPublic& san, const Request& request) {
    // 1. Require X and Y to have n nonidentity G1 coordinates.
    if (request.x.size() != signer.sp.ka.size() || request.y.size() != signer.sp.ka.size())
        throw std::invalid_argument("Invalid PGUS signing request");
    for (std::size_t i = 0; i < request.x.size(); ++i)
        if (!Valid(request.x[i]) || !Valid(request.y[i]))
            throw std::invalid_argument("Invalid PGUS request point");
    // 2. mu = SPSEQ.Sign(ssk_sig, X) and eta = SPSEQ.Sign(ssk_sig, Y).
    auto mu = SPSEQ::Sign(pp, secret.sp, request.x);
    auto eta = SPSEQ::Sign(pp, secret.sp, request.y);
    // 3. tau = TRS.Sign(tsk_sig, ring, M_TRS(mu, eta)).
    auto ring = TRS::Sign({signer.tr, san.tr}, 0, secret.tr, RingMessage(signer, san, mu, eta));
    return {std::move(mu), std::move(eta), std::move(ring)};
}

/**
 * @brief Assembles the SBS signature in Figure 3.
 * 1. sigma = ((mu, eta), (h, X, Y), c, tau).
 */
Signature Derive(UserState state, Inner inner) {
    // 1. sigma = ((mu, eta), (h, X, Y), c, tau).
    return {std::move(state), std::move(inner)};
}

/**
 * @brief Updates a signature for admissible edits in Figure 4.
 * The updated exponent is stored in zeta. The SPSEQ backend consumes the adaptation tags.
 * 1. Require consistent signature dimensions and an adaptation tag for both SPSEQ signatures.
 * 2. zeta = DecodeScalars(PKE.Dec(esk_san, c)).
 * 3. Apply each distinct edit i only if i is in range and zeta_i != 0.
 * 4. Sample r, s from Z_q^* and set rs = r*s mod q.
 * 5. mu_prime = ChangeRep(X, mu, r) and eta_prime = ChangeRep(Y, eta, rs).
 * 6. X_i_prime = r*X_i and Y_i_prime = rs*Y_i.
 * 7. zeta_i_prime = s*zeta_i mod q.
 * 8. h_i_prime = zeta_i_prime*H_i(m_i_prime) if zeta_i_prime != 0, and s*h_i otherwise.
 * 9. c_prime = PKE.Enc(epk_san, EncodeScalars(zeta_prime)).
 * 10. tau_prime = TRS.Sign(tsk_san, ring, M_TRS(mu_prime, eta_prime)).
 * 11. Return (m_prime, ((mu_prime, eta_prime), (h_prime, X_prime, Y_prime), c_prime, tau_prime)).
 */
std::optional<std::pair<Message, Signature>> Sanit(const SPSEQ::Parameters& pp, const SignerPublic& signer,
    const SanitizerPublic& san, const SanitizerSecret& secret, const Message& message,
    const Signature& sig, const std::vector<Modification>& changes) {
    // 1. Require consistent signature dimensions and an adaptation tag for both SPSEQ signatures.
    if (!Shape(signer, message, sig.data) || !sig.inner.mu.tag || !sig.inner.eta.tag) return std::nullopt;
    // 2. zeta = DecodeScalars(PKE.Dec(esk_san, c)).
    auto plaintext = PKE::Decrypt(secret.enc, sig.data.ciphertext);
    if (!plaintext) return std::nullopt;
    auto zeta = DecodeScalars(*plaintext, message.size());
    if (!zeta) return std::nullopt;
    // 3. Apply each distinct edit i only if i is in range and zeta_i != 0.
    auto updated = message;
    std::vector<bool> changed(message.size());
    for (const auto& [index, value] : changes) {
        if (index >= message.size() || changed[index] || (*zeta)[index] == 0) return std::nullopt;
        changed[index] = true;
        updated[index] = value;
    }
    // 4. Sample r, s from Z_q^* and set rs = r*s mod q.
    const auto r = Sample(true), s = Sample(true), rs = Mod(r * s);
    // 5. mu_prime = ChangeRep(X, mu, r) and eta_prime = ChangeRep(Y, eta, rs).
    auto mu = SPSEQ::ChangeRep(pp, signer.sp, sig.data.request.x, sig.inner.mu, r);
    auto eta = SPSEQ::ChangeRep(pp, signer.sp, sig.data.request.y, sig.inner.eta, rs);
    if (!mu || !eta) return std::nullopt;
    UserState state;
    for (std::size_t i = 0; i < message.size(); ++i) {
        if (!Valid(sig.data.h[i])) return std::nullopt;
        // 6. X_i_prime = r*X_i and Y_i_prime = rs*Y_i.
        state.request.x.push_back(Mul(sig.data.request.x[i], r));
        state.request.y.push_back(Mul(sig.data.request.y[i], rs));
        // 7. zeta_i_prime = s*zeta_i mod q.
        auto& exponent = (*zeta)[i];
        exponent = Mod(s * exponent);
        // 8. h_i_prime = zeta_i_prime*H_i(m_i_prime) if zeta_i_prime != 0, and s*h_i otherwise.
        state.h.push_back(exponent != 0 ? Mul(BlockHash(san, i, updated[i]), exponent) : Mul(sig.data.h[i], s));
    }
    // 9. c_prime = PKE.Enc(epk_san, EncodeScalars(zeta_prime)).
    state.ciphertext = PKE::Encrypt(san.enc, EncodeScalars(*zeta));
    // 10. tau_prime = TRS.Sign(tsk_san, ring, M_TRS(mu_prime, eta_prime)).
    auto ring = TRS::Sign({signer.tr, san.tr}, 1, secret.tr, RingMessage(signer, san, *mu, *eta));
    // 11. Return (m_prime, ((mu_prime, eta_prime), (h_prime, X_prime, Y_prime), c_prime, tau_prime)).
    return std::make_pair(std::move(updated), Derive(std::move(state), {std::move(*mu), std::move(*eta), std::move(ring)}));
}

/**
 * @brief Checks an SBS signature in Figure 4.
 * 1. Require consistent dimensions and tag presence, then verify SPSEQ(X, mu) and SPSEQ(Y, eta).
 * 2. For each i, require Y_i != G1, valid h_i, and e(X_i, h_i) = e(Y_i, H_i(m_i)).
 * 3. Accept iff TRS.Verify(ring, M_TRS(mu, eta), tau) succeeds.
 */
bool Verify(const SPSEQ::Parameters& pp, const SignerPublic& signer, const SanitizerPublic& san,
            const Message& message, const Signature& sig) {
    const auto& data = sig.data;
    const auto& inner = sig.inner;
    // 1. Require consistent dimensions and tag presence, then verify SPSEQ(X, mu) and SPSEQ(Y, eta).
    if (!Shape(signer, message, data) || inner.mu.tag.has_value() != inner.eta.tag.has_value() ||
        !SPSEQ::Verify(pp, signer.sp, data.request.x, inner.mu) ||
        !SPSEQ::Verify(pp, signer.sp, data.request.y, inner.eta)) return false;
    for (std::size_t i = 0; i < message.size(); ++i) {
        // 2. For each i, require Y_i != G1, valid h_i, and e(X_i, h_i) = e(Y_i, H_i(m_i)).
        if (Equal(data.request.y[i], G1()) || !Valid(data.h[i]) ||
            !PairEqual({{data.request.x[i], data.h[i]}}, {{data.request.y[i], BlockHash(san, i, message[i])}}))
            return false;
    }
    // 3. Accept iff TRS.Verify(ring, M_TRS(mu, eta), tau) succeeds.
    return TRS::Verify({signer.tr, san.tr}, RingMessage(signer, san, inner.mu, inner.eta), inner.ring);
}

/**
 * @brief Traces two verified SBS signatures in Figure 4.
 * 1. Reconstruct M_TRS for both signatures under the same ordered ring.
 * 2. r = TRS.Trace(ring, (M_a, tau_a), (M_b, tau_b)).
 * 3. Return Invalid if r = Linked, and r otherwise.
 */
TRS::Result Trace(const SignerPublic& signer, const SanitizerPublic& san, const Signature& a, const Signature& b) {
    // 1. Reconstruct M_TRS for both signatures under the same ordered ring.
    const auto ma = RingMessage(signer, san, a.inner.mu, a.inner.eta);
    const auto mb = RingMessage(signer, san, b.inner.mu, b.inner.eta);
    // 2. r = TRS.Trace(ring, (M_a, tau_a), (M_b, tau_b)).
    const auto result = TRS::Trace({signer.tr, san.tr}, ma, a.inner.ring, mb, b.inner.ring);
    // 3. Return Invalid if r = Linked, and r otherwise.
    return result == TRS::Result::Linked ? TRS::Result::Invalid : result;
}

/**
 * @brief Serializes the complete SBS object for size accounting.
 * 1. Prefix = Field(Enc(mu)) || Field(Enc(eta)) || BE32(n).
 * 2. Append Enc(h_i) || Enc(X_i) || Enc(Y_i) for each i in order.
 * 3. Append Enc(c) || Enc(tau).
 */
std::string EncodeSignature(const Signature& sig) {
    // 1. Prefix = Field(Enc(mu)) || Field(Enc(eta)) || BE32(n).
    std::string output;
    Field(output, SPSEQ::Encode(sig.inner.mu));
    Field(output, SPSEQ::Encode(sig.inner.eta));
    const auto& data = sig.data;
    Number(output, data.h.size(), 4);
    // 2. Append Enc(h_i) || Enc(X_i) || Enc(Y_i) for each i in order.
    for (std::size_t i = 0; i < data.h.size(); ++i) {
        output += PointBytes(data.h[i]);
        output += DSS::EncodePoint(data.request.x.at(i));
        output += DSS::EncodePoint(data.request.y.at(i));
    }
    // 3. Append Enc(c) || Enc(tau).
    output += PKE::Encode(data.ciphertext);
    output += TRS::Encode(sig.inner.ring);
    return output;
}

} // namespace PGUS_SBS
