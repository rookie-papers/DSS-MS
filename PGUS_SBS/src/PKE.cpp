/**
 * @file PGUS_SBS/src/PKE.cpp
 * @brief Cramer-Shoup hybrid encryption for the SBS admissibility vector.
 * @details Encapsulates a random G1 point and encrypts the scalar bytes with AES-256-GCM.
 */
#include "Primitives.h"

namespace PGUS_SBS::PKE {
using namespace ComparisonCurve;
namespace {

/**
 * @brief Encodes the points bound by the Cramer-Shoup challenge.
 * 1. B = Enc(u1) || Enc(u2) || Enc(e).
 */
std::string Encapsulation(const Ciphertext& ciphertext) {
    // 1. B = Enc(u1) || Enc(u2) || Enc(e).
    return DSS::EncodePoint(ciphertext.u1) + DSS::EncodePoint(ciphertext.u2) +
           DSS::EncodePoint(ciphertext.e);
}

/**
 * @brief Derives the Cramer-Shoup verification exponent.
 * 1. alpha = HashScalar(domain || Enc(u1) || Enc(u2) || Enc(e)).
 */
mpz_class Challenge(const Ciphertext& ciphertext) {
    // 1. alpha = HashScalar(domain || Enc(u1) || Enc(u2) || Enc(e)).
    return HashScalar("PGUS/Cramer-Shoup/challenge/v1" + Encapsulation(ciphertext));
}

/**
 * @brief Derives the symmetric key from the session point.
 * 1. K = first_32_bytes(SHA-512(domain || Enc(session))).
 */
std::string AesKey(ECP point) {
    // 1. K = first_32_bytes(SHA-512(domain || Enc(session))).
    return Sha512("PGUS/Cramer-Shoup/DEM/v1" + DSS::EncodePoint(point)).substr(0, 32);
}

/**
 * @brief Compares the fixed-width authentication tags.
 * 1. Accept iff OR_i(a_i XOR b_i) = 0.
 */
bool TagEqual(std::string_view a, std::string_view b) {
    // 1. Accept iff OR_i(a_i XOR b_i) = 0.
    unsigned int difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i)
        difference |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    return difference == 0;
}

} // namespace

/**
 * @brief Generates a Cramer-Shoup key pair.
 * 1. Set g1 = G1 and derive g2 in G1 using the second-generator domain.
 * 2. Sample x1, x2, y1, y2 from Z_q and z from Z_q^*.
 * 3. c = x1*g1 + x2*g2, d = y1*g1 + y2*g2, h = z*g1.
 */
std::pair<PublicKey, SecretKey> KeyGen() {
    // 1. Set g1 = G1 and derive g2 in G1 using the second-generator domain.
    const auto g1 = G1();
    const auto g2 = HashG1("PGUS/Cramer-Shoup/g2/v1", "second generator");
    // 2. Sample x1, x2, y1, y2 from Z_q and z from Z_q^*.
    SecretKey sk{Sample(), Sample(), Sample(), Sample(), Sample(true)};
    // 3. c = x1*g1 + x2*g2, d = y1*g1 + y2*g2, h = z*g1.
    return {{g2, Add(Mul(g1, sk.x1), Mul(g2, sk.x2)),
             Add(Mul(g1, sk.y1), Mul(g2, sk.y2)), Mul(g1, sk.z)}, sk};
}

/**
 * @brief Encrypts a scalar transcript using a fresh session point.
 * 1. Sample r, a from Z_q^* and set session = a*g1.
 * 2. u1 = r*g1, u2 = r*g2, e = session + r*h.
 * 3. alpha = Challenge(u1, u2, e) and v = r*c + (r*alpha mod q)*d.
 * 4. Sample a 12-byte nonce, set AAD = Enc(u1, u2, e, v), and derive K from session.
 * 5. (body, tag) = AES-256-GCM.Encrypt(K, nonce, AAD, plaintext).
 */
Ciphertext Encrypt(const PublicKey& pk, std::string plaintext) {
    // 1. Sample r, a from Z_q^* and set session = a*g1.
    const auto r = Sample(true);
    const auto session = Mul(G1(), Sample(true));
    Ciphertext ct;
    // 2. u1 = r*g1, u2 = r*g2, e = session + r*h.
    ct.u1 = Mul(G1(), r);
    ct.u2 = Mul(pk.g2, r);
    ct.e = Add(session, Mul(pk.h, r));
    // 3. alpha = Challenge(u1, u2, e) and v = r*c + (r*alpha mod q)*d.
    ct.v = Add(Mul(pk.c, r), Mul(pk.d, Mod(r * Challenge(ct))));
    // 4. Sample a 12-byte nonce, set AAD = Enc(u1, u2, e, v), and derive K from session.
    ct.nonce = RandomBytes(12);
    ct.body.resize(plaintext.size());
    ct.tag.resize(16);
    auto header = Encapsulation(ct) + DSS::EncodePoint(ct.v);
    auto key = AesKey(session);
    gcm context;
    // 5. (body, tag) = AES-256-GCM.Encrypt(K, nonce, AAD, plaintext).
    GCM_init(&context, key.size(), key.data(), ct.nonce.size(), ct.nonce.data());
    GCM_add_header(&context, header.data(), header.size());
    GCM_add_plain(&context, ct.body.data(), plaintext.data(), plaintext.size());
    GCM_finish(&context, ct.tag.data());
    return ct;
}

/**
 * @brief Checks the Cramer-Shoup equation and opens the authenticated payload.
 * 1. Require 12-byte nonce, 16-byte tag, and subgroup membership of all ciphertext points.
 * 2. Accept the encapsulation only if v = (x1 + alpha*y1)*u1 + (x2 + alpha*y2)*u2.
 * 3. session = e - z*u1 and session must be nonidentity.
 * 4. Derive K from session and reconstruct AAD = Enc(u1, u2, e, v).
 * 5. (plaintext, tag_check) = AES-256-GCM.Decrypt(K, nonce, AAD, body).
 * 6. Return plaintext only if tag_check = tag.
 */
std::optional<std::string> Decrypt(const SecretKey& sk, const Ciphertext& ct) {
    // 1. Require 12-byte nonce, 16-byte tag, and subgroup membership of all ciphertext points.
    if (ct.nonce.size() != 12 || ct.tag.size() != 16 || !Valid(ct.u1) || !Valid(ct.u2))
        return std::nullopt;
    auto e = ct.e, v = ct.v;
    if ((!ECP_isinf(&e) && !Valid(e)) || (!ECP_isinf(&v) && !Valid(v))) return std::nullopt;
    // 2. Accept the encapsulation only if v = (x1 + alpha*y1)*u1 + (x2 + alpha*y2)*u2.
    const auto alpha = Challenge(ct);
    const auto expected = Add(Mul(ct.u1, Mod(sk.x1 + alpha * sk.y1)),
                              Mul(ct.u2, Mod(sk.x2 + alpha * sk.y2)));
    if (!Equal(expected, ct.v)) return std::nullopt;
    // 3. session = e - z*u1 and session must be nonidentity.
    const auto session = Sub(ct.e, Mul(ct.u1, sk.z));
    if (!Valid(session)) return std::nullopt;
    // 4. Derive K from session and reconstruct AAD = Enc(u1, u2, e, v).
    auto key = AesKey(session);
    auto header = Encapsulation(ct) + DSS::EncodePoint(ct.v);
    auto nonce = ct.nonce, body = ct.body;
    std::string plaintext(body.size(), '\0'), tag(16, '\0');
    gcm context;
    // 5. (plaintext, tag_check) = AES-256-GCM.Decrypt(K, nonce, AAD, body).
    GCM_init(&context, key.size(), key.data(), nonce.size(), nonce.data());
    GCM_add_header(&context, header.data(), header.size());
    GCM_add_cipher(&context, plaintext.data(), body.data(), body.size());
    GCM_finish(&context, tag.data());
    // 6. Return plaintext only if tag_check = tag.
    if (!TagEqual(tag, ct.tag)) return std::nullopt;
    return plaintext;
}

/**
 * @brief Encodes the Cramer-Shoup public key.
 * 1. pk_bytes = Enc(g2) || Enc(c) || Enc(d) || Enc(h).
 */
std::string Encode(const PublicKey& key) {
    // 1. pk_bytes = Enc(g2) || Enc(c) || Enc(d) || Enc(h).
    return DSS::EncodePoint(key.g2) + DSS::EncodePoint(key.c) +
           DSS::EncodePoint(key.d) + DSS::EncodePoint(key.h);
}

/**
 * @brief Encodes the full hybrid ciphertext.
 * 1. ct_bytes = Enc(u1) || Enc(u2) || Enc(e) || Enc(v) || nonce || Field(body) || tag.
 */
std::string Encode(const Ciphertext& ciphertext) {
    // 1. ct_bytes = Enc(u1) || Enc(u2) || Enc(e) || Enc(v) || nonce || Field(body) || tag.
    auto encoded = Encapsulation(ciphertext) + DSS::EncodePoint(ciphertext.v) + ciphertext.nonce;
    Field(encoded, ciphertext.body);
    return encoded + ciphertext.tag;
}

} // namespace PGUS_SBS::PKE
