/**
 * @file PGUS_SBS/include/Primitives.h
 * @brief Primitive interfaces for the PGUS benchmark.
 * @details Defines hash-to-curve, pairing comparisons, SPSEQ, two-member TRS, and hybrid encryption.
 */
#pragma once

#include "ComparisonCurve.h"

namespace PGUS_SBS {

/**
 * @brief Hashes a transcript into G1.
 * @param domain Domain separation tag.
 * @param message Transcript bytes.
 * @return Prime-order G1 point.
 */
ECP HashG1(std::string_view domain, std::string message);
/**
 * @brief Hashes a transcript into G2.
 * @param domain Domain separation tag.
 * @param message Transcript bytes.
 * @return Prime-order G2 point.
 */
ECP2 HashG2(std::string_view domain, std::string message);
/**
 * @brief Compares two products of pairings.
 * @param left Left-hand pairs in G1, G2 order.
 * @param right Right-hand pairs in G1, G2 order.
 * @return True if the products are equal.
 */
bool PairEqual(std::initializer_list<std::pair<ECP, ECP2>> left,
               const std::vector<std::pair<ECP, ECP2>>& right);

namespace SPSEQ {
// Two subgroup scalars.
using ScalarPair = std::array<mpz_class, 2>;
// Two G1 points.
using G1Pair = std::array<ECP, 2>;
// Two G2 points.
using G2Pair = std::array<ECP2, 2>;

// SPSEQ common reference string.
struct Parameters {
    std::array<G1Pair, 2> branches, ///< G1 proof branch bases A0 and A1.
    qaCommit;                       ///< G1 QA-NIZK commitment matrix.
    G1Pair qaBase;                            ///< G1 QA-NIZK basis.
    G2Pair d, ///< Encoded G2 basis D.
    z;        ///< Encoded G2 direction outside the span of D.
    ECP2 p;                                   ///< G2 QA-NIZK projection.
};
// SPSEQ public key.
struct PublicKey {
    G2Pair a, ///< Encoded verification column A.
    k0a;      ///< Encoded column K0 * A.
    std::vector<ECP2> ka; ///< Encoded row products K_i * A.
};
// SPSEQ private key.
struct SecretKey {
    std::array<ScalarPair, 2> k0; ///< Two rows of K0.
    std::vector<ScalarPair> k;    ///< Message matrix K.
};
// Two branches of the proof for one word.
struct ProofPart {
    std::array<G2Pair, 2> c;  ///< G2 proof commitments C_b.
    std::array<G1Pair, 2> pi; ///< G1 proof vectors Pi_b.
};
// One-use SPSEQ adaptation tag.
struct Tag {
    G1Pair u, ///< Auxiliary linear value u2.
    w;        ///< Auxiliary proof word w.
    ProofPart part; ///< Proof for the auxiliary word.
};
// SPSEQ signature with shared proof components.
struct Signature {
    G1Pair u, ///< Linear signature value u1.
    t;        ///< Signed proof word t.
    ProofPart part;          ///< Proof for the signed word.
    std::array<G2Pair, 2> z; ///< Shared G2 proof vectors z_b.
    ECP2 pi;                 ///< Shared G2 projection proof.
    std::optional<Tag> tag;  ///< Optional auxiliary tag for one representation change.
};

/**
 * @brief Generates common parameters for SPSEQ.
 * @return Common reference string.
 */
Parameters Setup();
/**
 * @brief Generates SPSEQ signing and verification keys.
 * @param blocks Number of coordinates, at least two.
 * @return Public and secret keys.
 */
std::pair<PublicKey, SecretKey> KeyGen(std::size_t blocks);
/**
 * @brief Signs a G1 vector with SPSEQ.
 * @param pp Common reference string.
 * @param key SPSEQ secret key.
 * @param message Vector of G1 message points.
 * @return Signature with its one-use adaptation tag.
 */
Signature Sign(const Parameters& pp, const SecretKey& key, const std::vector<ECP>& message);
/**
 * @brief Verifies an SPSEQ signature and its tag when present.
 * @param pp Common reference string.
 * @param key SPSEQ verification key.
 * @param message Vector of G1 message points.
 * @param sig Signature and optional adaptation tag.
 * @return True on successful verification.
 */
bool Verify(const Parameters& pp, const PublicKey& key, const std::vector<ECP>& message, const Signature& sig);
/**
 * @brief Adapts a signature to a scaled representative.
 * @param pp Common reference string.
 * @param key SPSEQ verification key.
 * @param message Original representative.
 * @param sig Original signature with its adaptation tag.
 * @param scale Nonzero canonical subgroup scalar.
 * @return Adapted signature or an empty value on rejection.
 */
std::optional<Signature> ChangeRep(const Parameters& pp, const PublicKey& key,
    const std::vector<ECP>& message, const Signature& sig, const mpz_class& scale);
/**
 * @brief Serializes the SPSEQ public key.
 * @param key Public key to encode.
 * @return Public-key transcript bytes.
 */
std::string Encode(const PublicKey& key);
/**
 * @brief Serializes the SPSEQ signature.
 * @param signature Signature to encode.
 * @return Signature transcript bytes.
 */
std::string Encode(const Signature& signature);
} // namespace SPSEQ

namespace TRS {
// Two ordered TRS public keys in signer, sanitizer order.
using Ring = std::array<ECP, 2>;
// Two-member Fujisaki-Suzuki ring signature.
struct Signature {
    ECP slope;                                    ///< Line slope A1.
    std::array<mpz_class, 2> challenge, ///< Per-member challenge scalars c_i.
    response;                           ///< Per-member response scalars z_i.
};

/**
 * @brief Produces a two-member traceable ring signature.
 * @param ring Ordered public keys.
 * @param member Zero-based index of the signing member.
 * @param secret Signing member secret scalar.
 * @param message Ring message bytes.
 * @return Traceable ring signature.
 */
Signature Sign(const Ring& ring, std::size_t member, const mpz_class& secret, std::string_view message);
/**
 * @brief Verifies a traceable ring signature.
 * @param ring Ordered public keys.
 * @param message Ring message bytes.
 * @param signature Signature to verify.
 * @return True if the ring challenge is valid.
 */
bool Verify(const Ring& ring, std::string_view message, const Signature& signature);
// Outcome of comparing two traceable ring signatures.
enum class Result { Independent, Signer, Sanitizer, Linked, Invalid };
/**
 * @brief Compares two verified signatures under the same ring and issue.
 * @param ring Ordered public keys.
 * @param a First verified ring message.
 * @param sigA First verified signature.
 * @param b Second verified ring message.
 * @param sigB Second verified signature.
 * @return Trace result for the two transcripts.
 */
Result Trace(const Ring& ring, std::string_view a, const Signature& sigA,
             std::string_view b, const Signature& sigB);
/**
 * @brief Serializes the TRS signature.
 * @param signature Signature to encode.
 * @return Signature transcript bytes.
 */
std::string Encode(const Signature& signature);
} // namespace TRS

namespace PKE {
// Cramer-Shoup public key in the BLS12-381 G1 subgroup.
struct PublicKey {
    ECP g2, ///< Second generator of G1.
    c,      ///< First Cramer-Shoup verification point.
    d,      ///< Second Cramer-Shoup verification point.
    h;      ///< Cramer-Shoup masking point.
};
// Cramer-Shoup secret key.
struct SecretKey {
    mpz_class x1, ///< First coefficient of c.
    x2,           ///< Second coefficient of c.
    y1,           ///< First coefficient of d.
    y2,           ///< Second coefficient of d.
    z;            ///< Session-point masking exponent.
};
// Hybrid ciphertext for the admissibility vector.
struct Ciphertext {
    ECP u1, ///< First ephemeral generator multiple.
    u2,     ///< Second ephemeral generator multiple.
    e,      ///< Masked session point.
    v;      ///< Cramer-Shoup verification point.
    std::string nonce, ///< 12-byte AES-GCM nonce.
    body,              ///< AES-GCM ciphertext bytes.
    tag;               ///< 16-byte AES-GCM authentication tag.
};

/**
 * @brief Generates the hybrid encryption key pair.
 * @return Encryption public and private keys.
 */
std::pair<PublicKey, SecretKey> KeyGen();
/**
 * @brief Encrypts a byte string for the sanitizer.
 * @param pk Recipient public key.
 * @param plaintext Plaintext bytes.
 * @return Hybrid ciphertext and authentication tag.
 */
Ciphertext Encrypt(const PublicKey& pk, std::string plaintext);
/**
 * @brief Decrypts and authenticates a hybrid ciphertext.
 * @param sk Recipient private key.
 * @param ciphertext Ciphertext to open.
 * @return Plaintext bytes or an empty value on rejection.
 */
std::optional<std::string> Decrypt(const SecretKey& sk, const Ciphertext& ciphertext);
/**
 * @brief Serializes the encryption public key.
 * @param key Public key to encode.
 * @return Public-key transcript bytes.
 */
std::string Encode(const PublicKey& key);
/**
 * @brief Serializes the hybrid ciphertext.
 * @param ciphertext Ciphertext to encode.
 * @return Ciphertext byte string.
 */
std::string Encode(const Ciphertext& ciphertext);
} // namespace PKE
} // namespace PGUS_SBS
