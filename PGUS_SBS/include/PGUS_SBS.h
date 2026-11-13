/**
 * @file PGUS_SBS/include/PGUS_SBS.h
 * @brief Public interfaces for PGUS sanitizable blind signatures.
 * @details Defines the blind-issuance, sanitization, verification, and tracing inputs.
 */
#pragma once

#include "Primitives.h"

namespace PGUS_SBS {

// Ordered message blocks.
using Message = std::vector<std::string>;
// Replacement block and its zero-based position.
using Modification = std::pair<std::size_t, std::string>;

// Public keys for the SBS signer.
struct SignerPublic {
    SPSEQ::PublicKey sp; ///< SPSEQ verification key.
    ECP tr;              ///< Signer TRS public key.
};
// Private keys for the SBS signer.
struct SignerSecret {
    SPSEQ::SecretKey sp; ///< SPSEQ signing key.
    mpz_class tr;        ///< Signer TRS signing scalar.
};
// Public keys for the SBS sanitizer.
struct SanitizerPublic {
    PKE::PublicKey enc; ///< Encryption key for the admissibility vector.
    ECP tr;             ///< Sanitizer TRS public key.
};
// Private keys for the SBS sanitizer.
struct SanitizerSecret {
    PKE::SecretKey enc; ///< Decryption key for the admissibility vector.
    mpz_class tr;       ///< Sanitizer TRS signing scalar.
};

// Blinded request sent to the signer.
struct Request {
    std::vector<ECP> x, ///< Blinded base vector X.
    y;                  ///< Blinded image vector Y.
};
// User state retained across blind issuance.
struct UserState {
    Request request;            ///< Blinded request sent to the signer.
    std::vector<ECP2> h;        ///< Per-block G2 commitments.
    PKE::Ciphertext ciphertext; ///< Encrypted admissibility scalars.
};
// Signer response before derivation.
struct Inner {
    SPSEQ::Signature mu, ///< SPSEQ signature on X.
    eta;                 ///< SPSEQ signature on Y.
    TRS::Signature ring;      ///< Traceable ring signature over the SPSEQ pair.
};
// Complete signature on a message.
struct Signature {
    UserState data; ///< Per-block commitments and encrypted admissibility vector.
    Inner inner;    ///< Structure-preserving signatures and ring signature.
};

/**
 * @brief Generates the SBS signer keys.
 * @param blocks Number of message blocks.
 * @return Signer public and private keys.
 */
std::pair<SignerPublic, SignerSecret> KGenSig(std::size_t blocks);
/**
 * @brief Generates the SBS sanitizer keys.
 * @return Sanitizer public and private keys.
 */
std::pair<SanitizerPublic, SanitizerSecret> KGenSan();
/**
 * @brief Prepares the blinded request and retained user state.
 * @param san Intended sanitizer public keys.
 * @param message Ordered message blocks.
 * @param allowed Per-block admissibility mask.
 * @return Blinded request, commitments, and encrypted admissibility scalars.
 */
UserState Extract(const SanitizerPublic& san, const Message& message, const std::vector<bool>& allowed);
/**
 * @brief Signs the blinded request.
 * @param pp SPSEQ common parameters.
 * @param signer Signer public keys.
 * @param secret Signer private keys.
 * @param san Intended sanitizer public keys.
 * @param request Blinded request.
 * @return Signer response containing two SPSEQ signatures and a TRS signature.
 */
Inner Sign(const SPSEQ::Parameters& pp, const SignerPublic& signer, const SignerSecret& secret,
           const SanitizerPublic& san, const Request& request);
/**
 * @brief Assembles the full signature from blind issuance.
 * @param state User state from Extract.
 * @param inner Signer response.
 * @return Complete SBS signature.
 */
Signature Derive(UserState state, Inner inner);
/**
 * @brief Applies admissible edits and updates the signature.
 * @param pp SPSEQ common parameters.
 * @param signer Signer public keys.
 * @param san Sanitizer public keys.
 * @param secret Sanitizer private keys.
 * @param message Original message.
 * @param sig Signature with adaptation tags.
 * @param changes Requested block replacements.
 * @return Updated message and signature, or an empty value on rejection.
 */
std::optional<std::pair<Message, Signature>> Sanit(const SPSEQ::Parameters& pp, const SignerPublic& signer,
    const SanitizerPublic& san, const SanitizerSecret& secret, const Message& message,
    const Signature& sig, const std::vector<Modification>& changes);
/**
 * @brief Verifies an issued or sanitized signature.
 * @param pp SPSEQ common parameters.
 * @param signer Signer public keys.
 * @param san Sanitizer public keys.
 * @param message Message to verify.
 * @param sig Signature to verify.
 * @return True if all signature and pairing checks pass.
 */
bool Verify(const SPSEQ::Parameters& pp, const SignerPublic& signer, const SanitizerPublic& san,
            const Message& message, const Signature& sig);
/**
 * @brief Compares the TRS transcripts of two verified signatures.
 * @param signer Signer public keys.
 * @param san Sanitizer public keys.
 * @param a First verified signature.
 * @param b Second verified signature.
 * @return Traced role, independence, or an invalid result for a linked pair.
 */
TRS::Result Trace(const SignerPublic& signer, const SanitizerPublic& san, const Signature& a, const Signature& b);
/**
 * @brief Serializes a complete SBS signature.
 * @param signature Signature to encode.
 * @return Benchmark encoding of the complete signature.
 */
std::string EncodeSignature(const Signature& signature);

} // namespace PGUS_SBS
