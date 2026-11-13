/**
 * @file LSanS/include/LSanS.h
 * @brief Interfaces for LSanS certificate issuance and derivation.
 * @details Defines the CA anchor, vehicle signature, and accountability interfaces.
 */
#pragma once

#include "ComparisonCurve.h"

#include <optional>

namespace LSanS {

// Shared scalar and public-point representation for CA and vehicle keys.
using ComparisonCurve::Key;
// Shared key generator for both roles.
using ComparisonCurve::KeyGen;

// Schnorr signature over one certificate layer.
struct Signature {
    ECP commitment;     ///< Nonce commitment R.
    mpz_class response; ///< Challenge response s.
};

// CA-issued master certificate for one registered vehicle.
struct Master {
    std::string fixed;   ///< Immutable certificate field.
    std::uint64_t slot;  ///< Initial or current variable slot.
    ECP vehicle;         ///< Registered vehicle public key Q_i.
    std::uint8_t policy; ///< Admissibility policy identifier.
    Signature anchor;    ///< CA anchor (R0, s0).
};

// Vehicle-derived certificate.
struct Derived {
    Master fields;      ///< Certificate fields and retained CA anchor.
    Signature variable; ///< Vehicle signature (R1, s1) on the current slot.
};

// Maps benchmark vehicle identifiers to registered public keys.
class Registry {
public:
    /**
     * @brief Registers a public key for a new vehicle identifier.
     * @param vehicleId Vehicle identifier.
     * @param key Candidate vehicle public key.
     * @return True on successful registration.
     */
    bool Register(std::uint64_t vehicleId, ECP key);
    /**
     * @brief Retrieves the registered vehicle public key.
     * @param vehicleId Previously registered identifier.
     * @return Public key of the registered vehicle.
     */
    ECP KeyFor(std::uint64_t vehicleId) const;

private:
    std::map<std::uint64_t, ECP> entries_; ///< Registered identifier-to-key map.
};

/**
 * @brief Issues a master certificate for a registered vehicle.
 * @param ca CA key pair.
 * @param registry Registry used for issuance.
 * @param vehicleId Registered recipient.
 * @param fixed Immutable certificate bytes.
 * @param slot Initial variable slot.
 * @param policy Admissibility policy identifier.
 * @return Master certificate with its CA anchor.
 */
Master Sign(const Key& ca, const Registry& registry, std::uint64_t vehicleId,
            std::string fixed, std::uint64_t slot, std::uint8_t policy);
/**
 * @brief Derives a certificate with a replacement slot.
 * @param ca CA public key.
 * @param vehicle Vehicle key pair.
 * @param master Master certificate.
 * @param slot Requested replacement slot.
 * @return Derived certificate or an empty value on rejection.
 */
std::optional<Derived> Sanit(ECP ca, const Key& vehicle, const Master& master, std::uint64_t slot);
/**
 * @brief Verifies both signature layers and the slot policy.
 * @param ca CA public key.
 * @param derived Derived certificate.
 * @return True if the certificate passes verification.
 */
bool Verify(ECP ca, const Derived& derived);
/**
 * @brief Retrieves the public key bound to a verified certificate.
 * @param ca CA public key.
 * @param derived Certificate to trace.
 * @return Verified vehicle public key or an empty value.
 */
std::optional<ECP> Trace(ECP ca, const Derived& derived);
/**
 * @brief Compares the vehicle bindings of two verified certificates.
 * @param ca CA public key.
 * @param a First certificate.
 * @param b Second certificate.
 * @return Whether both certificates bind the same key, or an empty value if either is rejected.
 */
std::optional<bool> Link(ECP ca, const Derived& a, const Derived& b);
/**
 * @brief Serializes the two signature layers.
 * @param derived Certificate whose signatures are encoded.
 * @return Concatenated CA and vehicle signature encodings.
 */
std::string EncodeSignature(const Derived& derived);

} // namespace LSanS
