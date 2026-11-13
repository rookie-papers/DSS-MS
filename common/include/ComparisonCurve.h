/**
 * @file common/include/ComparisonCurve.h
 * @brief Shared BLS12-381 utilities for the comparison schemes.
 * @details Provides subgroup arithmetic, random scalars, and transcript encodings.
 */
#pragma once

#include "DSS.h"

#include <cstdint>
#include <fstream>
#include <limits>
#include <string_view>

namespace ComparisonCurve {

/**
 * @brief Retrieves the BLS12-381 subgroup order.
 * @return Subgroup order q.
 */
inline const mpz_class& Order() {
    static const auto order = getCurveOrder();
    return order;
}

/**
 * @brief Reduces an integer modulo the subgroup order.
 * @param value Integer to reduce.
 * @return Canonical subgroup scalar.
 */
inline mpz_class Mod(const mpz_class& value) {
    mpz_class result;
    mpz_mod(result.get_mpz_t(), value.get_mpz_t(), Order().get_mpz_t());
    return result;
}

/**
 * @brief Inverts a scalar modulo the subgroup order.
 * @param value Invertible scalar.
 * @return Canonical modular inverse.
 */
inline mpz_class Inv(const mpz_class& value) {
    mpz_class result;
    if (!mpz_invert(result.get_mpz_t(), value.get_mpz_t(), Order().get_mpz_t()))
        throw std::invalid_argument("Scalar has no inverse");
    return result;
}

/**
 * @brief Decodes an unsigned big-endian integer.
 * @param bytes Input octets.
 * @return Decoded integer.
 */
inline mpz_class Integer(std::string_view bytes) {
    mpz_class value;
    mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
    return value;
}

/**
 * @brief Reads random bytes from the operating system.
 * @param size Requested byte count.
 * @return Random octets.
 */
inline std::string RandomBytes(std::size_t size) {
    thread_local std::ifstream random("/dev/urandom", std::ios::binary);
    std::string bytes(size, '\0');
    if (!random.read(bytes.data(), bytes.size()))
        throw std::runtime_error("Cannot read the OS random source");
    return bytes;
}

/**
 * @brief Samples a uniform subgroup scalar by rejection.
 * @param nonzero Excludes the zero scalar when true.
 * @return Sampled scalar.
 */
inline mpz_class Sample(bool nonzero = false) {
    for (;;) {
        auto scalar = Integer(RandomBytes(32));
        if (scalar < Order() && (!nonzero || scalar != 0)) return scalar;
    }
}

/**
 * @brief Appends a fixed-width big-endian integer.
 * @param bytes Destination transcript.
 * @param value Unsigned integer.
 * @param width Width in bytes, at most eight.
 */
inline void Number(std::string& bytes, std::uint64_t value, unsigned width) {
    while (width != 0) bytes.push_back(static_cast<char>(value >> (8 * --width)));
}

/**
 * @brief Appends a length-prefixed byte string.
 * @param bytes Destination transcript.
 * @param value Field bytes.
 */
inline void Field(std::string& bytes, std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::length_error("Field exceeds uint32 length");
    Number(bytes, value.size(), 4);
    bytes.append(value);
}

/**
 * @brief Encodes a canonical scalar in a fixed-width field.
 * @param scalar Canonical subgroup scalar.
 * @param width Width in bytes, at least 32.
 * @return Big-endian scalar with leading zero padding.
 */
inline std::string ScalarBytes(const mpz_class& scalar, std::size_t width = 32) {
    if (scalar < 0 || scalar >= Order() || width < 32)
        throw std::invalid_argument("Invalid scalar encoding");
    std::string bytes(width, '\0');
    if (scalar != 0) {
        const auto size = (mpz_sizeinbase(scalar.get_mpz_t(), 2) + 7) / 8;
        mpz_export(bytes.data() + width - size, nullptr, 1, 1, 0, 0, scalar.get_mpz_t());
    }
    return bytes;
}

/**
 * @brief Computes a SHA-512 digest.
 * @param bytes Input octets.
 * @return 64-byte digest.
 */
inline std::string Sha512(std::string_view bytes) {
    hash512 hash;
    HASH512_init(&hash);
    for (unsigned char byte : bytes) HASH512_process(&hash, byte);
    std::string digest(64, '\0');
    HASH512_hash(&hash, digest.data());
    return digest;
}

/**
 * @brief Hashes a transcript to a subgroup scalar.
 * @param bytes Encoded transcript.
 * @return SHA-512 digest interpreted and reduced modulo q.
 */
inline mpz_class HashScalar(std::string_view bytes) { return Mod(Integer(Sha512(bytes))); }

/**
 * @brief Retrieves the G1 generator.
 * @return G1 generator point.
 */
inline ECP G1() {
    ECP point;
    ECP_generator(&point);
    return point;
}

/**
 * @brief Retrieves the G2 generator.
 * @return G2 generator point.
 */
inline ECP2 G2() {
    ECP2 point;
    ECP2_generator(&point);
    return point;
}

/**
 * @brief Multiplies a G1 point by a scalar.
 * @param point G1 point.
 * @param scalar Subgroup scalar.
 * @return Scalar multiple in G1.
 */
inline ECP Mul(ECP point, const mpz_class& scalar) { ECP_mul(point, scalar); return point; }
/**
 * @brief Multiplies a G2 point by a scalar.
 * @param point G2 point.
 * @param scalar Subgroup scalar.
 * @return Scalar multiple in G2.
 */
inline ECP2 Mul(ECP2 point, const mpz_class& scalar) { ECP2_mul(point, scalar); return point; }
/**
 * @brief Adds two G1 points.
 * @param a First G1 point.
 * @param b Second G1 point.
 * @return Sum in G1.
 */
inline ECP Add(ECP a, ECP b) { ECP_add(&a, &b); return a; }
/**
 * @brief Adds two G2 points.
 * @param a First G2 point.
 * @param b Second G2 point.
 * @return Sum in G2.
 */
inline ECP2 Add(ECP2 a, ECP2 b) { ECP2_add(&a, &b); return a; }
/**
 * @brief Subtracts a G1 point from another.
 * @param a Minuend.
 * @param b Subtrahend.
 * @return Difference in G1.
 */
inline ECP Sub(ECP a, ECP b) { ECP_sub(&a, &b); return a; }
/**
 * @brief Compares two G1 points.
 * @param a First G1 point.
 * @param b Second G1 point.
 * @return True if both points are equal.
 */
inline bool Equal(ECP a, ECP b) { return ECP_equals(&a, &b); }
/**
 * @brief Checks membership in G1 and excludes the identity.
 * @param a Candidate point.
 * @return True for a nonidentity G1 point.
 */
inline bool Valid(ECP a) { return !ECP_isinf(&a) && PAIR_G1member(&a); }
/**
 * @brief Checks membership in G2 and excludes the identity.
 * @param a Candidate point.
 * @return True for a nonidentity G2 point.
 */
inline bool Valid(ECP2 a) { return !ECP2_isinf(&a) && PAIR_G2member(&a); }

/**
 * @brief Encodes a G2 point for the comparison transcripts.
 * @param point G2 point, possibly the identity.
 * @return 97-byte encoding with all zeros for the identity.
 */
inline std::string PointBytes(ECP2 point) {
    std::array<char, 193> buffer{};
    if (ECP2_isinf(&point)) return std::string(97, '\0');
    octet output{0, static_cast<int>(buffer.size()), buffer.data()};
    ECP2_toOctet(&output, &point, true);
    if (output.len != 97) throw std::runtime_error("Unexpected MIRACL compressed G2 width");
    return {output.val, static_cast<std::size_t>(output.len)};
}

// Discrete-log key pair in G1.
struct Key {
    mpz_class secret; ///< Nonzero scalar in Z_q.
    ECP publicKey;    ///< Corresponding G1 public point.
};

/**
 * @brief Generates a scalar and its G1 public point.
 * @return Fresh discrete-log key pair.
 */
inline Key KeyGen() {
    auto secret = Sample(true);
    return {secret, Mul(G1(), secret)};
}

} // namespace ComparisonCurve
