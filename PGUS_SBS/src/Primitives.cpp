/**
 * @file PGUS_SBS/src/Primitives.cpp
 * @brief BLS12-381 transcript hashing and pairing comparisons.
 * @details Uses SHA-256 XMD expansion, curve maps, subgroup clearing, and a shared Miller product.
 */
#include "Primitives.h"

namespace PGUS_SBS {
using namespace ComparisonCurve;
namespace {

/**
 * @brief Expands a domain-separated transcript.
 * 1. uniform = expand_message_xmd(SHA-256, message, domain, length).
 */
std::string Expand(std::string_view domain, std::string& message, int length) {
    std::string dst(domain);
    std::string bytes(length, '\0');
    octet d{static_cast<int>(dst.size()), static_cast<int>(dst.size()), dst.data()};
    octet m{static_cast<int>(message.size()), static_cast<int>(message.size()), message.data()};
    octet out{0, length, bytes.data()};
    // 1. uniform = expand_message_xmd(SHA-256, message, domain, length).
    XMD_Expand(MC_SHA2, 32, &out, length, &d, &m);
    return bytes;
}

/**
 * @brief Reduces a wide integer to the BLS12-381 base field.
 * 1. u = OS2IP(wide) mod p, where p is the base-field modulus.
 * 2. Encode u in 48 bytes for base-field conversion.
 * 3. Convert u to the field implementation representation.
 */
FP ToField(std::string_view wide) {
    static const auto modulus = [] {
        BIG value;
        BIG_rcopy(value, Modulus);
        return BIG_to_mpz(value);
    }();
    // 1. u = OS2IP(wide) mod p, where p is the base-field modulus.
    const mpz_class reduced = Integer(wide) % modulus;
    BIG scalar;
    // 2. Encode u in 48 bytes for base-field conversion.
    std::array<char, MODBYTES_B384_58> bytes{};
    if (reduced != 0) {
        const auto length = (mpz_sizeinbase(reduced.get_mpz_t(), 2) + 7) / 8;
        mpz_export(bytes.data() + bytes.size() - length, nullptr, 1, 1, 0, 0, reduced.get_mpz_t());
    }
    BIG_fromBytesLen(scalar, bytes.data(), bytes.size());
    FP field;
    // 3. Convert u to the field implementation representation.
    FP_nres(&field, scalar);
    return field;
}

} // namespace

/**
 * @brief Hashes a transcript to G1.
 * 1. Expand 128 bytes and reduce two 64-byte chunks to u0, u1 in F_p.
 * 2. P = MapG1(u0) + MapG1(u1).
 * 3. Return ClearCofactorG1(P).
 */
ECP HashG1(std::string_view domain, std::string message) {
    // 1. Expand 128 bytes and reduce two 64-byte chunks to u0, u1 in F_p.
    const auto uniform = Expand(domain, message, 128);
    auto first = ToField(std::string_view(uniform).substr(0, 64));
    auto second = ToField(std::string_view(uniform).substr(64, 64));
    ECP p, q;
    // 2. P = MapG1(u0) + MapG1(u1).
    ECP_map2point(&p, &first);
    ECP_map2point(&q, &second);
    ECP_add(&p, &q);
    // 3. Return ClearCofactorG1(P).
    ECP_cfp(&p);
    return p;
}

/**
 * @brief Hashes a transcript to G2.
 * 1. Expand 256 bytes and reduce four 64-byte chunks to a, b, c, d in F_p.
 * 2. x = a + b*i and y = c + d*i in F_p^2.
 * 3. P = MapG2(x) + MapG2(y).
 * 4. Return ClearCofactorG2(P).
 */
ECP2 HashG2(std::string_view domain, std::string message) {
    // 1. Expand 256 bytes and reduce four 64-byte chunks to a, b, c, d in F_p.
    const auto uniform = Expand(domain, message, 256);
    const std::string_view bytes(uniform);
    auto a = ToField(bytes.substr(0, 64));
    auto b = ToField(bytes.substr(64, 64));
    auto c = ToField(bytes.substr(128, 64));
    auto d = ToField(bytes.substr(192, 64));
    FP2 x, y;
    // 2. x = a + b*i and y = c + d*i in F_p^2.
    FP2_from_FPs(&x, &a, &b);
    FP2_from_FPs(&y, &c, &d);
    ECP2 p, q;
    // 3. P = MapG2(x) + MapG2(y).
    ECP2_map2point(&p, &x);
    ECP2_map2point(&q, &y);
    ECP2_add(&p, &q);
    // 4. Return ClearCofactorG2(P).
    ECP2_cfp(&p);
    return p;
}

/**
 * @brief Checks equality of pairing products.
 * 1. Use the identity rule e(0, Q) = e(P, 0) = 1 and inversion rule e(-P, Q) = e(P, Q)^(-1).
 * 2. Accumulate the Miller factors for left-hand pairs and inverses of right-hand pairs.
 * 3. Accept iff FinalExp(MillerProduct) = 1.
 */
bool PairEqual(std::initializer_list<std::pair<ECP, ECP2>> left,
               const std::vector<std::pair<ECP, ECP2>>& right) {
    FP12 terms[ATE_BITS_BLS12381];
    PAIR_initmp(terms);
    // 1. Use the identity rule e(0, Q) = e(P, 0) = 1 and inversion rule e(-P, Q) = e(P, Q)^(-1).
    const auto add = [&](ECP p, ECP2 q, bool inverse) {
        if (ECP_isinf(&p) || ECP2_isinf(&q)) return;
        if (inverse) ECP_neg(&p);
        PAIR_another(terms, &q, &p);
    };
    // 2. Accumulate the Miller factors for left-hand pairs and inverses of right-hand pairs.
    for (const auto& [p, q] : left) add(p, q, false);
    for (const auto& [p, q] : right) add(p, q, true);
    FP12 product;
    // 3. Accept iff FinalExp(MillerProduct) = 1.
    PAIR_miller(&product, terms);
    PAIR_fexp(&product);
    return FP12_isunity(&product);
}

} // namespace PGUS_SBS
