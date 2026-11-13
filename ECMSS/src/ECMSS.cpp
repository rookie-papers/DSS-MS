/**
 * @file ECMSS/src/ECMSS.cpp
 * @brief ECMSS signing, aggregation, and one-hop verification.
 * @details Implements the journal construction and the subset re-keying equation.
 */
#include "ECMSS.h"

#include <algorithm>
#include <tuple>

namespace ECMSS {
using namespace ComparisonCurve;

/**
 * @brief Encodes and hashes the source cells.
 * 1. B = BE32(number of cells) || Pack20(cells).
 * 2. h = HashZp256(B, q) using the wrapper padding convention.
 */
mpz_class HashCells(const Cells& cells) {
    // 1. B = BE32(number of cells) || Pack20(cells).
    if (cells.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::length_error("ECMSS cell count exceeds uint32");
    std::string encoded;
    Number(encoded, cells.size(), 4);
    std::uint32_t pending = 0;
    unsigned bits = 0;
    for (const auto cell : cells) {
        if (cell >= (1u << 20)) throw std::invalid_argument("ECMSS cell exceeds 20 bits");
        pending = (pending << 20) | cell;
        bits += 20;
        while (bits >= 8) {
            bits -= 8;
            encoded.push_back(static_cast<char>(pending >> bits));
        }
    }
    if (bits != 0) encoded.push_back(static_cast<char>(pending << (8 - bits)));
    // Match the wrapper hash for short inputs without its temporary string limit.
    // 2. h = HashZp256(B, q) using the wrapper padding convention.
    if (encoded.size() > std::numeric_limits<int>::max())
        throw std::length_error("ECMSS encoded input exceeds the hash interface");
    const auto length = static_cast<int>(encoded.size());
    encoded.resize(std::max<std::size_t>(8192, encoded.size()), '\0');
    octet input{length, static_cast<int>(encoded.size()), encoded.data()};
    BIG order, result;
    BIG_rcopy(order, CURVE_Order);
    hashZp256(result, &input, order);
    return BIG_to_mpz(result);
}

/**
 * @brief Computes the ECMSS source signature.
 * The source scalar s_h is signer and the opening r_h is rh. See Eq. (7).
 * 1. sigma_h = (H(x_h) + s_h * r0) * G + r_h * K0.
 */
ECP Sign(const Cells& cells, const mpz_class& signer, const mpz_class& rh, const Batch& batch) {
    // 1. sigma_h = (H(x_h) + s_h * r0) * G + r_h * K0.
    return Add(Mul(G1(), Mod(HashCells(cells) + signer * batch.r0)), Mul(batch.K0, rh));
}

/**
 * @brief Combines source records into a batch.
 * See Eq. (8) for signature aggregation.
 * 1. Order records by (groupId, sourceId) and require each pair to be distinct.
 * 2. S = sum_h S_h, sigma_agg = sum_h sigma_h, H_agg = sum_h H(x_h), R0 = sum_h r_h.
 * 3. H_agg = H_agg mod q and R0 = R0 mod q.
 */
AggregateResult Aggregate(std::vector<Record> records) {
    // 1. Order records by (groupId, sourceId) and require each pair to be distinct.
    if (records.empty()) throw std::invalid_argument("Empty ECMSS batch");
    const auto id = [](const Record& record) { return std::tie(record.groupId, record.sourceId); };
    std::sort(records.begin(), records.end(), [&](const auto& a, const auto& b) { return id(a) < id(b); });
    AggregateResult result;
    ECP_inf(&result.sourceSum);
    ECP_inf(&result.signature);
    result.messages.reserve(records.size());
    for (std::size_t i = 0; i < records.size(); ++i) {
        auto& record = records[i];
        if (i && id(records[i - 1]) == id(record))
            throw std::invalid_argument("Duplicate ECMSS source");
        // 2. S = sum_h S_h, sigma_agg = sum_h sigma_h, H_agg = sum_h H(x_h), R0 = sum_h r_h.
        result.sourceSum = Add(result.sourceSum, record.sourceKey);
        result.signature = Add(result.signature, record.signature);
        result.hashSum += HashCells(record.cells);
        result.opening += record.rh;
        result.messages.push_back(std::move(record.cells));
    }
    // 3. H_agg = H_agg mod q and R0 = R0 mod q.
    result.hashSum = Mod(result.hashSum);
    result.opening = Mod(result.opening);
    return result;
}

/**
 * @brief Verifies the aggregate signature at the initial sanitization key.
 * The R0 term in Eq. (12) uses the point K0 as required by the signature equation.
 * 1. H_agg = sum_h H(x_h).
 * 2. V = (H_agg mod q) * G + R0 * K0 + r0 * S.
 * 3. Accept iff V = sigma_agg.
 */
bool VerifyOneHop(const AggregateResult& aggregate, const Batch& batch) {
    if (aggregate.messages.empty()) return false;
    // 1. H_agg = sum_h H(x_h).
    mpz_class hashSum = 0;
    for (const auto& cells : aggregate.messages) hashSum += HashCells(cells);
    // 2. V = (H_agg mod q) * G + R0 * K0 + r0 * S.
    const auto expected = Add(Add(Mul(G1(), Mod(hashSum)), Mul(batch.K0, aggregate.opening)),
                              Mul(aggregate.sourceSum, batch.r0));
    // 3. Accept iff V = sigma_agg.
    return Equal(expected, aggregate.signature);
}

/**
 * @brief Computes the elliptic-curve chameleon hash.
 * 1. ECCH(m, r, K) = m * G + r * K.
 */
ECP ECCH(const mpz_class& value, const mpz_class& opening, ECP key) {
    // 1. ECCH(m, r, K) = m * G + r * K.
    return Add(Mul(G1(), value), Mul(key, opening));
}

/**
 * @brief Reopens a subset under the next hop key.
 * In Eq. (9), localSubset is x_j, oldOpening is R_prev, and oldKey and newKey are k_prev and k_j.
 * 1. R_j = (H(x_j) - attribute + R_prev * k_prev) * inverse(k_j) mod q.
 */
mpz_class SubSanit(const Cells& localSubset, const mpz_class& attribute, const mpz_class& oldOpening,
                  const mpz_class& oldKey, const mpz_class& newKey) {
    // 1. R_j = (H(x_j) - attribute + R_prev * k_prev) * inverse(k_j) mod q.
    return Mod((HashCells(localSubset) - attribute + oldOpening * oldKey) * Inv(newKey));
}

} // namespace ECMSS
