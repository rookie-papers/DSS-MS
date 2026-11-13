/**
 * @file ECMSS/include/ECMSS.h
 * @brief ECMSS signing, aggregation, and subset sanitization interfaces.
 * @details Defines the inputs and outputs of the single-hop benchmark.
 */
#pragma once

#include "ComparisonCurve.h"

namespace ECMSS {

// Ordered unsigned 20-bit message cells.
using Cells = std::vector<std::uint32_t>;
// Shared BLS12-381 scalar and public point.
using ComparisonCurve::Key;
// Shared generator for signer and sanitization key pairs.
using ComparisonCurve::KeyGen;

// Shared initial sanitization parameters for one batch.
struct Batch {
    mpz_class r0; ///< Batch signing scalar r0.
    ECP K0;       ///< Initial sanitization public key K0.
};

// Signed contribution from one data source.
struct Record {
    std::uint32_t groupId, ///< Aggregation group identifier.
    sourceId;              ///< Data source identifier.
    Cells cells;                     ///< Ordered cells contributed by the source.
    ECP sourceKey, ///< Data source public key S_h.
    signature;     ///< Source signature sigma_h.
    mpz_class rh;                    ///< Source opening rh.
};

// Ordered batch and auxiliary values for one-hop verification.
struct AggregateResult {
    std::vector<Cells> messages; ///< Source messages in canonical order.
    ECP sourceSum, ///< Aggregate public key S.
    signature;     ///< Aggregate signature sigma_agg.
    mpz_class hashSum, ///< Aggregate cell hash H_agg.
    opening;           ///< Aggregate opening R0.
};

/**
 * @brief Hashes an ordered cell sequence to a subgroup scalar.
 * @param cells Cell sequence.
 * @return Reduced scalar hash.
 */
mpz_class HashCells(const Cells& cells);
/**
 * @brief Signs one data source contribution.
 * @param cells Source message.
 * @param signer Source private key.
 * @param rh Source opening.
 * @param batch Shared batch parameters.
 * @return Source signature point.
 */
ECP Sign(const Cells& cells, const mpz_class& signer, const mpz_class& rh, const Batch& batch);
/**
 * @brief Aggregates distinct source records in canonical order.
 * @param records Nonempty batch with distinct group and source pairs.
 * @return Ordered messages and aggregate values.
 */
AggregateResult Aggregate(std::vector<Record> records);
/**
 * @brief Verifies an aggregate against its ordered source messages.
 * @param aggregate Aggregate and its auxiliary values.
 * @param batch Initial batch parameters.
 * @return True if the one-hop verification equation holds.
 */
bool VerifyOneHop(const AggregateResult& aggregate, const Batch& batch);
/**
 * @brief Computes an elliptic-curve chameleon hash.
 * @param value Message representative.
 * @param opening Scalar opening.
 * @param key Sanitization public key.
 * @return Chameleon hash point.
 */
ECP ECCH(const mpz_class& value, const mpz_class& opening, ECP key);
/**
 * @brief Reopens a local subset under a new sanitization key.
 * @param localSubset Cells processed at this hop.
 * @param attribute Scalar representative of the replacement attribute.
 * @param oldOpening Prior scalar opening.
 * @param oldKey Prior private sanitization key.
 * @param newKey Nonzero new private sanitization key.
 * @return Replacement opening.
 */
mpz_class SubSanit(const Cells& localSubset, const mpz_class& attribute, const mpz_class& oldOpening,
                  const mpz_class& oldKey, const mpz_class& newKey);

} // namespace ECMSS
