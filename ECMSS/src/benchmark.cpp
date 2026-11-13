/**
 * @file ECMSS/src/benchmark.cpp
 * @brief ECMSS single-hop benchmark fixtures.
 * @details Measures signing, aggregation, verification, and a single subset re-keying operation.
 */
#include "ECMSS.h"
#include "measure.h"

namespace Experiment {
namespace {

/**
 * @brief Packs benchmark payload bytes into ordered 20-bit cells.
 * 1. Read successive 20-bit words from the payload in big-endian bit order.
 * 2. Right-pad the final partial word with zeros.
 */
ECMSS::Cells Pack(std::string_view payload) {
    ECMSS::Cells cells;
    std::uint32_t pending = 0;
    unsigned bits = 0;
    // 1. Read successive 20-bit words from the payload in big-endian bit order.
    for (unsigned char byte : payload) {
        pending = (pending << 8) | byte;
        bits += 8;
        if (bits >= 20) {
            bits -= 20;
            cells.push_back((pending >> bits) & ((1u << 20) - 1));
        }
    }
    // 2. Right-pad the final partial word with zeros.
    if (bits) cells.push_back((pending << (20 - bits)) & ((1u << 20) - 1));
    return cells;
}

} // namespace

/**
 * @brief Checks ECMSS equations and records the one-hop measurements.
 * 1. Prepare one-source and two-source signatures under the same batch key.
 * 2. Verify the aggregate equations and check the canonical source order.
 * 3. Check that the same signature fails after a message change.
 * 4. Check ECCH(H(local), R0, K0) = ECCH(attribute, R_next, K_next).
 * 5. Measure Sign, Aggregate, Verify, and SubSanit and record the aggregate point size.
 */
void BenchEcmss(Csv* csv, const std::string& id, int repeats, int iterations) {
    using namespace ECMSS;
    using namespace ComparisonCurve;
    // 1. Prepare one-source and two-source signatures under the same batch key.
    const auto batchKey = KeyGen(), signer = KeyGen(), other = KeyGen(), next = KeyGen();
    const Batch batch{batchKey.secret, batchKey.publicKey};
    const auto rh = ComparisonCurve::Sample(true), rh2 = ComparisonCurve::Sample(true);
    const auto a = std::string(128, 'a'), b = std::string(128, 'b');
    const auto full = Pack(a + b), local = Pack(a), second = Pack(b);
    const auto attribute = ComparisonCurve::Sample(true);
    const Record one{1, 1, full, signer.publicKey, Sign(full, signer.secret, rh, batch), rh};
    const std::vector<Record> records{
        {1, 2, second, other.publicKey, Sign(second, other.secret, rh2, batch), rh2},
        {1, 1, local, signer.publicKey, Sign(local, signer.secret, rh, batch), rh}};
    // 2. Verify the aggregate equations and check the canonical source order.
    const auto single = Aggregate({one});
    const auto aggregated = Aggregate(records);
    Require(VerifyOneHop(single, batch) && VerifyOneHop(aggregated, batch), "ECMSS one-hop verification failed");
    Require(aggregated.messages == std::vector<Cells>{local, second}, "ECMSS source order mismatch");
    // 3. Check that the same signature fails after a message change.
    auto bad = single;
    bad.messages[0][0] ^= 1;
    Require(!VerifyOneHop(bad, batch), "ECMSS accepted a changed message with the same signature");
    // 4. Check ECCH(H(local), R0, K0) = ECCH(attribute, R_next, K_next).
    const auto opening = SubSanit(local, attribute, single.opening, batchKey.secret, next.secret);
    Require(Equal(ECCH(HashCells(local), single.opening, batchKey.publicKey),
                  ECCH(attribute, opening, next.publicKey)), "ECMSS reopening mismatch");
    if (!csv) return;
    // 5. Measure Sign, Aggregate, Verify, and SubSanit and record the aggregate point size.
    BaselineRows out(*csv, id, "ECMSS", "1");
    out.Timing("Sign", Measure(repeats, iterations, [&] { return Sign(full, signer.secret, rh, batch); }),
        "one data source; 256 payload bytes packed into 103 20-bit cells; batch and opening prepared");
    out.Timing("Aggregate", Measure(repeats, iterations, [&] { return records; },
        [](auto& input) { return Aggregate(std::move(input)); }),
        "two data sources with 128 payload bytes each; prepared signatures and openings");
    out.Timing("Verify", Measure(repeats, iterations, [&] { return VerifyOneHop(single, batch); }),
        "one data source; single-hop equation; rehashes the 256-byte payload");
    out.Timing("SubSanit", Measure(repeats, iterations, [&] {
        return SubSanit(local, attribute, single.opening, batchKey.secret, next.secret);
    }), "one step; 128 of 256 payload bytes in local subset; attribute scalar and prior state prepared");
    out.Signature(DSS::EncodePoint(aggregated.signature).size(),
        "bare aggregate G1 point; verification context and scalar opening excluded");
}
} // namespace Experiment
