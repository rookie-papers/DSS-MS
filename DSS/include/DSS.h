#ifndef DSS_MS_DSS_H
#define DSS_MS_DSS_H

#include "Tools.h"

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string_view>

namespace DSS {

using Id = std::uint64_t;
using SystemId = std::array<unsigned char, 16>;
using Secret = std::array<unsigned char, 32>;

struct Params { mpz_class q; ECP P; };
struct KeyPair { mpz_class sk; ECP pk; };
struct Member { Id id; mpz_class modulus; Secret key; };
struct PublicMember { Id id; mpz_class modulus; };

struct Manifest {
    SystemId system;
    std::uint64_t epoch;
    Secret nonce;
    std::vector<PublicMember> members;
    std::optional<ECP> sanitizer;
    mpz_class sx;
    ECP commitment;
    mpz_class response;
};

class AcceptedEpoch {
public:
    const Manifest& manifest() const { return manifest_; }
    const Secret& contextDigest() const { return digest_; }

private:
    AcceptedEpoch(Manifest manifest, Secret digest)
        : manifest_(std::move(manifest)), digest_(digest) {}
    Manifest manifest_;
    Secret digest_;

    friend std::optional<AcceptedEpoch> AcceptEpoch(const Params&, const SystemId&,
        ECP, std::string_view, std::uint64_t);
};

struct Message {
    SystemId system;
    std::uint64_t epoch;
    Id order;
    std::string immutable;
    std::vector<bool> editable;
    std::vector<std::string> blocks;
};

struct Signature { ECP R; mpz_class z, s; ECP T; };
struct SignedOrder { Message message; Signature signature; };
struct Original { SignedOrder order; mpz_class randomness; };
struct Evidence { SignedOrder original, disputed; ECP U; mpz_class v; };
struct AuditEvent { Id member, order; std::uint64_t epoch; Secret outputDigest; };
using AuditSink = std::function<void(const AuditEvent&)>;

Params Setup();
KeyPair KGen(const Params& pp);
SystemId NewSystemId();

class Authority {
public:
    explicit Authority(const Params& pp, std::size_t memberCount);
    const SystemId& system() const { return system_; }
    ECP verificationKey() const { return auth_.pk; }
    const Member& member(Id id) const { return active_.at(id); }
    Manifest Publish();
    Manifest Join(std::size_t count);
    Manifest Revoke(const std::vector<Id>& ids);

private:
    using Members = std::map<Id, Member>;
    void addMembers(Members& target, std::set<mpz_class>& used, Id& nextId, std::size_t count) const;
    Manifest EpochGen(const Members& members) const;

    Params pp_;
    SystemId system_;
    KeyPair auth_;
    Members active_;
    std::set<mpz_class> usedModuli_;
    std::uint64_t epoch_ = 0;
    Id nextId_ = 1;
};

std::string EncodeContext(const Manifest& manifest);
std::string EncodeManifest(const Manifest& manifest);
std::string EncodePoint(ECP point);
std::optional<ECP> DecodePublicKey(std::string_view bytes);
std::string EncodeSignature(const Signature& signature);
std::string EncodeOrder(const SignedOrder& order);
std::optional<SignedOrder> DecodeOrder(const Params& pp, std::string_view bytes);
std::string EncodeEvidence(const Evidence& evidence);
std::size_t BitLength(const mpz_class& value);
std::optional<AcceptedEpoch> AcceptEpoch(const Params& pp, const SystemId& system,
    ECP verificationKey, std::string_view wire, std::uint64_t minimumEpoch);
std::optional<mpz_class> Recover(const Params& pp, const Member& member, const AcceptedEpoch& epoch);
bool MatchesSanitizerKey(const Params& pp, const AcceptedEpoch& epoch, const mpz_class& candidate);
std::optional<Original> Sign(const Params& pp, const Message& message, const KeyPair& signer,
    const AcceptedEpoch& epoch, std::uint64_t minimumEpoch);
bool Verify(const Params& pp, const SignedOrder& order, ECP signer, const AcceptedEpoch& epoch,
    std::uint64_t minimumEpoch);
std::optional<SignedOrder> Sanitizing(const Params& pp, const SignedOrder& original,
    const std::vector<std::string>& replacement, const Member& member, ECP signer,
    const AcceptedEpoch& epoch, std::uint64_t minimumEpoch, const AuditSink& audit = {});
std::optional<Evidence> Proof(const Params& pp, const Original& original,
    const SignedOrder& disputed, ECP signer, const AcceptedEpoch& epoch);
bool Judge(const Params& pp, const Evidence& evidence, ECP signer, const AcceptedEpoch& epoch);

} // namespace DSS

#endif
