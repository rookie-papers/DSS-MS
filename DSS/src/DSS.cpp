#include "DSS.h"

#include <algorithm>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace DSS {
namespace {

constexpr std::uint32_t VERSION = 1;
constexpr std::size_t POINT_BYTES = 49;
constexpr std::size_t SCALAR_BYTES = 32;
constexpr std::size_t MEMBER_BYTES = 40;

mpz_class Integer(std::string_view bytes) {
    mpz_class value;
    mpz_import(value.get_mpz_t(), bytes.size(), 1, 1, 0, 0, bytes.data());
    return value;
}

void PutNumber(std::string& output, std::uint64_t value, unsigned int width) {
    for (unsigned int index = width; index != 0; --index)
        output.push_back(static_cast<char>(value >> (8 * (index - 1))));
}

void PutCount(std::string& output, std::size_t count) {
    if (count > std::numeric_limits<std::uint32_t>::max())
        throw std::length_error("DSS encoding exceeds the uint32 length field");
    PutNumber(output, count, 4);
}

void PutField(std::string& output, std::string_view bytes) {
    PutCount(output, bytes.size());
    output.append(bytes);
}

template <std::size_t Size>
std::string_view Bytes(const std::array<unsigned char, Size>& bytes) {
    return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

std::string EncodeInteger(const mpz_class& value, std::size_t width) {
    const std::size_t length = (BitLength(value) + 7) / 8;
    if (value < 0 || length > width)
        throw std::invalid_argument("DSS integer does not fit its encoding");
    std::string bytes(width, '\0');
    if (length != 0)
        mpz_export(bytes.data() + width - length, nullptr, 1, 1, 0, 0, value.get_mpz_t());
    return bytes;
}

class Reader {
public:
    explicit Reader(std::string_view data) : remaining_(data) {}
    std::size_t size() const { return remaining_.size(); }
    std::string_view Take(std::size_t count) {
        if (count > size()) throw std::invalid_argument("Truncated DSS encoding");
        const auto bytes = remaining_.substr(0, count);
        remaining_.remove_prefix(count);
        return bytes;
    }
    std::uint64_t Number(std::size_t width) {
        std::uint64_t value = 0;
        for (unsigned char byte : Take(width)) value = (value << 8) | byte;
        return value;
    }
    std::string_view Field() { return Take(Number(4)); }
    template <std::size_t Size>
    std::array<unsigned char, Size> Array() {
        std::array<unsigned char, Size> output;
        const auto bytes = Take(Size);
        std::copy(bytes.begin(), bytes.end(), output.begin());
        return output;
    }

private:
    std::string_view remaining_;
};

template <std::size_t Size>
std::array<unsigned char, Size> RandomBytes() {
    thread_local std::ifstream random("/dev/urandom", std::ios::binary);
    std::array<unsigned char, Size> result;
    if (!random.read(reinterpret_cast<char*>(result.data()), result.size()))
        throw std::runtime_error("Cannot read the OS random source");
    return result;
}

mpz_class RandomScalar(const Params& pp, bool nonzero = false) {
    for (;;) {
        auto value = Integer(Bytes(RandomBytes<SCALAR_BYTES>()));
        if (value < pp.q && (!nonzero || value != 0)) return value;
    }
}

mpz_class Mod(const mpz_class& value, const mpz_class& modulus) {
    mpz_class result;
    mpz_mod(result.get_mpz_t(), value.get_mpz_t(), modulus.get_mpz_t());
    return result;
}

ECP Mul(ECP point, const mpz_class& scalar) {
    ECP_mul(point, scalar);
    return point;
}

void Add(ECP& left, ECP right) { ECP_add(&left, &right); }

bool Equal(ECP left, ECP right) { return ECP_equals(&left, &right) != 0; }

bool ValidPoint(ECP point, bool allowIdentity) {
    return ECP_isinf(&point) ? allowIdentity : PAIR_G1member(&point) != 0;
}

ECP ReadPoint(Reader& reader, bool allowIdentity) {
    const auto encoded = reader.Take(POINT_BYTES);
    ECP point;
    if (encoded.find_first_not_of('\0') == std::string_view::npos) {
        if (!allowIdentity) throw std::invalid_argument("Identity public key");
        ECP_inf(&point);
        return point;
    }
    std::string bytes(encoded);
    octet input{static_cast<int>(bytes.size()), static_cast<int>(bytes.size()), bytes.data()};
    if (!ECP_fromOctet(&point, &input) || !ValidPoint(point, false) || EncodePoint(point) != encoded)
        throw std::invalid_argument("Invalid or noncanonical DSS point");
    return point;
}

Secret Digest(std::string_view data) {
    hash256 hash;
    HASH256_init(&hash);
    for (unsigned char byte : data) HASH256_process(&hash, byte);
    Secret result;
    HASH256_hash(&hash, reinterpret_cast<char*>(result.data()));
    return result;
}

mpz_class HashScalar(const Params& pp, std::string_view domain,
    std::initializer_list<std::string_view> fields) {
    hash512 hash;
    HASH512_init(&hash);
    std::string header;
    PutField(header, domain);
    for (unsigned char byte : header) HASH512_process(&hash, byte);
    for (auto field : fields) {
        header.clear();
        PutCount(header, field.size());
        for (unsigned char byte : header) HASH512_process(&hash, byte);
        for (unsigned char byte : field) HASH512_process(&hash, byte);
    }
    std::array<unsigned char, 64> output;
    HASH512_hash(&hash, reinterpret_cast<char*>(output.data()));
    return Mod(Integer(Bytes(output)), pp.q);
}

mpz_class Mask(const Member& member, const Secret& digest) {
    std::string input;
    PutField(input, "DSS-MS/mask/v1");
    input.append(Bytes(digest));
    PutNumber(input, member.id, 8);
    const auto prefix = input.size();
    auto key = member.key;
    octet k{32, 32, reinterpret_cast<char*>(key.data())};
    for (std::uint64_t counter = 0; counter <= UINT32_MAX; ++counter) {
        input.resize(prefix);
        PutNumber(input, counter, 4);
        octet message{static_cast<int>(input.size()), static_cast<int>(input.size()), input.data()};
        Secret output;
        octet tag{0, 32, reinterpret_cast<char*>(output.data())};
        HMAC(MC_SHA2, 32, &tag, 32, &k, &message);
        const auto candidate = Integer(Bytes(output));
        if (candidate < member.modulus) return candidate;
    }
    throw std::runtime_error("PRF rejection counter exhausted");
}

std::string ManifestBody(const Manifest& manifest) {
    auto bytes = EncodeContext(manifest);
    if (manifest.sanitizer) {
        const auto width = std::max<std::size_t>(1, (BitLength(manifest.sx) + 7) / 8);
        PutField(bytes, EncodeInteger(manifest.sx, width));
    }
    return bytes;
}

// Balanced combination implements the same CRT residue as the summation formula.
struct Congruence { mpz_class residue, modulus; };

Congruence CombineCRT(std::vector<Congruence>& values, std::size_t first, std::size_t last) {
    if (last - first == 1) return std::move(values[first]);
    const auto middle = first + (last - first) / 2;
    const auto left = CombineCRT(values, first, middle);
    const auto right = CombineCRT(values, middle, last);
    mpz_class inverse;
    if (mpz_invert(inverse.get_mpz_t(), left.modulus.get_mpz_t(), right.modulus.get_mpz_t()) == 0)
        throw std::invalid_argument("Non-coprime DSS public moduli");
    return {left.residue + left.modulus * Mod((right.residue - left.residue) * inverse, right.modulus),
        left.modulus * right.modulus};
}

mpz_class CheckedProduct(const std::vector<PublicMember>& members, std::size_t first, std::size_t last) {
    if (last - first == 1) return members[first].modulus;
    const auto middle = first + (last - first) / 2;
    const auto left = CheckedProduct(members, first, middle);
    const auto right = CheckedProduct(members, middle, last);
    mpz_class divisor;
    mpz_gcd(divisor.get_mpz_t(), left.get_mpz_t(), right.get_mpz_t());
    if (divisor != 1) throw std::invalid_argument("Non-coprime DSS public moduli");
    return left * right;
}

bool ValidMessage(const Message& message) {
    return message.order != 0 && message.editable.size() == message.blocks.size();
}

bool Current(const Message& message, const AcceptedEpoch& epoch, std::uint64_t minimum) {
    const auto& manifest = epoch.manifest();
    return manifest.sanitizer.has_value() && ValidMessage(message) && message.system == manifest.system
        && message.epoch == manifest.epoch && message.epoch >= minimum;
}

std::string EncodeImmutable(const Message& message) {
    std::string output(Bytes(message.system));
    PutNumber(output, message.epoch, 8);
    PutNumber(output, message.order, 8);
    PutField(output, message.immutable);
    PutCount(output, message.editable.size());
    for (bool editable : message.editable) output.push_back(editable ? 1 : 0);
    return output;
}

std::string EncodeBlocks(const std::vector<std::string>& blocks) {
    std::string output;
    for (const auto& block : blocks) PutField(output, block);
    return output;
}

mpz_class Inner(const Params& pp, const Message& message, ECP T) {
    return HashScalar(pp, "DSS-MS/H0/v1",
        {EncodeImmutable(message), EncodeBlocks(message.blocks), EncodePoint(T)});
}

ECP Chameleon(const Params& pp, const SignedOrder& order, ECP sanitizer) {
    auto point = Mul(sanitizer, Inner(pp, order.message, order.signature.T));
    auto offset = Mul(pp.P, order.signature.s);
    ECP_add(&point, &offset);
    Add(point, order.signature.T);
    return point;
}

mpz_class Outer(const Params& pp, const Message& message, ECP R, ECP ch) {
    return HashScalar(pp, "DSS-MS/H1/v1", {EncodeImmutable(message), EncodePoint(R), EncodePoint(ch)});
}

bool SameDispute(const SignedOrder& original, const SignedOrder& disputed) {
    return EncodeImmutable(original.message) == EncodeImmutable(disputed.message)
        && original.message.blocks != disputed.message.blocks
        && Equal(original.signature.R, disputed.signature.R) && original.signature.z == disputed.signature.z;
}

mpz_class ProofChallenge(const Params& pp, const AcceptedEpoch& epoch, ECP signer, const Evidence& evidence) {
    return HashScalar(pp, "DSS-MS/H2/v1", {EncodeContext(epoch.manifest()), EncodePoint(signer),
        EncodeOrder(evidence.original), EncodeOrder(evidence.disputed), EncodePoint(evidence.U)});
}

bool Scalar(const Params& pp, const mpz_class& value) { return value >= 0 && value < pp.q; }

std::optional<ECP> VerifiedCommitment(const Params& pp, const SignedOrder& order, ECP signer,
    const AcceptedEpoch& epoch, std::uint64_t minimumEpoch) {
    const auto& sig = order.signature;
    if (!Current(order.message, epoch, minimumEpoch) || !Scalar(pp, sig.z) || !Scalar(pp, sig.s)
        || !ValidPoint(signer, false) || !ValidPoint(sig.R, true) || !ValidPoint(sig.T, true)) return std::nullopt;
    const auto ch = Chameleon(pp, order, *epoch.manifest().sanitizer);
    auto expected = Mul(signer, Outer(pp, order.message, sig.R, ch));
    Add(expected, sig.R);
    if (!Equal(Mul(pp.P, sig.z), expected)) return std::nullopt;
    return ch;
}

} // namespace

std::size_t BitLength(const mpz_class& value) {
    return value == 0 ? 0 : mpz_sizeinbase(value.get_mpz_t(), 2);
}

Params Setup() {
    Params pp;
    pp.q = getCurveOrder();
    ECP_generator(&pp.P);
    return pp;
}

KeyPair KGen(const Params& pp) {
    const auto sk = RandomScalar(pp, true);
    return {sk, Mul(pp.P, sk)};
}

SystemId NewSystemId() { return RandomBytes<16>(); }

Authority::Authority(const Params& pp, std::size_t memberCount)
    : pp_(pp), system_(NewSystemId()), auth_(KGen(pp)) {
    addMembers(active_, usedModuli_, nextId_, memberCount);
}

void Authority::addMembers(Members& target, std::set<mpz_class>& used, Id& nextId, std::size_t count) const {
    for (std::size_t index = 0; index < count; ++index) {
        mpz_class prime;
        do {
            auto bytes = RandomBytes<32>();
            bytes.front() |= 0x80;
            const auto start = Integer(Bytes(bytes));
            mpz_nextprime(prime.get_mpz_t(), start.get_mpz_t());
        } while (BitLength(prime) != 256 || prime <= pp_.q || !used.insert(prime).second);
        if (nextId == std::numeric_limits<Id>::max()) throw std::overflow_error("DSS member IDs exhausted");
        const auto id = nextId++;
        target.emplace(id, Member{id, prime, RandomBytes<32>()});
    }
}

Manifest Authority::EpochGen(const Members& members) const {
    if (epoch_ == UINT64_MAX) throw std::overflow_error("DSS epochs exhausted");
    Manifest manifest{};
    manifest.system = system_;
    manifest.epoch = epoch_ + 1;
    manifest.nonce = RandomBytes<32>();
    if (!members.empty()) {
        auto trapdoor = KGen(pp_);
        manifest.sanitizer.emplace();
        ECP_copy(&*manifest.sanitizer, &trapdoor.pk);
        manifest.members.reserve(members.size());
        for (const auto& entry : members)
            manifest.members.push_back({entry.first, entry.second.modulus});
        const auto digest = Digest(EncodeContext(manifest));
        std::vector<Congruence> values;
        values.reserve(members.size());
        for (const auto& entry : members) {
            const auto& member = entry.second;
            values.push_back({Mod(trapdoor.sk + Mask(member, digest), member.modulus), member.modulus});
        }
        manifest.sx = CombineCRT(values, 0, values.size()).residue;
    }
    auto nonce = KGen(pp_);
    ECP_copy(&manifest.commitment, &nonce.pk);
    const auto challenge = HashScalar(pp_, "DSS-MS/auth/v1",
        {EncodePoint(auth_.pk), EncodePoint(nonce.pk), ManifestBody(manifest)});
    manifest.response = Mod(nonce.sk + challenge * auth_.sk, pp_.q);
    return manifest;
}

Manifest Authority::Publish() {
    if (epoch_ != 0) throw std::logic_error("DSS initial epoch already published");
    auto manifest = EpochGen(active_);
    epoch_ = manifest.epoch;
    return manifest;
}

Manifest Authority::Join(std::size_t count) {
    if (epoch_ == 0 || count == 0) throw std::invalid_argument("Join needs a published epoch and new members");
    auto next = active_;
    auto used = usedModuli_;
    auto id = nextId_;
    addMembers(next, used, id, count);
    auto manifest = EpochGen(next);
    active_.swap(next);
    usedModuli_.swap(used);
    nextId_ = id;
    epoch_ = manifest.epoch;
    return manifest;
}

Manifest Authority::Revoke(const std::vector<Id>& ids) {
    if (epoch_ == 0 || ids.empty()) throw std::invalid_argument("Revoke needs a published epoch and member IDs");
    auto next = active_;
    for (Id id : ids)
        if (next.erase(id) == 0) throw std::invalid_argument("Unknown or repeated revoked member");
    auto manifest = EpochGen(next);
    active_.swap(next);
    epoch_ = manifest.epoch;
    return manifest;
}

std::string EncodePoint(ECP point) {
    if (ECP_isinf(&point)) return std::string(POINT_BYTES, '\0');
    std::array<char, 2 * POINT_BYTES> buffer;
    octet encoded{0, static_cast<int>(buffer.size()), buffer.data()};
    ECP_toOctet(&encoded, &point, true);
    if (encoded.len != POINT_BYTES) throw std::runtime_error("Unexpected MIRACL compressed G1 width");
    return {encoded.val, static_cast<std::size_t>(encoded.len)};
}

std::optional<ECP> DecodePublicKey(std::string_view bytes) {
    if (bytes.size() != POINT_BYTES) return std::nullopt;
    try {
        Reader reader(bytes);
        return ReadPoint(reader, false);
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}

std::string EncodeContext(const Manifest& manifest) {
    std::string output;
    PutNumber(output, VERSION, 4);
    output.append(Bytes(manifest.system));
    PutNumber(output, manifest.epoch, 8);
    output.append(Bytes(manifest.nonce));
    output.push_back(manifest.sanitizer ? 1 : 0);
    PutCount(output, manifest.members.size());
    for (const auto& member : manifest.members) {
        PutNumber(output, member.id, 8);
        output += EncodeInteger(member.modulus, 32);
    }
    if (manifest.sanitizer) output += EncodePoint(*manifest.sanitizer);
    return output;
}

std::string EncodeManifest(const Manifest& manifest) {
    return ManifestBody(manifest) + EncodePoint(manifest.commitment) + EncodeInteger(manifest.response, SCALAR_BYTES);
}

std::optional<AcceptedEpoch> AcceptEpoch(const Params& pp, const SystemId& system, ECP verificationKey,
    std::string_view wire, std::uint64_t minimumEpoch) {
    try {
        Reader reader(wire);
        if (reader.Number(4) != VERSION || !ValidPoint(verificationKey, false)) return std::nullopt;
        Manifest manifest{};
        manifest.system = reader.Array<16>();
        manifest.epoch = reader.Number(8);
        if (manifest.system != system || manifest.epoch == 0 || manifest.epoch < minimumEpoch)
            return std::nullopt;
        manifest.nonce = reader.Array<32>();
        const auto active = reader.Number(1);
        const auto count = reader.Number(4);
        if (active > 1 || (active == 1) != (count != 0) || count > reader.size() / MEMBER_BYTES)
            return std::nullopt;
        manifest.members.reserve(count);
        Id previous = 0;
        for (std::size_t index = 0; index < count; ++index) {
            const auto id = reader.Number(8);
            auto modulus = Integer(reader.Take(32));
            if (id <= previous || BitLength(modulus) != 256 || modulus <= pp.q || mpz_even_p(modulus.get_mpz_t()))
                return std::nullopt;
            manifest.members.push_back({id, std::move(modulus)});
            previous = id;
        }
        if (active) manifest.sanitizer = ReadPoint(reader, false);
        const auto context = wire.substr(0, wire.size() - reader.size());
        if (active) {
            const auto sx = reader.Field();
            if (sx.empty() || sx.size() > count * 32 || (sx.size() > 1 && sx.front() == '\0'))
                return std::nullopt;
            manifest.sx = Integer(sx);
        }
        const auto body = wire.substr(0, wire.size() - reader.size());
        manifest.commitment = ReadPoint(reader, false);
        manifest.response = Integer(reader.Take(SCALAR_BYTES));
        if (reader.size() != 0 || !Scalar(pp, manifest.response)) return std::nullopt;
        const auto challenge = HashScalar(pp, "DSS-MS/auth/v1",
            {EncodePoint(verificationKey), EncodePoint(manifest.commitment), body});
        auto expected = Mul(verificationKey, challenge);
        ECP_add(&expected, &manifest.commitment);
        if (!Equal(Mul(pp.P, manifest.response), expected)) return std::nullopt;
        if (active && manifest.sx >= CheckedProduct(manifest.members, 0, manifest.members.size()))
            return std::nullopt;
        return AcceptedEpoch(std::move(manifest), Digest(context));
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}

bool MatchesSanitizerKey(const Params& pp, const AcceptedEpoch& epoch, const mpz_class& candidate) {
    return epoch.manifest().sanitizer && Scalar(pp, candidate) && candidate != 0
        && Equal(Mul(pp.P, candidate), *epoch.manifest().sanitizer);
}

std::optional<mpz_class> Recover(const Params& pp, const Member& member, const AcceptedEpoch& epoch) {
    const auto& manifest = epoch.manifest();
    const auto found = std::lower_bound(manifest.members.begin(), manifest.members.end(), member.id,
        [](const PublicMember& entry, Id id) { return entry.id < id; });
    if (!manifest.sanitizer || found == manifest.members.end() || found->id != member.id
        || found->modulus != member.modulus) return std::nullopt;
    const auto recovered = Mod(Mod(manifest.sx, member.modulus) - Mask(member, epoch.contextDigest()), member.modulus);
    if (!MatchesSanitizerKey(pp, epoch, recovered)) return std::nullopt;
    return recovered;
}

std::string EncodeSignature(const Signature& signature) {
    return EncodePoint(signature.R) + EncodeInteger(signature.z, SCALAR_BYTES)
        + EncodeInteger(signature.s, SCALAR_BYTES) + EncodePoint(signature.T);
}

std::string EncodeOrder(const SignedOrder& order) {
    return EncodeImmutable(order.message) + EncodeBlocks(order.message.blocks) + EncodeSignature(order.signature);
}

std::optional<SignedOrder> DecodeOrder(const Params& pp, std::string_view bytes) {
    try {
        Reader reader(bytes);
        SignedOrder order{};
        auto& message = order.message;
        message.system = reader.Array<16>();
        message.epoch = reader.Number(8);
        message.order = reader.Number(8);
        message.immutable = reader.Field();
        const auto count = reader.Number(4);
        if (count > reader.size() / 5) return std::nullopt;
        for (unsigned char editable : reader.Take(count)) {
            if (editable > 1) return std::nullopt;
            message.editable.push_back(editable == 1);
        }
        for (std::size_t index = 0; index < count; ++index) message.blocks.emplace_back(reader.Field());
        order.signature = {ReadPoint(reader, true), Integer(reader.Take(SCALAR_BYTES)),
            Integer(reader.Take(SCALAR_BYTES)), ReadPoint(reader, true)};
        if (reader.size() != 0 || !ValidMessage(message) || !Scalar(pp, order.signature.s)
            || !Scalar(pp, order.signature.z)) return std::nullopt;
        return order;
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }
}

std::optional<Original> Sign(const Params& pp, const Message& message, const KeyPair& signer,
    const AcceptedEpoch& epoch, std::uint64_t minimumEpoch) {
    if (!Current(message, epoch, minimumEpoch) || !Scalar(pp, signer.sk) || signer.sk == 0) return std::nullopt;
    const auto r = RandomScalar(pp);
    const auto t = RandomScalar(pp);
    SignedOrder order{message, {Mul(pp.P, r), 0, RandomScalar(pp), Mul(pp.P, t)}};
    const auto ch = Chameleon(pp, order, *epoch.manifest().sanitizer);
    order.signature.z = Mod(r + Outer(pp, message, order.signature.R, ch) * signer.sk, pp.q);
    return Original{std::move(order), t};
}

bool Verify(const Params& pp, const SignedOrder& order, ECP signer, const AcceptedEpoch& epoch,
    std::uint64_t minimumEpoch) {
    return VerifiedCommitment(pp, order, signer, epoch, minimumEpoch).has_value();
}

std::optional<SignedOrder> Sanitizing(const Params& pp, const SignedOrder& original,
    const std::vector<std::string>& replacement, const Member& member, ECP signer,
    const AcceptedEpoch& epoch, std::uint64_t minimumEpoch, const AuditSink& audit) {
    const auto commitment = VerifiedCommitment(pp, original, signer, epoch, minimumEpoch);
    if (!commitment || replacement.size() != original.message.blocks.size()
        || replacement == original.message.blocks) return std::nullopt;
    for (std::size_t index = 0; index < replacement.size(); ++index)
        if (!original.message.editable[index] && replacement[index] != original.message.blocks[index])
            return std::nullopt;
    const auto trapdoor = Recover(pp, member, epoch);
    if (!trapdoor) return std::nullopt;

    SignedOrder result = original;
    result.message.blocks = replacement;
    auto point = *commitment;
    const auto k = RandomScalar(pp);
    const auto negative = Mul(pp.P, Mod(-k, pp.q));
    Add(point, negative);
    ECP_copy(&result.signature.T, &point);
    result.signature.s = Mod(k - Inner(pp, result.message, point) * *trapdoor, pp.q);
    if (audit) audit({member.id, result.message.order, result.message.epoch, Digest(EncodeOrder(result))});
    return result;
}

std::string EncodeEvidence(const Evidence& evidence) {
    std::string output;
    PutField(output, EncodeOrder(evidence.original));
    PutField(output, EncodeOrder(evidence.disputed));
    return output + EncodePoint(evidence.U) + EncodeInteger(evidence.v, SCALAR_BYTES);
}

std::optional<Evidence> Proof(const Params& pp, const Original& original,
    const SignedOrder& disputed, ECP signer, const AcceptedEpoch& epoch) {
    if (!Scalar(pp, original.randomness) || !Equal(Mul(pp.P, original.randomness), original.order.signature.T)
        || !SameDispute(original.order, disputed) || !Verify(pp, original.order, signer, epoch, 0)
        || !Verify(pp, disputed, signer, epoch, 0)) return std::nullopt;
    const auto rho = RandomScalar(pp);
    Evidence evidence{original.order, disputed, Mul(pp.P, rho), 0};
    evidence.v = Mod(rho + ProofChallenge(pp, epoch, signer, evidence) * original.randomness, pp.q);
    return evidence;
}

bool Judge(const Params& pp, const Evidence& evidence, ECP signer, const AcceptedEpoch& epoch) {
    if (!Scalar(pp, evidence.v) || !ValidPoint(evidence.U, true) || !SameDispute(evidence.original, evidence.disputed)
        || !Verify(pp, evidence.original, signer, epoch, 0) || !Verify(pp, evidence.disputed, signer, epoch, 0))
        return false;
    auto expected = Mul(evidence.original.signature.T, ProofChallenge(pp, epoch, signer, evidence));
    Add(expected, evidence.U);
    return Equal(Mul(pp.P, evidence.v), expected);
}

} // namespace DSS
