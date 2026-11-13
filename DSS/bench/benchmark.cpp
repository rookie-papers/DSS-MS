#include "DSS.h"
#include "measure.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <spawn.h>

extern char** environ;
#include <unistd.h>

namespace {
namespace fs = std::filesystem;
using namespace DSS;
using Experiment::Csv;
using Experiment::Measure;
using Experiment::Require;
using Experiment::Sample;

struct Options {
    fs::path output, inspect;
    int repeats = 30, iterations = 8, historyTrials = 1000;
    std::size_t members = 100, batch = 1;
    double window = 10;
    bool smoke = false, check = false;
    std::string workload;
};

Options Parse(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string arg(argv[index]);
        const auto next = [&]() -> std::string {
            if (++index == argc) throw std::invalid_argument("Missing value for " + arg);
            return argv[index];
        };
        if (arg == "--output") options.output = next();
        else if (arg == "--inspect-epoch") options.inspect = next();
        else if (arg == "--repeats") options.repeats = std::stoi(next());
        else if (arg == "--iterations") options.iterations = std::stoi(next());
        else if (arg == "--history-trials") options.historyTrials = std::stoi(next());
        else if (arg == "--members") options.members = std::stoul(next());
        else if (arg == "--batch") options.batch = std::stoul(next());
        else if (arg == "--window") options.window = std::stod(next());
        else if (arg == "--workload") options.workload = next();
        else if (arg == "--smoke") options.smoke = true;
        else if (arg == "--check") options.check = true;
        else throw std::invalid_argument("Unknown argument " + arg);
    }
    Require(options.repeats > 0 && options.iterations > 0 && options.historyTrials > 0
        && options.members > 0 && options.batch > 0 && options.window > 0, "Options must be positive");
    return options;
}

AcceptedEpoch Accepted(const Params& pp, const Authority& authority, const Manifest& manifest) {
    auto accepted = AcceptEpoch(pp, authority.system(), authority.verificationKey(), EncodeManifest(manifest), manifest.epoch);
    Require(accepted.has_value(), "Could not accept generated epoch");
    return std::move(*accepted);
}

std::vector<Id> FirstMembers(std::size_t count) {
    std::vector<Id> ids(count);
    std::iota(ids.begin(), ids.end(), Id{1});
    return ids;
}

Message WorkloadMessage(const Manifest& manifest, std::size_t bytes, std::size_t blocks, bool baseline = false) {
    const std::size_t immutable = baseline ? bytes / 2 : std::min<std::size_t>(32, bytes / 2);
    Require(blocks != 0 && bytes - immutable >= blocks, "Insufficient bytes for message blocks");
    Message message{manifest.system, manifest.epoch, 1, std::string(immutable, 'b'),
        std::vector<bool>(blocks, true), {}};
    const auto editable = bytes - immutable;
    for (std::size_t index = 0; index < blocks; ++index)
        message.blocks.emplace_back(editable / blocks + (index < editable % blocks), 'a');
    return message;
}

struct Fixture {
    Params pp = Setup();
    Authority authority;
    Manifest manifest;
    std::string wire;
    AcceptedEpoch epoch;
    KeyPair signer = KGen(pp);
    Message message;
    Original original;
    std::vector<std::string> edited;
    SignedOrder sanitized;
    Evidence evidence;

    Fixture(std::size_t members, std::size_t bytes, std::size_t blocks, bool baseline = false)
        : authority(pp, members), manifest(authority.Publish()), wire(EncodeManifest(manifest)),
          epoch(Accepted(pp, authority, manifest)), message(WorkloadMessage(manifest, bytes, blocks, baseline)),
          original(Sign(pp, message, signer, epoch, manifest.epoch).value()), edited(message.blocks) {
        edited.front().front() = 'x';
        sanitized = Sanitizing(pp, original.order, edited, authority.member(1), signer.pk, epoch, manifest.epoch).value();
        Require(Verify(pp, sanitized, signer.pk, epoch, manifest.epoch), "DSS sanitized signature failed");
        evidence = Proof(pp, original, sanitized, signer.pk, epoch).value();
        Require(Judge(pp, evidence, signer.pk, epoch), "DSS evidence failed");
    }
};

void Check() {
    Fixture f(5, 4096, 64);
    const auto& pp = f.pp;
    auto saved = f.authority.member(1);
    const auto expected = Recover(pp, saved, f.epoch);
    Require(expected.has_value(), "DSS authorized recovery failed");
    for (Id id = 2; id <= 5; ++id)
        Require(Recover(pp, f.authority.member(id), f.epoch) == expected, "CRT residues disagree");
    auto wrong = saved;
    wrong.key[0] ^= 1;
    Require(!Recover(pp, wrong, f.epoch), "Incorrect member secret accepted");
    auto invalid = f.wire;
    invalid.back() ^= 1;
    Require(!AcceptEpoch(pp, f.authority.system(), f.authority.verificationKey(), invalid, 1), "Tampered TA signature accepted");
    auto otherSystem = f.authority.system();
    otherSystem[0] ^= 1;
    Require(!AcceptEpoch(pp, otherSystem, f.authority.verificationKey(), f.wire, 1), "Wrong system accepted");
    auto decoded = DecodeOrder(pp, EncodeOrder(f.sanitized));
    Require(decoded && Verify(pp, *decoded, f.signer.pk, f.epoch, 1), "Order round trip failed");
    auto changed = f.sanitized;
    changed.message.blocks.back()[0] ^= 1;
    Require(!Verify(pp, changed, f.signer.pk, f.epoch, 1), "Tampered order accepted");
    auto evidence = f.evidence;
    ++evidence.v;
    Require(!Judge(pp, evidence, f.signer.pk, f.epoch), "Tampered evidence accepted");
    Require(!Proof(pp, f.original, f.original.order, f.signer.pk, f.epoch), "Unchanged dispute accepted");

    auto policy = f.message;
    policy.editable.front() = false;
    auto protectedOrder = Sign(pp, policy, f.signer, f.epoch, 1).value();
    Require(!Sanitizing(pp, protectedOrder.order, f.edited, saved, f.signer.pk, f.epoch, 1),
        "Protected block modified");
    bool audited = false;
    Require(Sanitizing(pp, f.original.order, f.edited, saved, f.signer.pk, f.epoch, 1,
        [&](const AuditEvent& event) { audited = event.member == 1 && event.epoch == 1; }).has_value()
        && audited, "Missing sanitization audit event");

    auto revoked = f.authority.Revoke({1});
    auto newEpoch = Accepted(pp, f.authority, revoked);
    Require(!Recover(pp, saved, newEpoch), "Revoked member recovered the new epoch");
    Require(Recover(pp, f.authority.member(2), newEpoch).has_value(), "Remaining member recovery failed");
    Require(!AcceptEpoch(pp, f.authority.system(), f.authority.verificationKey(), f.wire, 2), "Rollback accepted");
    Require(!Verify(pp, f.sanitized, f.signer.pk, newEpoch, 2), "Wrong epoch accepted");
    Require(!Verify(pp, f.sanitized, f.signer.pk, f.epoch, 2), "Archived order accepted for live dispatch");
    Require(Verify(pp, f.sanitized, f.signer.pk, f.epoch, 0), "Historical verification failed");
    auto joined = f.authority.Join(1);
    Require(!Recover(pp, f.authority.member(6), f.epoch), "New member accepted for past epoch");
    Require(Recover(pp, f.authority.member(6), Accepted(pp, f.authority, joined)).has_value(), "Joined member recovery failed");
    auto stopped = f.authority.Revoke({2, 3, 4, 5, 6});
    Require(!Accepted(pp, f.authority, stopped).manifest().sanitizer, "Revoking all members should disable the epoch");
}

struct Axis {
    std::string sweep;
    std::size_t members, after, batch, bytes, blocks;
};

struct Results {
    const std::string id;
    Csv timing, sizes, baseline, history;

    Results(const fs::path& path, std::string runId)
        : id(std::move(runId)),
          timing((path / "timing.csv").string(),
              "run_id,sweep,algorithm,active_sanitizers,active_after,batch,msg_bytes,editable_blocks,repeat,iterations,time_us,source"),
          sizes((path / "size_comm.csv").string(),
              "run_id,active_sanitizers,epoch,kind,operation,message,sender,receiver,item,bits,bytes,source,note"),
          baseline((path / "baseline.csv").string(),
              "run_id,scheme,algorithm,message_blocks,active_sanitizers,msg_bytes,repeat,iterations,time_us,signature_bytes,source,note"),
          history((path / "gcd_history.csv").string(),
              "run_id,trial,scenario,initial_members,epochs,gcd_bits,candidate_matches_secret,pk_check_pass,recovered") {}

    void Timing(const Axis& a, const std::string& algorithm, const std::vector<Sample>& samples) {
        for (const auto& sample : samples)
            timing.Row({id, a.sweep, algorithm, std::to_string(a.members), std::to_string(a.after),
                std::to_string(a.batch), std::to_string(a.bytes), std::to_string(a.blocks),
                std::to_string(sample.repeat), std::to_string(sample.iterations), std::to_string(sample.us), "measured"});
    }

    void Size(const Manifest& m, const std::string& kind, const std::string& operation, const std::string& message,
        const std::string& sender, const std::string& receiver, const std::string& item, std::size_t bits,
        std::size_t bytes, const std::string& source, const std::string& note) {
        sizes.Row({id, std::to_string(m.members.size()), std::to_string(m.epoch), kind, operation, message,
            sender, receiver, item, std::to_string(bits), std::to_string(bytes), source, note});
    }
};

void ManifestSizes(Results& out, const Manifest& m) {
    const auto contextBytes = EncodeContext(m).size();
    const auto manifestBytes = EncodeManifest(m).size();
    const auto sxBits = BitLength(m.sx);
    const auto sxBytes = m.sanitizer ? std::max<std::size_t>(1, (sxBits + 7) / 8) : 0;
    const std::vector<std::pair<std::string, std::size_t>> parts{{"context", contextBytes},
        {"manifest", manifestBytes}, {"public_moduli", m.members.size() * 32},
        {"member_ids", m.members.size() * 8}, {"sanitizer_public_key", m.sanitizer ? EncodePoint(*m.sanitizer).size() : 0},
        {"authority_signature", EncodePoint(m.commitment).size() + 32}};
    out.Size(m, "parameter", "", "", "", "", "S_x", sxBits, sxBytes, "measured", "integer bit length; minimal encoded payload");
    for (const auto& [name, size] : parts)
        out.Size(m, "parameter", "", "", "", "", name, size * 8, size, "measured",
            "encoded bytes; component entries overlap");
}

void InspectEpoch(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    SystemId system{};
    std::string publicKey(49, '\0');
    Require(static_cast<bool>(input.read(reinterpret_cast<char*>(system.data()), system.size())
        .read(publicKey.data(), publicKey.size())), "Missing trusted epoch inspection header");
    std::ostringstream buffer;
    buffer << input.rdbuf();
    const auto key = DecodePublicKey(publicKey);
    Require(key && AcceptEpoch(Setup(), system, *key, buffer.str(), 1).has_value(), "Epoch inspection failed");
}

std::size_t PeakReceiverMemory(const Fixture& f, const fs::path& executable, const fs::path& output) {
    const auto file = output / ".epoch-inspection";
    {
        std::ofstream bundle(file, std::ios::binary);
        bundle.exceptions(std::ios::badbit | std::ios::failbit);
        bundle.write(reinterpret_cast<const char*>(f.manifest.system.data()), f.manifest.system.size());
        bundle << EncodePoint(f.authority.verificationKey()) << f.wire;
        bundle.close();
    }
    auto command = executable.string();
    auto input = file.string();
    char option[] = "--inspect-epoch";
    char* args[] = {command.data(), option, input.data(), nullptr};
    pid_t child;
    int status = 0;
    rusage usage{};
    const auto spawned = posix_spawn(&child, args[0], nullptr, nullptr, args, environ);
    const auto finished = spawned == 0 && wait4(child, &status, 0, &usage) == child;
    fs::remove(file);
    Require(finished && WIFEXITED(status) && WEXITSTATUS(status) == 0, "Receiver memory probe failed");
#if defined(__APPLE__)
    return usage.ru_maxrss;
#else
    return static_cast<std::size_t>(usage.ru_maxrss) * 1024;
#endif
}

void Communication(Results& out, const Fixture& f) {
    const auto& m = f.manifest;
    const auto signature = EncodeSignature(f.original.order.signature).size();
    const auto order = EncodeOrder(f.original.order).size() - signature;
    const auto sanitized = EncodeOrder(f.sanitized).size() - signature;
    const auto manifest = f.wire.size();
    auto wire = [&](const std::string& op, const std::string& message, const std::string& from,
                    const std::string& to, const std::string& item, std::size_t bytes, const std::string& note = "") {
        out.Size(m, "protocol", op, message, from, to, item, bytes * 8, bytes, "formula", note);
    };
    const auto keyBytes = EncodePoint(f.signer.pk).size();
    wire("Setup", "trust bootstrap", "TA", "each receiver", "TA verification key", keyBytes);
    wire("Setup", "trust bootstrap", "TA", "each receiver", "system ID", m.system.size());
    wire("Setup", "signer certification", "TA", "each receiver", "signer certificate",
        m.system.size() + sizeof(Id) + keyBytes + keyBytes + 32,
        "model: system ID, signer ID, signer public key, TA signature; application payload");
    wire("Setup", "initial parameters", "TA", "each receiver", "manifest", manifest);
    wire("Setup", "initial enrollment", "TA", "each enrolled sanitizer", "PRF key", Secret{}.size(),
        "per recipient; protected channel framing excluded");
    wire("Sign", "original order", "signer", "logistics", "order", order);
    wire("Sign", "original order", "signer", "logistics", "signature", signature);
    wire("Sign", "forward original order", "logistics", "warehouse", "order", order);
    wire("Sign", "forward original order", "logistics", "warehouse", "signature", signature);
    wire("Sanitize", "sanitized order", "warehouse", "UAV", "order", sanitized);
    wire("Sanitize", "sanitized order", "warehouse", "UAV", "signature", signature);
    wire("Verify", "local verification", "UAV", "UAV", "no additional message", 0, "cached manifest and signer key");
    wire("Proof", "dispute evidence", "signer", "judge", "evidence", EncodeEvidence(f.evidence).size());
    wire("Judge", "local judgment", "judge", "judge", "no additional message", 0);
}

void UpdateCommunication(Results& out, const Manifest& m, const std::string& op, std::size_t count) {
    const auto publish = EncodeManifest(m).size();
    out.Size(m, "protocol", op, "authenticated update", "TA", "each receiver", "manifest",
        publish * 8, publish, "formula", "per recipient; authorization set is part of the manifest");
    if (op == "Join") {
        const auto secrets = count * Secret{}.size();
        out.Size(m, "protocol", op, "enrollment secrets", "TA", "joining members", "PRF key",
            secrets * 8, secrets, "formula", "one 32-byte secret per joining member; secure-channel overhead excluded");
    }
    const auto ids = 4 + count * sizeof(Id);
    out.Size(m, "protocol", op, "membership request", "logistics", "TA", "member IDs",
        ids * 8, ids, "formula", "hypothetical 32-bit count and 64-bit member IDs; certificate and transport envelopes excluded");
}

void OrderTimes(Results& out, const Fixture& f, const Axis& a, int repeats, int iterations) {
    const auto& pp = f.pp;
    const auto& epoch = f.epoch;
    const auto period = f.manifest.epoch;
    const auto& member = f.authority.member(1);
    const auto& signer = f.signer;
    out.Timing(a, "Sign", Measure(repeats, iterations, [&] { return Sign(pp, f.message, signer, epoch, period); }));
    out.Timing(a, "Sanitize", Measure(repeats, iterations, [&] {
        return Sanitizing(pp, f.original.order, f.edited, member, signer.pk, epoch, period);
    }));
    out.Timing(a, "Verify", Measure(repeats, iterations, [&] { return Verify(pp, f.sanitized, signer.pk, epoch, period); }));
}

void RecordBaselineDss(Results& out, int repeats, int iterations) {
    const Fixture f(2, 256, 1, true);
    auto write = [&](const std::string& algorithm, const std::vector<Sample>& samples) {
        for (const auto& sample : samples)
            out.baseline.Row({out.id, "DSS-MS", algorithm, "2", "2", "256", std::to_string(sample.repeat),
                std::to_string(sample.iterations), std::to_string(sample.us), "NA", "measured",
                "one editable and one immutable block"});
    };
    write("Sign", Measure(repeats, iterations, [&] { return Sign(f.pp, f.message, f.signer, f.epoch, 1); }));
    write("Sanitize", Measure(repeats, iterations, [&] {
        return Sanitizing(f.pp, f.original.order, f.edited, f.authority.member(1), f.signer.pk, f.epoch, 1);
    }));
    write("Verify", Measure(repeats, iterations, [&] { return Verify(f.pp, f.sanitized, f.signer.pk, f.epoch, 1); }));
    out.baseline.Row({out.id, "DSS-MS", "Signature", "2", "2", "256", "NA", "NA", "NA",
        std::to_string(EncodeSignature(f.original.order.signature).size()), "measured", "canonical signature bytes"});
}

void ManagementTimes(Results& out, const Fixture& f, std::size_t count, const Options& opts) {
    const auto repeats = opts.repeats;
    const auto members = f.manifest.members.size();
    const auto prepare = [&] { return f.authority; };
    for (const auto batch : {std::size_t{1}, std::size_t{10}, std::size_t{100}}) {
        if (opts.smoke && batch > 10) continue;
        const Axis join{"membership", members, members + batch, batch, 0, 0};
        out.Timing(join, "Join", Measure(repeats, 1, prepare,
            [batch](Authority& authority) { return authority.Join(batch); }));
        if (batch == count) {
            auto authority = prepare();
            UpdateCommunication(out, authority.Join(batch), "Join", batch);
        }
        if (batch >= members) continue;
        const auto ids = FirstMembers(batch);
        const Axis revoke{"membership", members, members - batch, batch, 0, 0};
        out.Timing(revoke, "Revoke", Measure(repeats, 1, prepare,
            [&](Authority& authority) { return authority.Revoke(ids); }));
        if (batch == count) {
            auto authority = prepare();
            UpdateCommunication(out, authority.Revoke(ids), "Revoke", batch);
        }
    }
}

void History(Results& out, int trials) {
    const auto pp = Setup();
    for (int index = 1; index <= trials; ++index) {
        for (bool mixed : {false, true}) {
            Authority authority(pp, 5);
            std::vector<AcceptedEpoch> periods;
            periods.push_back(Accepted(pp, authority, authority.Publish()));
            auto candidate = periods.back().manifest().sx;
            for (int step = 1; step <= 5; ++step) {
                const auto next = mixed && step % 2 == 0 ? authority.Revoke({static_cast<Id>(step)})
                    : authority.Join(1);
                periods.push_back(Accepted(pp, authority, next));
                mpz_gcd(candidate.get_mpz_t(), candidate.get_mpz_t(), next.sx.get_mpz_t());
            }
            bool equal = false, publicMatch = false;
            for (const auto& period : periods) {
                const auto trapdoor = Recover(pp, authority.member(1), period).value();
                equal |= trapdoor == candidate;
                publicMatch |= MatchesSanitizerKey(pp, period, candidate);
            }
            out.history.Row({out.id, std::to_string(index), mixed ? "mixed" : "join_only", "5", "6",
                std::to_string(BitLength(candidate)), equal ? "1" : "0", publicMatch ? "1" : "0",
                equal && publicMatch ? "1" : "0"});
        }
    }
}

std::string ReadText(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    std::ostringstream contents;
    contents << file.rdbuf();
    auto result = contents.str();
    while (!result.empty() && (result.back() == '\0' || result.back() == '\n')) result.pop_back();
    return result.empty() ? "NA" : result;
}

std::string UtcTime() {
    const auto now = std::time(nullptr);
    std::ostringstream text;
    text << std::put_time(std::gmtime(&now), "%Y%m%dT%H%M%SZ");
    return text.str();
}

void Run(const Options& options, const fs::path& executable) {
    const auto scripts = executable.parent_path();
    const auto runId = UtcTime() + "-" + std::to_string(getpid());
    const auto output = options.output.empty() ? fs::path("results") / runId : options.output;
    fs::create_directories(output);
    Require(!fs::exists(output / "runs.csv"), "Use a new output directory for each run");
    for (const auto script : {"plot_results.py", "collect_energy.py"}) {
        const auto source = scripts / script;
        Require(fs::is_regular_file(source), "Missing companion script " + source.string());
        fs::copy_file(source, output / script, fs::copy_options::overwrite_existing);
    }
    std::cout << "Results: " << fs::absolute(output) << std::endl;
    utsname platform{};
    uname(&platform);
    Csv runs((output / "runs.csv").string(), "run_id,profile,platform,board,kernel,compiler,build_type,git_revision,"
        "wrapper_revision,jetpack,nvpmodel,governor,cpu_khz,temp_millic,warmup_repeats,repeats,iterations,history_trials");
    const auto config = ReadText("/etc/nvpmodel.conf");
    runs.Row({runId, options.smoke ? "smoke" : "full", platform.machine, ReadText("/proc/device-tree/model"),
        platform.release, DSS_COMPILER, DSS_BUILD_TYPE, DSS_GIT_REVISION, DSS_WRAPPER_REVISION,
        ReadText("/etc/nv_tegra_release"), config == "NA" ? config : ReadText("/var/lib/nvpmodel/status"),
        ReadText("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        ReadText("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"),
        ReadText("/sys/class/thermal/thermal_zone0/temp"), "1", std::to_string(options.repeats),
        std::to_string(options.iterations), std::to_string(options.historyTrials)});
    Results out(output, runId);
    const std::vector<std::size_t> counts = options.smoke ? std::vector<std::size_t>{2, 10, 100, 10000}
        : std::vector<std::size_t>{2, 10, 100, 500, 1000, 3000, 10000};
    const auto repeats = options.repeats, iterations = options.iterations;
    const auto noInputs = Axis{"setup", 0, 0, 0, 0, 0};
    out.Timing(noInputs, "Setup", Measure(repeats, iterations, [] { return Setup(); }));
    for (const auto members : counts) {
        std::cout << "Membership scale " << members << std::endl;
        const Fixture f(members, 256, 4);
        const auto& pp = f.pp;
        ManifestSizes(out, f.manifest);
        const auto signatureSize = EncodeSignature(f.original.order.signature).size();
        out.Size(f.manifest, "signature", "", "", "", "", "signature", signatureSize * 8, signatureSize,
            "measured", "DSS canonical serialization");
        if (members == 100 || members == 3000 || members == 10000) {
            Communication(out, f);
            const auto rss = PeakReceiverMemory(f, executable, output);
            out.Size(f.manifest, "storage", "", "", "", "receiver", "accept_epoch_peak_rss", rss * 8, rss,
                "measured", "fresh receiver process; includes executable, file buffer, decoder, and authenticated manifest");
        }
        const Axis a{"members", members, members, 0, 256, 4};
        out.Timing(a, "KGen", Measure(repeats, 1, [&] { return Authority(pp, members); }));
        const Authority initial(pp, members);
        out.Timing(a, "EpochGen", Measure(repeats, 1, [&] { return initial; },
            [](Authority& authority) { return authority.Publish(); }));
        out.Timing(a, "Serialize", Measure(repeats, iterations, [&] { return EncodeManifest(f.manifest); }));
        out.Timing(a, "AcceptEpoch", Measure(repeats, 1, [&] {
            return AcceptEpoch(pp, f.authority.system(), f.authority.verificationKey(), f.wire, 1);
        }));
        out.Timing(a, "Recover", Measure(repeats, iterations,
            [&] { return Recover(pp, f.authority.member(1), f.epoch); }));
        OrderTimes(out, f, a, repeats, iterations);
        out.Timing(a, "Proof", Measure(repeats, iterations,
            [&] { return Proof(pp, f.original, f.sanitized, f.signer.pk, f.epoch); }));
        out.Timing(a, "Judge", Measure(repeats, iterations,
            [&] { return Judge(pp, f.evidence, f.signer.pk, f.epoch); }));
        ManagementTimes(out, f, members == 100 || members == 3000 || members == 10000 ? 1 : 0, options);
    }
    for (const auto bytes : {64, 256, 1024, 4096}) {
        const Fixture f(100, bytes, 4);
        OrderTimes(out, f, Axis{"bytes", 100, 100, 0, static_cast<std::size_t>(bytes), 4}, repeats, iterations);
    }
    for (const auto blocks : {1, 4, 16, 64}) {
        const Fixture f(100, 1024, blocks);
        OrderTimes(out, f, Axis{"blocks", 100, 100, 0, 1024, static_cast<std::size_t>(blocks)}, repeats, iterations);
    }

    std::cout << "Comparable schemes" << std::endl;
    RecordBaselineDss(out, repeats, iterations);
    Experiment::RunBaselines(out.baseline, out.id, repeats, iterations);
    std::cout << "GCD history" << std::endl;
    History(out, options.historyTrials);
    std::ofstream(output / "complete.txt") << runId << '\n';
}

template <class RunOperation>
void Workload(double window, RunOperation operation) {
    using Clock = std::chrono::steady_clock;
    const auto nanoseconds = [](auto time) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(time.time_since_epoch()).count();
    };
    std::cout << "READY" << std::endl;
    std::string line;
    Require(static_cast<bool>(std::getline(std::cin, line)) && line == "GO", "Expected GO on stdin");
    const auto start = Clock::now();
    std::uint64_t completed = 0;
    do {
        auto result = operation();
        benchmark::DoNotOptimize(result);
        ++completed;
    } while (Clock::now() - start < std::chrono::duration<double>(window));
    std::cout << nanoseconds(start) << ',' << nanoseconds(Clock::now()) << ',' << completed << '\n';
}

void EnergyWorkload(const Options& options) {
    if (options.workload == "Idle") {
        Workload(options.window, [&] { usleep(100000); return true; });
        return;
    }
    const Fixture f(options.members, 256, 4);
    const auto& pp = f.pp;
    const auto& op = options.workload;
    if (op == "AcceptEpoch")
        Workload(options.window, [&] { return AcceptEpoch(pp, f.authority.system(), f.authority.verificationKey(), f.wire, 1); });
    else if (op == "Sign")
        Workload(options.window, [&] { return Sign(pp, f.message, f.signer, f.epoch, 1); });
    else if (op == "Sanitize")
        Workload(options.window, [&] { return Sanitizing(pp, f.original.order, f.edited, f.authority.member(1), f.signer.pk, f.epoch, 1); });
    else if (op == "Verify")
        Workload(options.window, [&] { return Verify(pp, f.sanitized, f.signer.pk, f.epoch, 1); });
    else if (op == "Join")
        Workload(options.window, [&] { auto authority = f.authority; return authority.Join(options.batch); });
    else if (op == "Revoke") {
        Require(options.batch <= options.members, "Revoke batch exceeds active members");
        const auto ids = FirstMembers(options.batch);
        Workload(options.window, [&] { auto authority = f.authority; return authority.Revoke(ids); });
    } else throw std::invalid_argument("Unknown energy workload " + op);
}

} // namespace

int main(int argc, char** argv) {
    try {
        const auto options = Parse(argc, argv);
        if (!options.inspect.empty()) {
            InspectEpoch(options.inspect);
            return 0;
        }
        if (!options.workload.empty()) {
            EnergyWorkload(options);
            return 0;
        }
        Check();
        if (options.check) Experiment::CheckNewBaselines();
        else Run(options, fs::canonical(argv[0]));
        std::cout << "DSS correctness checks passed" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "DSS benchmark: " << error.what() << '\n';
        return 1;
    }
}
