#ifndef DSS_BENCH_MEASURE_H
#define DSS_BENCH_MEASURE_H

#include <benchmark/benchmark.h>

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace Experiment {

class Csv {
public:
    Csv(const std::string& path, std::string_view header) : output_(path) {
        if (!output_) throw std::runtime_error("Cannot write " + path);
        output_ << header << '\n';
        output_.exceptions(std::ios::badbit | std::ios::failbit);
    }

    void Row(std::initializer_list<std::string> fields) {
        const char* delimiter = "";
        for (const auto& field : fields) {
            output_ << delimiter << '"';
            for (char byte : field) {
                if (byte == '"') output_ << '"';
                output_ << byte;
            }
            output_ << '"';
            delimiter = ",";
        }
        output_ << '\n';
        output_.flush();
    }

private:
    std::ofstream output_;
};

struct Sample { int repeat, iterations; double us; };

inline void Require(bool condition, const std::string& detail) {
    if (!condition) throw std::runtime_error(detail);
}

template <class Prepare, class Run>
std::vector<Sample> Measure(int repetitions, int iterations, Prepare prepare, Run run) {
    using Clock = std::chrono::steady_clock;
    std::vector<Sample> samples;
    for (int repeat = 0; repeat <= repetitions; ++repeat) {
        double microseconds = 0;
        for (int iteration = 0; iteration < iterations; ++iteration) {
            auto input = prepare();
            const auto start = Clock::now();
            auto result = run(input);
            benchmark::DoNotOptimize(result);
            microseconds += std::chrono::duration<double, std::micro>(Clock::now() - start).count();
        }
        if (repeat != 0) samples.push_back({repeat, iterations, microseconds / iterations});
    }
    return samples;
}

template <class Run>
std::vector<Sample> Measure(int repetitions, int iterations, Run run) {
    return Measure(repetitions, iterations, [] { return 0; }, [&](int&) { return run(); });
}

class BaselineRows {
public:
    BaselineRows(Csv& csv, const std::string& runId, std::string scheme, std::string sanitizers)
        : csv_(csv), runId_(runId), scheme_(std::move(scheme)), sanitizers_(std::move(sanitizers)) {}

    void Timing(const std::string& operation, const std::vector<Sample>& samples, const std::string& note) {
        for (const auto& sample : samples)
            csv_.Row({runId_, scheme_, operation, "2", sanitizers_, "256", std::to_string(sample.repeat),
                std::to_string(sample.iterations), std::to_string(sample.us), "NA", "measured", note});
    }

    void Signature(std::size_t bytes, const std::string& note) {
        csv_.Row({runId_, scheme_, "Signature", "2", sanitizers_, "256", "NA", "NA", "NA",
                  std::to_string(bytes), "measured", note});
    }

private:
    Csv& csv_;
    const std::string& runId_;
    std::string scheme_, sanitizers_;
};

// A null output runs the fixture's correctness checks only.
void BenchEcmss(Csv* csv, const std::string& id, int repeats, int iterations);
void BenchLsans(Csv* csv, const std::string& id, int repeats, int iterations);
void BenchPgus(Csv* csv, const std::string& id, int repeats, int iterations);
void CheckNewBaselines();

void RunBaselines(Csv& csv, const std::string& runId, int repetitions, int iterations);

} // namespace Experiment

#endif
