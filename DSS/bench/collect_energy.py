#!/usr/bin/env python3
"""Collect paired tegrastats power windows for the DSS-MS benchmark on Jetson."""
import argparse
import csv
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time


def read_power(stream, rail, samples):
    pattern = re.compile(r"(?<!\S)" + re.escape(rail) + r"\s+(\d+)(?:mW)?/\d+")
    for line in stream:
        match = pattern.search(line)
        if match:
            samples.append((time.monotonic_ns(), int(match[1])))


def workload(args, operation):
    command = [str(args.binary.resolve()), "--workload", operation, "--members", str(args.members),
               "--batch", str(args.batch), "--window", str(args.seconds)]
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as process:
        if process.stdout.readline().strip() != "READY":
            raise RuntimeError("The benchmark workload did not initialize")
        process.stdin.write("GO\n")
        process.stdin.flush()
        start, stop, count = map(int, process.stdout.readline().split(","))
        if process.wait() != 0 or count == 0:
            raise RuntimeError("The benchmark workload failed")
    return start, stop, count


def integrate(samples, start, stop):
    before = next((s for s in reversed(samples) if s[0] <= start), None)
    after = next((s for s in samples if s[0] >= stop), None)
    inside = [(t, p) for t, p in samples if start < t < stop]
    if before is None or after is None or len(inside) < 2:
        raise RuntimeError("Too few power samples. Increase the window or confirm the configured power rail.")
    points = [before, *inside, after]
    energy = 0.0
    for (first, a), (last, b) in zip(points, points[1:]):
        left, right = max(first, start), min(last, stop)
        if left >= right:
            continue
        fraction = ((left + right) / 2 - first) / (last - first)
        energy += (a + (b - a) * fraction) * (right - left) / 1e9
    return energy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--rail", required=True, help="power rail shown on this Jetson")
    parser.add_argument("--operation", nargs="+", choices=["Sign", "Sanitize", "Verify", "Join", "Revoke", "AcceptEpoch"],
                        default=["Sign", "Sanitize", "Verify", "Join", "Revoke", "AcceptEpoch"])
    parser.add_argument("--members", type=int, default=100)
    parser.add_argument("--batch", type=int, default=10)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--interval-ms", type=int, default=100)
    args = parser.parse_args()
    if not shutil.which("tegrastats"):
        parser.error("tegrastats is required on the Jetson")
    if min(args.members, args.batch, args.repeats, args.seconds, args.interval_ms) <= 0:
        parser.error("numeric options must be positive")
    args.directory.mkdir(parents=True, exist_ok=True)
    windows = args.directory / "energy.csv"
    raw = args.directory / "power_samples.csv"
    if windows.exists() or raw.exists():
        parser.error("this directory already has energy data")
    samples = []
    with subprocess.Popen(["tegrastats", "--interval", str(args.interval_ms)],
                          stdout=subprocess.PIPE, text=True) as sensor:
        thread = threading.Thread(target=read_power, args=(sensor.stdout, args.rail, samples), daemon=True)
        thread.start()
        try:
            time.sleep(3 * args.interval_ms / 1000)
            with windows.open("w", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(["operation", "members", "batch", "repeat", "rail", "interval_ms", "active_start_ns",
                                 "active_end_ns", "idle_start_ns", "idle_end_ns", "completed", "active_mj", "idle_mj",
                                 "energy_mj_per_operation"])
                for op in args.operation:
                    for repeat in range(1, args.repeats + 1):
                        pair = [op, "Idle"] if repeat % 2 else ["Idle", op]
                        measurements = {mode: workload(args, mode) for mode in pair}
                        time.sleep(2 * args.interval_ms / 1000)
                        a, b, count = measurements[op]
                        c, d, _ = measurements["Idle"]
                        active = integrate(samples, a, b)
                        idle = integrate(samples, c, d)
                        net = (active - idle * (b - a) / (d - c)) / count
                        writer.writerow([op, args.members, args.batch if op in {"Join", "Revoke"} else 0, repeat,
                                         args.rail, args.interval_ms, a, b, c, d, count, active, idle, net])
                        output.flush()
        finally:
            sensor.terminate()
            thread.join(timeout=5)
            with raw.open("w", newline="") as output:
                writer = csv.writer(output)
                writer.writerow(["monotonic_ns", "power_mw"])
                writer.writerows(samples)


if __name__ == "__main__":
    main()
