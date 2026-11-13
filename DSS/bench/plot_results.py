#!/usr/bin/env python3
"""Draw the DSS-MS paper figures from one result directory."""
import argparse
import csv
from collections import defaultdict
from pathlib import Path
import math
import statistics

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from mpl_toolkits.mplot3d.art3d import Poly3DCollection


def rows(path, name):
    with (path / name).open(newline="") as source:
        return list(csv.DictReader(source))


def save(fig, path, name):
    for extension in ("pdf", "png"):
        fig.savefig(path / f"{name}.{extension}", dpi=240, bbox_inches="tight")
    plt.close(fig)


def stats(samples):
    mean = statistics.mean(samples)
    if len(samples) == 1:
        return mean, 0
    df = len(samples) - 1
    small = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262]
    z = 1.959964
    critical = (small[df - 1] if df <= len(small)
                else z + (z**3 + z) / (4 * df) + (5 * z**5 + 16 * z**3 + 3 * z) / (96 * df**2))
    return mean, critical * statistics.stdev(samples) / math.sqrt(len(samples))


def line(ax, records, x_field, label, scale=1_000):
    values = defaultdict(list)
    for row in records:
        values[int(row[x_field])].append(float(row["time_us"]) / scale)
    if not values:
        return
    x = sorted(values)
    mean, ci = zip(*(stats(values[key]) for key in x))
    ax.errorbar(x, mean, yerr=ci, marker="o", markersize=4, linewidth=1.3, capsize=3, label=label)


def format_axis(ax, xlabel, ylabel, *, logx=False, logy=False):
    ax.set(xlabel=xlabel, ylabel=ylabel)
    if logx:
        ax.set_xscale("log")
    if logy:
        ax.set_yscale("log")
    ax.grid(alpha=.22, axis="y")
    if ax.get_legend_handles_labels()[0]:
        ax.legend(fontsize=8)


def sizes_plot(path, sizes):
    fig, ax = plt.subplots(figsize=(4.7, 3.25), layout="constrained")
    for item, label in [("S_x", r"CRT residue $S_x$"), ("manifest", "Authenticated manifest")]:
        values = sorted((int(r["active_sanitizers"]), int(r["bytes"]) / 1024)
                        for r in sizes if r["kind"] == "parameter" and r["item"] == item)
        ax.plot(*zip(*values), marker="o", label=label)
    format_axis(ax, "Authorized sanitizers", "Encoded size (KiB)", logx=True, logy=True)
    save(fig, path, "01_parameter_and_signature_sizes")


def timing_plot(path, timing):
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.25), layout="constrained")
    for ax, operations in zip(axes, [("EpochGen", "AcceptEpoch"), ("Sign", "Sanitize", "Verify")]):
        for op in operations:
            line(ax, [r for r in timing if r["sweep"] == "members" and r["algorithm"] == op],
                 "active_sanitizers", op)
        format_axis(ax, "Authorized sanitizers", "Time (ms)", logx=True, logy=ax is axes[0])
    save(fig, path, "02_membership_scale")


def membership_plot(path, timing):
    colors = {"Join": "#2166ac", "Revoke": "#18835b"}
    samples = {operation: defaultdict(list) for operation in colors}
    for row in timing:
        operation = row["algorithm"]
        if row["sweep"] == "membership" and operation in samples:
            pair = int(row["active_sanitizers"]), int(row["batch"])
            samples[operation][pair].append(float(row["time_us"]) / 1000)

    members = sorted({n for values in samples.values() for n, _ in values})
    batches = sorted({batch for values in samples.values() for _, batch in values})
    fig = plt.figure(figsize=(5.8, 4.1))
    ax = fig.add_subplot(projection="3d")
    z_values = []
    legend = []
    for operation, color in colors.items():
        # Transform coordinates explicitly so the surfaces and markers share log spacing.
        points = {(n, batch): (math.log10(n), math.log10(batch), math.log10(statistics.mean(times)))
                  for (n, batch), times in samples[operation].items()}
        if not points:
            continue
        faces = []
        for n0, n1 in zip(members, members[1:]):
            for b0, b1 in zip(batches, batches[1:]):
                corners = [(n0, b0), (n1, b0), (n1, b1), (n0, b1)]
                # Leave holes where the benchmark has no measurement at a corner.
                if all(corner in points for corner in corners):
                    faces.append([points[corner] for corner in corners])
        if faces:
            ax.add_collection3d(Poly3DCollection(
                faces, facecolors=color, edgecolors=color, alpha=.28, linewidths=.55))
        x, y, z = zip(*points.values())
        z_values.extend(z)
        marker = "o" if operation == "Join" else "^"
        ax.scatter(x, y, z, color=color, marker=marker, s=16, depthshade=False,
                   edgecolors="white", linewidths=.45)
        legend.append(Patch(facecolor=color, alpha=.48, label=operation))

    if members:
        member_ticks = sorted({members[0], members[-1], *(n for n in members if n in (10, 100, 1000))})
        ax.set_xticks([math.log10(n) for n in member_ticks], [f"{n:,}" for n in member_ticks])
        ax.set_yticks([math.log10(batch) for batch in batches], [f"{batch:,}" for batch in batches])
        z_min, z_max = math.floor(min(z_values)), math.ceil(max(z_values))
        z_ticks = range(z_min, z_max + 1)
        ax.set_zticks(z_ticks, [rf"$10^{{{z}}}$" for z in z_ticks])
        ax.set_zlim(z_min, max(z_min + 1, z_max))
    ax.set_xlabel("Sanitizers before update", labelpad=9)
    ax.set_ylabel("Sanitizers added or revoked", labelpad=9)
    ax.set_zlabel("Time (ms)", labelpad=6)
    ax.tick_params(labelsize=8, pad=0)
    ax.set_box_aspect((1.4, 1.05, .88))
    ax.view_init(elev=35, azim=-65)
    if legend:
        ax.legend(handles=legend, loc="upper left", bbox_to_anchor=(.01, .99), fontsize=8)
    save(fig, path, "03_join_revoke")


def message_plot(path, timing):
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.25), layout="constrained")
    for ax, sweep, field, xlabel in zip(axes, ("bytes", "blocks"), ("msg_bytes", "editable_blocks"),
                                       ("Message payload (bytes)", "Editable fields")):
        for op in ("Sign", "Sanitize", "Verify"):
            line(ax, [r for r in timing if r["sweep"] == sweep and r["algorithm"] == op], field, op)
        format_axis(ax, xlabel, "Time (ms)", logx=True)
    save(fig, path, "04_message_scaling")


def communication_plot(path, sizes, receivers):
    available = {int(r["active_sanitizers"]) for r in sizes if r["operation"] == "Setup"}
    members = 3000 if 3000 in available else min(available, key=lambda n: abs(n - 3000))
    management = ["Setup", "Join", "Revoke"]
    steady = ["original order", "forward original order", "sanitized order", "local verification"]
    protocol = [r for r in sizes if r["kind"] == "protocol"
                and int(r["active_sanitizers"]) == members + {"Join": 1, "Revoke": -1}.get(r["operation"], 0)]
    fig, (orders, updates) = plt.subplots(1, 2, figsize=(8.5, 3.5), layout="constrained")

    totals = [0] * len(steady)
    for item in ("order", "signature"):
        amounts = [sum(int(r["bytes"]) for r in protocol if r["message"] == message and r["item"] == item)
                   for message in steady]
        orders.bar(range(len(steady)), amounts, bottom=totals, label=item.capitalize())
        totals = [total + amount for total, amount in zip(totals, amounts)]
    orders.set_xticks(range(len(steady)), ["OI → LC", "LC → warehouse", "Warehouse → UAV", "Verify (local)"],
                     rotation=25, ha="right")
    orders.set_ylim(0, max(totals) * 1.3)
    format_axis(orders, "Order path", "Modeled payload (bytes)")

    def update_total(operation, fanout, enrollment_count):
        total = 0
        for row in protocol:
            if row["operation"] != operation:
                continue
            factors = {"each receiver": fanout, "each enrolled sanitizer": enrollment_count}
            total += int(row["bytes"]) * factors.get(row["receiver"], 1)
        return total / 1024

    for offset, fanout, enroll, label in [(-.19, 1, 1, "One recipient"),
                                           (.19, receivers, members, f"{receivers:,} recipients")]:
        values = [update_total(op, fanout, enroll) for op in management]
        updates.bar([index + offset for index in range(len(management))], values, width=.34, label=label)
    updates.set_xticks(range(len(management)), management)
    updates.set_title(f"{members:,} authorized sanitizers")
    format_axis(updates, "Parameter distribution", "Modeled payload (KiB)", logy=True)
    save(fig, path, "05_communication_payload")


def baseline_plot(path, baseline):
    reference_schemes = ("PF-CLSS-DV", "LSanS", "PGUS-SBS", "ECMSS")
    multi_schemes = ("IUT-k-SAN", "DSS-MS")
    size_order = ("IUT-k-SAN", "PF-CLSS-DV", "ECMSS", "LSanS", "PGUS-SBS", "DSS-MS")
    colors = {"DSS-MS": "C0", "IUT-k-SAN": "C1", "PF-CLSS-DV": "C2",
              "ECMSS": "C3", "LSanS": "C4", "PGUS-SBS": "C5"}

    def bar_style(scheme):
        color = colors[scheme]
        if scheme in reference_schemes:
            return {"facecolor": "white", "edgecolor": color, "hatch": "///", "linewidth": .85}
        return {"color": color}

    available = {row["scheme"] for row in baseline}
    schemes = [scheme for scheme in (*reference_schemes, *multi_schemes) if scheme in available]
    operations = ["Sign", "Sanitize", "Verify"]
    ecmss_only = ["Aggregate", "SubSanit"]
    timing = defaultdict(list)
    for row in baseline:
        if row["time_us"] != "NA":
            timing[row["scheme"], row["algorithm"]].append(float(row["time_us"]) / 1000)
    sizes = {r["scheme"]: int(r["signature_bytes"]) for r in baseline if r["algorithm"] == "Signature"}
    fig, (common, steps, signature) = plt.subplots(
        1, 3, figsize=(12.5, 3.65), width_ratios=[2.1, 1, 1.45], layout="constrained")
    width = .78 / max(len(schemes), 1)
    gap = .10 if available.intersection(reference_schemes) and available.intersection(multi_schemes) else 0
    for index, scheme in enumerate(schemes):
        offset = (index - (len(schemes) - 1) / 2) * width
        offset += gap / 2 if scheme in multi_schemes else -gap / 2
        points = [(i, stats(timing[scheme, op])) for i, op in enumerate(operations) if timing[scheme, op]]
        if points:
            common.bar([i + offset for i, _ in points], [mean for _, (mean, _) in points],
                       yerr=[ci for _, (_, ci) in points], width=width * .92, capsize=2,
                       label=scheme, **bar_style(scheme))
    common.set_xticks(range(len(operations)), operations)
    common.set_title("Signing, sanitization and verification")
    format_axis(common, "", "Time (ms)", logy=True)
    handles, labels = common.get_legend_handles_labels()
    if handles:
        common.legend(handles, labels, fontsize=7, ncols=3, loc="upper left")
    lo, hi = common.get_ylim()
    common.set_ylim(lo, hi * 5)

    for i, op in enumerate(ecmss_only):
        if timing["ECMSS", op]:
            mean, ci = stats(timing["ECMSS", op])
            steps.bar(i, mean, yerr=ci, width=.55, capsize=3, **bar_style("ECMSS"))
    steps.set_xticks(range(len(ecmss_only)), ["Aggregate", "Single-step\nsanitization"])
    steps.set_title("ECMSS")
    format_axis(steps, "", "Time (ms)")

    with_sizes = [scheme for scheme in size_order if scheme in sizes]
    if with_sizes:
        for scheme in with_sizes:
            signature.barh(scheme, sizes[scheme], **bar_style(scheme))
        signature.invert_yaxis()
        signature.set_xscale("log")
        signature.set_xlim(min(sizes.values()) * .6, max(sizes.values()) * 2)
        for i, scheme in enumerate(with_sizes):
            signature.annotate(f"{sizes[scheme]:,}", (sizes[scheme], i), xytext=(4, 0),
                               textcoords="offset points", va="center", fontsize=8)
    signature.set(xlabel="Bytes", title="Encoded signature size")
    signature.grid(axis="x", alpha=.22)
    save(fig, path, "06_baselines")


def tables(path, timing, baseline, sizes, history):
    exact = [r for r in sizes if r["kind"] == "parameter" and r["item"] in {"S_x", "manifest"}]
    with (path / "parameter_sizes.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, ["active_sanitizers", "epoch", "item", "bits", "bytes"], extrasaction="ignore")
        writer.writeheader()
        writer.writerows(sorted(exact, key=lambda r: (int(r["active_sanitizers"]), r["item"])))
    with (path / "signature_comparison.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, ["scheme", "message_blocks", "active_sanitizers", "signature_bytes", "source", "note"],
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(r for r in baseline if r["algorithm"] == "Signature")
    with (path / "history_summary.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["scenario", "trials", "pk_check_pass", "recovered"])
        for scenario in sorted({r["scenario"] for r in history}):
            data = [r for r in history if r["scenario"] == scenario]
            writer.writerow([scenario, len(data), sum(int(r["pk_check_pass"]) for r in data),
                             sum(int(r["recovered"]) for r in data)])
    groups = defaultdict(list)
    for r in timing:
        key = ("DSS-MS", r["sweep"], r["algorithm"], r["active_sanitizers"],
               r["active_after"], r["batch"], r["msg_bytes"], r["editable_blocks"])
        groups[key].append(float(r["time_us"]))
    for r in baseline:
        if r["algorithm"] != "Signature":
            key = (r["scheme"], "baseline", r["algorithm"], r["active_sanitizers"],
                   r["active_sanitizers"], "NA", r["msg_bytes"], "1")
            groups[key].append(float(r["time_us"]))
    with (path / "timing_summary.csv").open("w", newline="") as output:
        writer = csv.writer(output)
        writer.writerow(["scheme", "sweep", "algorithm", "active_sanitizers", "active_after", "batch", "msg_bytes",
                         "editable_blocks", "repeats", "mean_us", "sd_us", "ci95_lower_us", "ci95_upper_us"])
        for key, samples in groups.items():
            mean, ci = stats(samples)
            writer.writerow([*key, len(samples), mean, statistics.stdev(samples) if len(samples) > 1 else "NA",
                             mean - ci if len(samples) > 1 else "NA", mean + ci if len(samples) > 1 else "NA"])


def energy_plot(path):
    if not (path / "energy.csv").exists():
        return
    data = rows(path, "energy.csv")
    labels = sorted({(r["operation"], r["members"], r["batch"]) for r in data})
    points = [stats([float(r["energy_mj_per_operation"]) for r in data
                    if (r["operation"], r["members"], r["batch"]) == label]) for label in labels]
    if not points:
        return
    means, errors = zip(*points)
    fig, ax = plt.subplots(figsize=(max(5, len(labels)), 3.5), layout="constrained")
    ax.bar(range(len(labels)), means, yerr=errors, capsize=3)
    ax.set_xticks(range(len(labels)), [f"{op}\n{n} members, batch {b}" for op, n, b in labels],
                  rotation=30, ha="right")
    format_axis(ax, "", "Net energy (mJ per operation)")
    save(fig, path, "07_energy")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=Path(__file__).resolve().parent)
    parser.add_argument("--receivers", type=int, default=100, help="assumed manifest recipients in the fanout model")
    args = parser.parse_args()
    if args.receivers < 1 or not (args.directory / "complete.txt").is_file():
        parser.error("use a completed benchmark directory and a positive receiver count")
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "pdf.fonttype": 42,
                         "axes.spines.top": False, "axes.spines.right": False})
    path = args.directory
    timing, sizes, baseline, history = [rows(path, name) for name in
                                       ("timing.csv", "size_comm.csv", "baseline.csv", "gcd_history.csv")]
    sizes_plot(path, sizes)
    timing_plot(path, timing)
    membership_plot(path, timing)
    message_plot(path, timing)
    communication_plot(path, sizes, args.receivers)
    baseline_plot(path, baseline)
    tables(path, timing, baseline, sizes, history)
    energy_plot(path)


if __name__ == "__main__":
    main()
