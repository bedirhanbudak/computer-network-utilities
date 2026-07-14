#!/usr/bin/env python3

import argparse
import subprocess
import os
import re
import json
import time
import statistics
import matplotlib.pyplot as plt
import math
from pathlib import Path


# Regex parts
HOP_PART = r"\s*(\d+)"
HOST_PART = r"\s+([^\s]+)"
IP_PART = r"\s+\(([\d\.]+)\)"
OTHER_PART = r"(.*)"
EMPTY_PART = re.compile(r"\s*(\d+)\s+\*")

LINE_PATTERN = re.compile(HOP_PART + HOST_PART + IP_PART + OTHER_PART)
TIME_PATTERN = re.compile(r"([\d\.]+)\s+ms")

# Parse the traceroute output
def parse_output(output):
    stats = {}
    for line in output.splitlines():
        match = LINE_PATTERN.match(line)
        if match:
            hop = int(match.group(1))
            host = match.group(2)
            ip = match.group(3)
            others = match.group(4)
            times = [float(t) for t in TIME_PATTERN.findall(others)]

            if hop not in stats:
                stats[hop] = {"hosts": [[host, f"({ip})"]], "times": []}
            stats[hop]["times"].extend(times)

        else:
            asterisk = EMPTY_PART.match(line)
            if asterisk:
                hop = int(asterisk.group(1))
                if hop not in stats:
                    stats[hop] = {"hosts": [["*", "EMPTY"]], "times": []}
    return stats


# Calculate the statistics for each hop
def calc_stats(stats_all):
    sum_stats = []
    for hop in sorted(stats_all):
        hop_stats = stats_all[hop]
        times = hop_stats.get("times", [])

        if not times:
            sum_stats.append({
                "hop": hop,
                "hosts": hop_stats.get("hosts", [])
            })
            continue
        
        dict_stats = {
            "avg": float(sum(times) / len(times)),
            "hop": hop,
            "hosts": hop_stats.get("hosts", []),
            "max": float(max(times)),
            "med": float(statistics.median(times)),
            "min": float(min(times))
        }
        sum_stats.append(dict_stats)

    return sum_stats


# Create a boxplot graph and save it as a PDF
def create_plot(stats_all, graph_file):
    hops = sorted(stats_all)
    values = []

    for hop in hops:
        times = stats_all[hop]["times"]
        if times:
            values.append(times)
        else:
            values.append([math.nan])

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.boxplot(values, positions=hops, showfliers=False)
    ax.set_xlabel("Hop number")
    ax.set_ylabel("RTT (ms)")
    ax.set_title("Latency distribution per hop")
    ax.set_xticks(hops)
    fig.tight_layout()
    fig.savefig(str(graph_file), format="pdf")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Trstats.py")
    parser.add_argument("-n", type=int, required=True, help="Number of times traceroute will run")
    parser.add_argument("-d", type=int, required=True, help="Number of seconds to wait between two consecutive runs")
    parser.add_argument("-m", type=int, required=True, help="Number of max hops per traceroute run")
    parser.add_argument("-o", required=True, help="Path and name of output JSON file containing the stats")
    parser.add_argument("-g", required=True, help="Path and name of output PDF file containing stats graph")
    parser.add_argument("-t", help="A target domain name or IP address (required if --test is absent)")
    parser.add_argument("--test", help="Directory containing num_runs text files, each of which contains the output of a traceroute run. If present, this will override all other options and traceroute will not be invoked. Stats will be computed over the traceroute output stored in the text files")

    args = parser.parse_args()

    stats_all = {}

    # --test and -t commands
    if args.test:
        # Read from file
        for fname in os.listdir(args.test):
            with open(os.path.join(args.test, fname)) as f:
                parsed = parse_output(f.read())
                for hop, data in parsed.items():
                    entry = stats_all.setdefault(hop, {"hosts": [], "times": []})
                    for h in data["hosts"]:
                        if h not in entry["hosts"]:
                            entry["hosts"].append(h)
                    entry["times"].extend(data["times"])

    else:
        # Command line traceroute
        if not args.t:
            print("Please select a target using the -t parameter")
            return
        for _ in range(args.n):
            res = subprocess.run(
                ["traceroute", "-m", str(args.m), args.t],
                capture_output=True, text=True
            )
            parsed = parse_output(res.stdout)
            for hop, data in parsed.items():
                entry = stats_all.setdefault(hop, {"hosts": [], "times": []})
                for h in data["hosts"]:
                    if h not in entry["hosts"]:
                        entry["hosts"].append(h)
                entry["times"].extend(data["times"])
            time.sleep(args.d)


    # Calculate the statistics
    sum_stats = calc_stats(stats_all)

    # Save statistics as a JSON file
    json_f = args.o if args.o.endswith(".json") else args.o + ".json"
    Path(json_f).write_text(json.dumps(sum_stats, indent=2))

    # Generate the plot graph
    pdf_f = args.g if args.g.endswith(".pdf") else args.g + ".pdf"
    create_plot(stats_all, pdf_f)


if __name__ == "__main__":
    main()