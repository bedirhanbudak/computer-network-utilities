#!/usr/bin/env python3

import argparse
import subprocess
import re
import json
import statistics
import matplotlib.pyplot as plt
from pathlib import Path


# Regex parts
TIME_PATTERN = re.compile(r"time=([\d\.]+)\s*ms")
PING_HEADER = re.compile(r"PING\s+([^\s]+)\s+\(([\d\.]+)\)")


# Parse the output
def parse_output(output):
    times = []
    host, ip = None, None
    for line in output.splitlines():
        if host is None:
            m = PING_HEADER.match(line)
            if m:
                host, ip = m.group(1), m.group(2)

        match = TIME_PATTERN.search(line)
        if match:
            times.append(float(match.group(1)))

    return times, host, ip


# Calculate the statistics
def calc_stats(times, host, ip):
    if not times:
        return [None]

    else:
        return [{
            "avg": float(sum(times) / len(times)),
            "hop": 0,
            "hosts": [[host, f"({ip})"]],
            "max": float(max(times)),
            "med": float(statistics.median(times)),
            "min": float(min(times))
        }]


# Create a boxplot graph and save it as a PDF
def create_plot(times, graph_file):
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.boxplot([times], positions=[0], patch_artist=True, showfliers=False)
    ax.set_xlabel("Hop number (no hop)")
    ax.set_ylabel("RTT (ms)")
    ax.set_title("Latency distribution")
    fig.tight_layout()
    fig.savefig(str(graph_file), format="pdf")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Pingstats.py")
    parser.add_argument("-d", type=int, required=True, help="Number of seconds to wait between two consecutive ping packets")
    parser.add_argument("-m", type=int, required=True, help="Number of max ping packets to send")
    parser.add_argument("-o", required=True, help="Path and name of output JSON file containing the stats")
    parser.add_argument("-g", required=True, help="Path and name of output PDF file containing stats graph")
    parser.add_argument("-t", required=True, help="Target host")

    args = parser.parse_args()

    # Run ping
    res = subprocess.run(
        ["ping", "-c", str(args.m), "-i", str(args.d), args.t],
        capture_output=True, text=True
    )

    times, host, ip = parse_output(res.stdout)
    sum_stats = calc_stats(times, host, ip)

    # Save results as a JSON file
    json_f = args.o if args.o.endswith(".json") else args.o + ".json"
    Path(json_f).write_text(json.dumps(sum_stats, indent=2))

    # Generate the plot graph
    pdf_f = args.g if args.g.endswith(".pdf") else args.g + ".pdf"
    create_plot(times, pdf_f)


if __name__ == "__main__":
    main()