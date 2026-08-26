#!/usr/bin/env python3
"""Print two `api-benchmark.py` result files side by side.

Two numbers per operation per room size, and the ratio between them. Reports
the *growth* separately from the absolute cost, because they answer different
questions: the ratio says which server is faster today, and the growth says
which one will still be fast in a room ten times the size. SPEC 18.1's claims
are all of the second kind.
"""

import argparse
import json


def load(path):
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    results = {}
    for key, value in document["benchmarks"].items():
        name, size = key.rsplit("/", 1)
        results.setdefault(name, {})[int(size)] = value["mean_ns"] / 1e6
    return document.get("server", path), results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first")
    parser.add_argument("second")
    args = parser.parse_args()

    name_a, a = load(args.first)
    name_b, b = load(args.second)
    shared = sorted(set(a) & set(b))
    if not shared:
        print("no operations in common")
        return 1
    sizes = sorted(set(a[shared[0]]) & set(b[shared[0]]))

    print(f"milliseconds, mean; lower is better ({name_a} vs {name_b})\n")
    header = "operation".ljust(16)
    for size in sizes:
        header += f"{name_a[:7]}@{size}".rjust(14) + f"{name_b[:7]}@{size}".rjust(14) + "ratio".rjust(9)
    print(header)
    for name in shared:
        row = name.ljust(16)
        for size in sizes:
            first, second = a[name][size], b[name][size]
            row += f"{first:14.3f}{second:14.3f}{second / first:8.1f}x"
        print(row)

    print(f"\ngrowth from {sizes[0]} to {sizes[-1]} events (flat is the claim):")
    for name in shared:
        ga = a[name][sizes[-1]] / a[name][sizes[0]]
        gb = b[name][sizes[-1]] / b[name][sizes[0]]
        print(f"  {name:16} {name_a:10} {ga:5.2f}x   {name_b:10} {gb:5.2f}x")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
