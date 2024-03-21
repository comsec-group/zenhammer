#!/usr/bin/env python3
import sys
from argparse import ArgumentParser
from pathlib import Path


MiB = 1024**2
GiB = 1024**3

TERM_BOLD = "\033[1m"
TERM_RESET = "\033[0m"


def main():
    parser = ArgumentParser(prog="parse_iomem.py")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "iomem_file", nargs="?", help="/proc/iomem dump file (optional, reads from STDIN if not provided)"
    )
    args = parser.parse_args()

    iomem_path = Path(args.iomem_file if args.iomem_file else "/dev/stdin")

    entries = []

    with iomem_path.open("r") as f:
        for line in f:
            # Ignore all entries not on the top level.
            if line.startswith(" "):
                continue
            entry = line.rstrip("\n")
            addr_range, name = entry.split(" : ")
            start, end = addr_range.split("-")
            start = int(start, 16)
            end = int(end, 16) + 1
            entries.append((start, end, name))

    if args.verbose:
        print(f"Read {len(entries)} top-level entries from '{iomem_path.name}':")
        for start, end, name in entries:
            print(f"  [{start / GiB:6.3f},{end / GiB:6.3f}) {name}")

    # Find first "PCI Bus" entry.
    offset = None
    for start, end, name in entries:
        if not name.startswith("PCI Bus"):
            continue
        # Found it.
        print("First PCI bus memory range is:")
        print(f"  [{start / GiB:6.3f},{end / GiB:6.3f}) {name}")
        offset = 4 * GiB - start
        break

    if offset is None:
        print("Error: Could not find PCI bus memory range below 4 GiB. Cannot continue.")
        sys.exit(1)

    print(f"The most likely address offset is {TERM_BOLD}{offset // MiB} MiB{TERM_RESET} ({offset} bytes).")
    print(
        "Warning: This tool is only designed to work on AMD Zen systems. For other systems, consider using an offset of 0."
    )
    print(f"Make DARE consider this using the following command line option: --offset {offset // MiB}")


if __name__ == "__main__":
    main()
