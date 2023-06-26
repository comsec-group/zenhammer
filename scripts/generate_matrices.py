#!/usr/bin/env python3
from argparse import ArgumentParser, ArgumentTypeError
import numpy as np
import sys


def get_args():
    def hex_addr_func(input: str):
        try:
            func = int(input, 16)
        except ValueError:
            raise ArgumentTypeError("Address function needs to be specified as hexdecimal mask value, e.g., 0x0c3200.")
        return func

    parser = ArgumentParser(prog="generate_matrices.py")
    parser.add_argument("--bits", help="matrix bits (e.g., 30 for 1 Gib = 2^30 bytes)", required=True, type=int)
    parser.add_argument("--sc", help="subchannel (SC) function", type=hex_addr_func)
    parser.add_argument("--rk", help="rank (RK) function", type=hex_addr_func)
    parser.add_argument("--bg", help="bank group (BG) functions", nargs="+", type=hex_addr_func)
    parser.add_argument("--ba", help="bank address (BA) functions", nargs="+", type=hex_addr_func)
    parser.add_argument("--row", help="row (ROW) mask", type=hex_addr_func, required=True)
    parser.add_argument("--col", help="col (COL) mask", type=hex_addr_func, required=True)
    return parser.parse_args()


def print_matrix(matrix, labels):
    for i in range(len(matrix)):
        print(f"{labels[i]:>9s}", end="")
        for j in range(len(matrix)):
            print(f" {matrix[i,j]}", end="")
        print()


if __name__ == "__main__":
    args = get_args()
    
    size = args.bits
    print(f"Generating matrices with size of {size} address bits.")
    size_mask = (1 << size) - 1

    sc_func = args.sc
    rk_func = args.rk
    bg_funcs = args.bg
    ba_funcs = args.ba
    row_mask = args.row
    col_mask = args.col

    print("I was given the following functions:")
    for label, func in [("sc", sc_func), ("RK", rk_func)]:
        if func is None:
            print(f"  {label:>3s}: (none)")
        else:
            print(f"  {label:>3s}: 0x{func:09x}")
    for label, funcs in [("BG", bg_funcs), ("BA", ba_funcs)]:
        if len(funcs) == 0:
            print(f"  {label:>3s}: (none)")
        else:
            for i, func in enumerate(funcs):
                print(f"  {label:>2s}{i}: 0x{func:09x}")
    for label, mask in [("ROW", row_mask), ("COL", col_mask)]:
        print(f"  {label:>3s}: 0x{mask:09x} (mask)")
    print()
    
    matrix = []
    labels = []

    col_shift = len(matrix)
    col_idx = 0
    for i in range(size):
        func = 1 << i
        if col_mask & func:
            matrix.append(func)
            labels.append(f"col_b{col_idx}")
            col_idx += 1
    col_mask = (1 << (len(matrix) - col_shift)) - 1

    row_shift = len(matrix)
    row_idx = 0
    for i in range(size):
        func = 1 << i
        if row_mask & func:
            matrix.append(func)
            labels.append(f"row_b{row_idx}")
            row_idx += 1
    row_mask = (1 << (len(matrix) - row_shift)) - 1

    ba_shift = len(matrix)
    for i, func in enumerate(ba_funcs):
        matrix.append(func & size_mask)
        labels.append(f"ba_b{i}")
    ba_mask = (1 << (len(matrix) - ba_shift)) - 1

    bg_shift = len(matrix)
    for i, func in enumerate(bg_funcs):
        matrix.append(func & size_mask)
        labels.append(f"bg_b{i}")
    bg_mask = (1 << (len(matrix) - bg_shift)) - 1

    rk_shift = len(matrix)
    if rk_func is not None:
        matrix.append(rk_func & size_mask)
        labels.append("rk_b0")
    rk_mask = (1 << (len(matrix) - rk_shift)) - 1

    sc_shift = len(matrix)
    if sc_func is not None:
        matrix.append(sc_func & size_mask)
        labels.append("sc_b0")
    sc_mask = (1 << (len(matrix) - sc_shift)) - 1

    # Reverse order of matrix.
    dram_matrix = matrix[::-1]
    dram_labels = labels[::-1]

    if len(dram_matrix) != size:
        print(f"Error: Specified {size} address bits, but {len(dram_matrix)} functions were given.")
        sys.exit(1)

    np_dram_matrix = np.array([[(func >> i) & 0x1 for i in range(size)][::-1] for func in dram_matrix])
    print("=== DRAM matrix ===")
    print_matrix(np_dram_matrix, dram_labels)
    print()

    # Invert DRAM matrix to get address matrix.
    try:
        np_addr_matrix = np.mod(np.linalg.inv(np_dram_matrix), 2).astype(np.uint64)
    except np.linalg.LinAlgError as err:
        print(f"Error while inverting matrix: {err}")
        sys.exit(1)

    addr_labels = [f"addr b{bit}" for bit in range(size - 1, -1, -1)]

    # Verify the matrices are inverses of each other.
    product = np.mod(np_dram_matrix @ np_addr_matrix, 2)
    assert np.array_equal(product, np.eye(size)), "DRAM and address matrices are inverses of each other."

    print("=== Address matrix ===")
    print_matrix(np_addr_matrix, addr_labels)
    print()

    # Converting numpy matrix back into list of integers.
    addr_matrix = []
    for row in np_addr_matrix:
        value = 0
        for col in row:
            value <<= 1
            value |= int(col)
        addr_matrix.append(value)

    print("Generating detailed labels...")

    dram_full_labels = []
    for func, label in zip(dram_matrix, dram_labels):
        contributors = [l for i, l in enumerate(addr_labels[::-1]) if (1 << i) & func][::-1]
        contributors = [c[5:] for c in contributors]
        full_label = f"{label} = addr {' '.join(contributors)}"
        dram_full_labels.append(full_label)
    
    addr_full_labels = []
    for func, label in zip(addr_matrix, addr_labels):
        contributors = [l for i, l in enumerate(dram_labels[::-1]) if (1 << i) & func][::-1]
        full_label = f"{label} = {' '.join(contributors)}"
        addr_full_labels.append(full_label)
    
    print("Generating C++ code...")
    print()

    print("struct MemConfiguration config = {")
    print("  .IDENTIFIER = /* TODO */,")
    print()
    print(f"  .SC_SHIFT = {sc_shift},")
    print(f"  .SC_MASK = 0b{sc_mask:b},")
    print(f"  .RK_SHIFT = {rk_shift},")
    print(f"  .RK_MASK = 0b{rk_mask:b},")
    print(f"  .BG_SHIFT = {bg_shift},")
    print(f"  .BG_MASK = 0b{bg_mask:b},")
    print(f"  .BK_SHIFT = {ba_shift},")
    print(f"  .BK_MASK = 0b{ba_mask:b},")
    print(f"  .ROW_SHIFT = {row_shift},")
    print(f"  .ROW_MASK = 0b{row_mask:b},")
    print(f"  .COL_SHIFT = {col_shift},")
    print(f"  .COL_MASK = 0b{col_mask:b},")
    print()
    print("  .DRAM_MTX = {")
    for row, label in zip(dram_matrix, dram_full_labels):
        print(("    0b{:0%db},  // {}" % size).format(row, label))
    print("  },")
    print()
    print("  .ADDR_MTX = {")
    for row, label in zip(addr_matrix, addr_full_labels):
        print(("    0b{:0%db},  // {}" % size).format(row, label))
    print("  },")
    print("};")
