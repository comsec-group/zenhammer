# DARE (ZenHammer)

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![contributions welcome](https://img.shields.io/badge/Contributions-welcome-lightgray.svg?style=flat)]() [![Preprint: arXiv](https://img.shields.io/badge/Preprint-COMSEC-orange.svg)](https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf) [![Paper](https://img.shields.io/badge/To%20appear%20in-Usenix%20Security%20'24-brightgreen.svg)](https://www.usenix.org/conference/usenixsecurity24/fall-accepted-papers) 

This repository provides the code accompanying the paper _[ZenHammer: Rowhammer Attacks on AMD Zen-based Platforms](https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf)_ that is to appear at USENIX Security 2024.

This is the implementation of the **DARE (<ins>D</ins>RAM <ins>A</ins>ddress Mapping <ins>R</ins>everse <ins>E</ins>ngineering)** tool.
DARE is described in detail in the [paper](https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf).

## Usage

To use DARE, two steps are required.

### Obtaining Offset

First, the offset between physical and DRAM addresses needs to be obtained, which is later passed to the DARE tool.
To determine the offset, run the script `./scripts/get_amd_zen_offset.py`, passing the contents of `/proc/iomem` as input:
```sh
sudo cat /proc/iomem | ./scripts/get_amd_zen_offset.py
```
This script will report an offset in MiB, which needs to be passed to `dare` as shown below.

> This step is only required for AMD Zen-based CPUs.
> For other CPUs, using a zero offset is usually correct.

### Running DARE

Second, run the main DARE tool.
Install dependencies and run the tool as described below.

Set `--superpages` to the maximum number of superpages available on the system, and ``--clusters`` to the expected number of clusters (banks * bank groups * ranks * ...).
Use the previously obtained offset (in MiB) for the `--offset` argument.

```sh
# Install the required tools
sudo apt install g++ make cmake

# Configure and compile the executable
cmake -B build
make -C build

# Disable CPU frequency boost which can influence measurements
./scripts/disable_frequency_boost.sh

# Run the tool with the required parameters (adjust as needed for the system)
sudo ./build/dare --superpages 12 --clusters 64 --offset 768
```
DARE will now run and display the functions found at the end.

## High-Level Overview

The tool performs the following steps:

1. The specified number of 1 GiB superpages is allocated.
2. The *row conflict threshold* is determined.
For this, random pairs of addresses are timed.
Depending on the number of clusters specified (using the `--clusters` argument), the threshold is picked such that `1 / #clusters` of all samples is above the threshold.
Alternatively, the threshold can be specified on the command line using the `--threshold` argument, in which case this step is skipped.
3. Clusters are built from an address pool.
A needle is picked, and all addresses in the pool are checked for row conflicts with the needle (in which case they belong to the same cluster).
This is repeated until the specified number of clusters have been built.
4. The clusters are cleaned by checking that all addresses in the cluster conflict with (almost) all other addresses in the same cluster.
Any address where this is not the case is removed from the cluster.
5. (Optional) The clusters are dumped to a CSV file if the `--out` parameter is specified.
6. Possible candidate functions are brute-forced.
This is done for different physical-to-DRAM offsets (i.e., 0 MiB, 256 MiB, ...).
All possible functions with at most `BRUTE_FORCE_MAX_BITS` contributing bits are generated and checked over the sets.
If a function evaluates to the same value each set individually, and is 0 and 1 on half the sets each, it is accepted.
7. Linearly dependent functions are removed from the result.

The tool requires superuser privileges to translate virtual to physical addresses.
Use as many 1 GiB superpages as the system allows for to maximize accuracy.

## Citing our Work

To cite ZenHammer in academic papers, please use the following BibTeX entry:

```
@inproceedings{jattke.wipfli2024zenhammer,
  title={{{ZenHammer}}: {{R}}owhammer {{A}}ttacks on {{AMD}} {{Z}}en-based {{P}}latforms},
  author={Jattke, Patrick and Wipfli, Max and Solt, Flavien and Marazzi, Michele and Bölcskei, Matej and Razavi, Kaveh},
  booktitle={USENIX Security},
  year={2024},
  month = aug,
  note = {\url{https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf}}
}
```
