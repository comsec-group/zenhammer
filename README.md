# ZenHammer: Rowhammer Attacks on AMD Zen-based Platforms

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![contributions welcome](https://img.shields.io/badge/Contributions-welcome-lightgray.svg?style=flat)]() [![Preprint: arXiv](https://img.shields.io/badge/Preprint-COMSEC-orange.svg)](https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf) [![Paper](https://img.shields.io/badge/To%20appear%20in-Usenix%20Security%20'24-brightgreen.svg)](https://www.usenix.org/conference/usenixsecurity24/fall-accepted-papers) 

This repository provides the code accompanying the paper _[ZenHammer: Rowhammer Attacks on AMD Zen-based Platforms](https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf)_ that is to appear at USENIX Security 2024.

## Branches

This repository consists of multiple branches with different tools:

* [`dare`](https://github.com/comsec-group/zenhammer/tree/dare) contains the **DARE** tool to reverse-engineer DRAM address mappings.
* [`ddr4_zen2_zen3_pub`](https://github.com/comsec-group/zenhammer/tree/ddr4_zen2_zen3_pub) contains the ZenHammer Rowhammer fuzzer **for DDR4 (Zen 2 and Zen 3)**.
* [`ddr5_zen4_pub`](https://github.com/comsec-group/zenhammer/tree/ddr4_zen2_zen3_pub) contains the ZenHammer Rowhammer fuzzer **for DDR5 (Zen 4)**.

## Getting Started

Instructions to build and run DARE and the ZenHammer fuzzer are provided in the respective branches' `README.md` files.

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
