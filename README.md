# ZenHammer Rowhammer Fuzzer

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![contributions welcome](https://img.shields.io/badge/Contributions-welcome-lightgray.svg?style=flat)]() [![Preprint: arXiv](https://img.shields.io/badge/Preprint-COMSEC-orange.svg)](https://comsec.ethz.ch/wp-content/files/zenhammer_usenix24.pdf) [![Paper](https://img.shields.io/badge/To%20appear%20in-Usenix%20Security%20'24-brightgreen.svg)](https://www.usenix.org/conference/usenixsecurity24/summer-accepted-papers) 

This repository provides the code accompanying the paper _[ZenHammer: Rowhammer Attacks on AMD Zen-based Platforms](https://comsec.ethz.ch/wp-content/files/zenhammer_sec24.pdf)_ that is to appear at USENIX Security 2024.

This is the implementation of our ZenHammer Rowhammer fuzzer **for DDR5 (Zen 4)**.

## Getting Started

Following, we quickly describe how to build and run ZenHammer.

### Prerequisites

ZenHammer has been tested on Ubuntu 20.04 LTS with Linux kernel 5.15.0. As the CMakeLists we ship with ZenHammer downloads all required dependencies at compile time, there is no need to install any package other than g++ (>= 8) and cmake (>= 3.14).

### Building ZenHammer

You can build ZenHammer with its supplied `CMakeLists.txt` in a new `build` directory:

```bash
mkdir build \ 
  && cd build \
  && cmake .. \
  && make -j$(nproc)
```

Now we can run ZenHammer. For example, we can run ZenHammer in fuzzing mode by passing a random DIMM ID (e.g., `--dimm-id 1`; only used internally for logging into `stdout.log`), we limit the fuzzing to 6 hours (`--runtime-limit 21600`), pass the number of ranks of our current DIMM (`--ranks 1`) to select the proper bank/rank functions, and tell ZenHammer to do a sweep with the best found pattern after fuzzing finished (`--sweeping`): 

```bash
sudo ./zenHammer --dimm-id 1 --runtime-limit 21600 --ranks 1 --sweeping  
```

While ZenHammer is running, you can use `tail -f stdout.log` to keep track of the current progress (e.g., patterns, found bit flips). You will see a line like 
```
[!] Flip 0x2030486dcc, row 3090, page offset: 3532, from 8f to 8b, detected after 0 hours 6 minutes 6 seconds.
```
in case that a bit flip was found. After finishing the ZenHammer run, you can find a `fuzz-summary.json` that contains the information found in the stdout.log in a machine-processable format. In case you passed the `--sweeping` flag, you can additionally find a `sweep-summary-*.json` file that contains the information of the sweeping pass.

## Supported Parameters

ZenHammer supports command-line arguments as described in detail by `./blacksmith -h`.
The following parameters are **mandatory** and must always be passed to ZenHammer:
```
==== Mandatory Parameters ==================================

    -d, --dimm-id <id>
        internal numeric identifier of the currently inserted DIMM (default: 0)
        
    -g, --geometry <#ranks,#bankgroups,#banks>
        a triple describing the DRAM geometry: #ranks, #bankgroups, #banks (e.g. '--geometry 2,8,4') 
```

The default values of the parameters can be found in the [`struct ProgramArguments`](include/ZenHammer.hpp#L8).

Configuration parameters of ZenHammer that we did not need to modify frequently, and thus are not runtime parameters, can be found in the [`GlobalDefines.hpp`](include/GlobalDefines.hpp) file.

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
