# Blacksmith Rowhammer Fuzzer

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![contributions welcome](https://img.shields.io/badge/Contributions-welcome-lightgray.svg?style=flat)]()

[![Preprint: arXiv](https://img.shields.io/badge/Preprint-COMSEC-orange.svg)](https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf) [![Paper](https://img.shields.io/badge/To%20appear%20in-IEEE%20S&P%20'22-brightgreen.svg)](https://www.ieee-security.org/TC/SP2022/program-papers.html) [![Funding](https://img.shields.io/badge/Grant-NCCR%20Automation%20(51NF40180545)-red.svg)](https://nccr-automation.ch/)

This repository provides the code accompanying the paper _[Blacksmith: Scalable Rowhammering in the Frequency Domain](https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf)_ that is to appear in the IEEE conference Security & Privacy (S&P) 2022.

This is the implementation of our Blacksmith Rowhammer fuzzer. This fuzzer crafts novel non-uniform Rowhammer access patterns based on the concepts of frequency, phase, and amplitude. Our evaluation on 40 DIMMs showed that it is able to bypass recent Target Row Refresh (TRR) in-DRAM mitigations effectively and as such can could trigger bit flips on all 40 tested DIMMs.

## Getting Started

Following, we quickly describe how to build and run Blacksmith.

### Prerequisites

Blacksmith has been tested on Ubuntu 18.04 LTS with Linux kernel 4.15.0. As the CMakeLists we ship with Blacksmith downloads all required dependencies at compile time, there is no need to install any package other than g++ (>= 8) and cmake (>= 3.14).

To facilitate the development, we also provide a Docker container (see [Dockerfile](docker/Dockerfile)) where all required tools and libraries are installed. This container can be configured, for example, as remote host in the CLion IDE, which automatically transfers the files via SSH to the Docker container (i.e., no manual mapping required).

### Building Blacksmith

You can build Blacksmith with its supplied `CMakeLists.txt` in a new `build` directory:

```bash
mkdir build \ 
  && cd build \
  && cmake .. \
  && make -j$(nproc)
```

Now we can run Blacksmith. For example, we can run Blacksmith in fuzzing mode by passing a random DIMM ID (e.g., `--dimm-id 1`; only used internally for logging into `stdout.log`), we limit the fuzzing to 6 hours (`--runtime-limit 21600`), pass the number of ranks of our current DIMM (`--ranks 1`) to select the proper bank/rank functions, and tell Blacksmith to do a sweep with the best found pattern after fuzzing finished (`--sweeping`): 

```bash
sudo ./blacksmith --dimm-id 1 --runtime-limit 21600 --ranks 1 --sweeping  
```

While Blacksmith is running, you can use `tail -f stdout.log` to keep track of the current progress (e.g., patterns, found bit flips). You will see a line like 
```
[!] Flip 0x2030486dcc, row 3090, page offset: 3532, from 8f to 8b, detected after 0 hours 6 minutes 6 seconds.
```
in case that a bit flip was found. After finishing the Blacksmith run, you can find a `fuzz-summary.json` that contains the information found in the stdout.log in a machine-processable format. In case you passed the `--sweeping` flag, you can additionally find a `sweep-summary-*.json` file that contains the information of the sweeping pass.

## Supported Parameters

Blacksmith supports the command-line arguments listed in the following.
Except for the parameters `--dimm-id` and `--ranks` all other parameters are optional.

```
    -h, --help
        shows this help message

==== Mandatory Parameters ==================================

    -d, --dimm-id
        internal identifier of the currently inserted DIMM (default: 0)
    
==== Execution Modes ==============================================

    -f, --fuzzing
        perform a fuzzing run (default program mode)        
    -g, --generate-patterns
        generates N patterns, but does not perform hammering; used by ARM port
    -y, --replay-patterns <csv-list>
        replays patterns given as comma-separated list of pattern IDs

==== Replaying-Specific Configuration =============================

    -j, --load-json
        loads the specified JSON file generated in a previous fuzzer run, required for --replay-patterns
        
==== Fuzzing-Specific Configuration =============================

    -s, --sync
        synchronize with REFRESH while hammering (default: 1)
    -w, --sweeping
        sweep the best pattern over a contig. memory area after fuzzing (default: 0)
    -t, --runtime-limit
        number of seconds to run the fuzzer before sweeping/terminating (default: 120)
    -a, --acts-per-ref
        number of activations in a tREF interval, i.e., 7.8us (default: None)
    -p, --probes
        number of different DRAM locations to try each pattern on (default: NUM_BANKS/4)

```

The default values of the parameters can be found in the [`struct ProgramArguments`](include/Blacksmith.hpp#L8).

Configuration parameters of Blacksmith that we did not need to modify frequently, and thus are not runtime parameters, can be found in the [`GlobalDefines.hpp`](include/GlobalDefines.hpp) file.

## Blacksmith Experiments

For facilitating the reproduction of the experiments of our paper, we following provide the commits we used to run the experiments. These commits are either based on the forked and extended [TRRespass](https://github.com/pjattke/trrespass-fork) codebase or our [Blacksmith](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith) codebase.

- Section III-A: Are non-uniform accesses effective to bypass mitigations
  - Codebase: TRRespass
  - Commit: [86acbcc7cd3fb8536c52e32d9f91db585ea059a7](https://github.com/pjattke/trrespass-fork/commit/86acbcc7cd3fb8536c52e32d9f91db585ea059a7)
  - Function: [`hammer-suite.c::fuzz_random`](https://github.com/pjattke/trrespass-fork/blob/main/hammersuite/src/hammer-suite.c#L998)


- Section III-B: When should we hammer and for how long?
  - Codebase: TRRespass
  - Commit: [985c5626bb41e86899c2d80e8797f4d212b2f23c](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/commit/985c5626bb41e86899c2d80e8797f4d212b2f23c)
  - Function: [`TraditionalHammerer::n_sided_hammer_experiment`](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/blob/985c5626bb41e86899c2d80e8797f4d212b2f23c/src/Forges/TraditionalHammerer.cpp#L77)


- Section III-C: Should our patterns be longer than one refresh interval?
  - Codebase: Blacksmith
  - Commit: [17163fc769c6abd9ea8d1d5042e2763f4c502efe](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/commit/17163fc769c6abd9ea8d1d5042e2763f4c502efe)
  - Function: [`TraditionalHammerer::n_sided_hammer_experiment_frequencies`](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/blob/17163fc769c6abd9ea8d1d5042e2763f4c502efe/src/Forges/TraditionalHammerer.cpp#L314)


- Section V-B: Blacksmith Results on DDR4
  - Codebase: Blacksmith
  - Commit: [2073e0a769fe8211bb8b61ee4e6946cb3ae8c1b3](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/commit/2073e0a769fe8211bb8b61ee4e6946cb3ae8c1b3)
  - Function: [`FuzzyHammerer::n_sided_frequency_based_hammering`](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/blob/master/src/Forges/FuzzyHammerer.cpp#L18)


- Section V-D: Blacksmith on LPDDR4X
  - Codebase: Blacksmith
  - Code is not publicly available but code is derived from commit [432511d5](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/commit/432511d5a23e9fa594d103972889bc18f24a319b)

Upon request, we can provide the collected data (stdout.log, JSON) of these experiments/runs.

## Citing our Work

To cite Blacksmith in academic papers, please use the following BibTeX entry:

```
@inproceedings{jattke2021blacksmith,
  title = {{{BLACKSMITH}}: Rowhammering in the {{Frequency Domain}}},
  shorttitle = {Blacksmith},
  booktitle = {{{IEEE S}}\&{{P}} '22},
  author = {Jattke, Patrick and {van der Veen}, Victor and Frigo, Pietro and Gunter, Stijn and Razavi, Kaveh},
  year = {2021},
  month = nov,
  note = {\url{https://comsec.ethz.ch/wp-content/files/blacksmith_sp22.pdf}}
}
```
