# Blacksmith Rowhammer Fuzzer

[![Academic Code](https://img.shields.io/badge/Origin-Academic%20Code-C1ACA0.svg?style=flat)]() [![Language Badge](https://img.shields.io/badge/Made%20with-C/C++-blue.svg)](https://isocpp.org/std/the-standard) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![contributions welcome](https://img.shields.io/badge/Contributions-welcome-lightgray.svg?style=flat)]()

[![Preprint: arXiv](https://img.shields.io/badge/Preprint-arXiv:0000.0000-orange.svg)](arxiv.org/) [![Paper](https://img.shields.io/badge/To%20appear%20in-IEEE%20S&P%20'22-brightgreen.svg)](https://www.ieee-security.org/TC/SP2022) [![Funding](https://img.shields.io/badge/Grant-NCCR%20Automation%20(51NF40180545)-red.svg)](http://www.snf.ch/en/researchinFocus/nccr/automation/)

This repository provides the code accompanying the paper _[Blacksmith: Compromising Target Row Refresh by Rowhammering in the Frequency Domain]()_ that is to appear in IEEE S&P 2022.

This is the implementation of our Blacksmith Rowhammer fuzzer. This fuzzer crafts novel non-uniform Rowhammer access patterns based on the concepts of frequency, phase, and amplitude. Our evaluation on 40 DIMMs showed that it is able to bypass recent Target Row Refresh (TRR) in-DRAM mitigations effectively and as such can could trigger bit flips on all 40 tested DIMMs.

## Reproducibility

For facilitating the reproduction of our experiments, we following provide the commits we used to run the experiments. These commits are either based on the forked and extended [TRRespass](https://github.com/pjattke/trrespass-fork) codebase or our [Blacksmith](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith) codebase.

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

## Getting Started

Following, we quickly describe how to build and run Blacksmith.

### Prerequisites

Blacksmith has been tested on Ubuntu 18.04 LTS with Linux kernel 4.15.0. Prior building Blacksmith, the following packages need to be installed:

```bash
sudo apt install build-essential nlohmann-json-dev cmake libasmjit-dev
```

### Building Blacksmith

Note that the Blacksmith codebase also includes code for generating TRRespass-like n-sided patterns. Make sure that in `GlobalDefines.h` the following variables are set before proceeding:

```cpp
/// do synchronized hammering
#define USE_SYNC 1

// generate frequency-based patterns using fuzzing
#define USE_FREQUENCY_BASED_FUZZING 1
```

Then, you can build Blacksmith with the supplied `CMakeLists.txt` in a new `build` directory:

```bash
mkdir build \ 
  && cd build \
  && cmake .. \
  && make -j$(nproc)
```

Now we can run Blacksmith. For example, we can run Blacksmith in fuzzing mode by passing a random DIMM ID (e.g., `-dimm_id 1`; only used internally for logging into `stdout.log`), we limit the fuzzing to 6 hours (`-runtime_limit 21600`), pass the number of ranks of our current DIMM (`-num_ranks 1`) to select the proper bank/rank functions, and tell Blacksmith to do a sweep with the best found pattern after fuzzing finished (`-sweeping`): 

```bash
sudo ./blacksmith -dimm_id 1 -runtime_limit 21600 -num_ranks 1 -sweeping  
```

While Blacksmith is running, you can use `tail -f stdout.log` to keep track of the current progress (e.g., patterns, found bit flips). You will see a line like 
```
[!] Flip 0x2030486dcc, row 3090, page offset: 3532, from 8f to 8b, detected after 0 hours 6 minutes 6 seconds.
```
in case that a bit flip was found. After finishing the Blacksmith run, you can find a `fuzz-summary.json` that contains the information found in the stdout.log in a machine-processable format. In case you passed the `-sweeping` flag, you can additionally find a `sweep-summary-*.json` file that contains the information of the sweeping pass.

## Supported Parameters

Blacksmith supports the following command-line arguments.
Please note that `<integer>` in (e.g.) `-probes <integer>` is to be replaced by an integer, e.g., `-probes 10`.
Except the `dimm_id`, all parameters are optional.

```
==== Execution Modes ==============================================

-sweeping                       
    whether to do a sweep with the best pattern after fuzzing (when runtime_limit exceeded)
-generate_patterns              
    generates patterns only but skips hammering (used for ARM port only)    
-load_json <filepath>           
    loads a previously generated fuzz-summary.json from the given filepath       
-replay_patterns <pattern_ids>  
    takes a comma-separated list of pattern IDs that should be loaded (requires -load_json to be passed)

==== Execution-Specific Configuration =============================

-runtime_limit <integer>
    the time limit in second after which the fuzzing should stop 
-probes <integer>
    the number of different DRAM locations (i.e., rows) where a pattern should be tested on

==== DRAM-Specific Configuration ==================================

-num_ranks <1|2>                
    the number of ranks on the currently inserted DIMM; this is used to determine the bank/rank functions. 
    Note: functions are tailored to an i7-8700K, might be different on other CPUs 
-acts_per_ref <integer>         
    the number of ACTIVATEs we assume that are possible in a REFRESH interval (is automatically determined if not passed) 
-dimm_id <integer>
    the (internal) ID of the currently inserted DIMM, is only used for logging to stdout.log
```

The default values of the parameters can be found in the [`struct ProgramArguments`](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/blob/master/include/Blacksmith.hpp#L8).

## Additional Configuration

More configuration parameters of Blacksmith can be found in the [`GlobalDefines.hpp`](https://gitlab.ethz.ch/comsec/blacksmith-project/blacksmith/-/blob/master/include/GlobalDefines.hpp) file.

## Citing Blacksmith

**TODO**: Register DOI after releasing on Github as described [here](https://guides.github.com/activities/citable-code/).