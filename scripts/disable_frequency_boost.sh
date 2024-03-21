#!/bin/sh
# This script disables the CPU frequency boost on Intel and AMD systems using
# the respective sysfs drivers.

# https://www.kernel.org/doc/Documentation/cpu-freq/intel-pstate.txt
INTEL_PSTATE="/sys/devices/system/cpu/intel_pstate/no_turbo"
# https://www.kernel.org/doc/Documentation/cpu-freq/boost.txt
CPUFREQ_BOOST="/sys/devices/system/cpu/cpufreq/boost"

if [ -f "$INTEL_PSTATE" ]; then
    echo "'intel_pstate' driver found."
    echo "1" | sudo tee "$INTEL_PSTATE"
elif [ -f "$CPUFREQ_BOOST" ]; then
    echo "'cpufreq/boost' found."
    echo "0" | sudo tee "$CPUFREQ_BOOST"
else
    echo "Error: No supported driver available."
    exit 1
fi

echo "Frequency boost disabled successfully."
