#!/bin/bash
for fn in $(find ../visualize/data/ -name "*.log");
do
    # DIMM ID
    DIMM=`echo ${fn} | cut -d'/' -f2`

    # number of successful patterns
    SUCC_PATTERNS=`pcregrep -M '\[\+\] Checking if any bit flips occurred.*\n.*\[0\;' ${fn} | awk 'NR % 2 != 1' | wc -l | xargs`

    # number of patterns
    NUM_PATTERNS=`cat ${fn} | grep "Running for pattern" | tail -n1 | cut -d' ' -f5 | xargs`

    # number of flips in total
    NUM_FLIPS=`grep -e "\[!\] Flip" ${fn} | wc -l | xargs`

    echo "${DIMM}, ${SUCC_PATTERNS}/${NUM_PATTERNS}, ${NUM_FLIPS}"
done
