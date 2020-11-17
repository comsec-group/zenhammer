#!/bin/bash

cd ../log

HOST_NAMES=("ee-tik-cn003" "pc-10835")
HOST_PATHS=("/local/home/pjattke/blacksmith/log" "/home/patrick/blacksmith/log")
HOST_USERNAMES=("pjattke" "patrick")

for i in {0..1}
do
    echo "Downloading files from "${HOST_NAMES[$i]}"..."
    scp -r ${HOST_USERNAMES[$i]}@${HOST_NAMES[$i]}:${HOST_PATHS[$i]}/${HOST_NAMES[$i]} .
    mkdir -p ${HOST_NAMES[$i]}
    mv log/* ${HOST_NAMES[$i]}/
    rm -rf log
done

# echo "Downloading files from cn003..."
# scp -r pjattke@cn003:/local/home/pjattke/blacksmith/log .
# mkdir -p cn003
# mv log/* cn003/
# rm -rf log

# echo "Downloading files from testbed..."
# scp -r patrick@testbed:~/blacksmith/log .
# mkdir -p testbed
# mv log/* testbed/
# rm -rf log
