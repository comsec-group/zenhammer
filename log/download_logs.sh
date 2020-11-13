#!/bin/bash

echo "Downloading files from cn003..."
scp -r pjattke@cn003:/local/home/pjattke/blacksmith/log .
mkdir -p cn003
mv log/* cn003/
rm -rf log

echo "Downloading files from testbed..."
scp -r patrick@testbed:~/blacksmith/log .
mkdir -p testbed
mv log/* testbed/
rm -rf log
