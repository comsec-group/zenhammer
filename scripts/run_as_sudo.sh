#!/bin/bash
cd ../cmake-build-debug-pc-10835 || return
#echo "$1" | sudo -S chown root:root blacksmith
#echo "$1" | sudo -S chmod a+s blacksmith

sudo chown root:root blacksmith
sudo chmod a+s blacksmith
