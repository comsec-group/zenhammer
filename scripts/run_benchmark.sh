#!/bin/bash

# Stop on error
set -e
# Stop on unitialized variables
set -u
# Stop on failed pipes
set -o pipefail

echo "Not implemented yet!"
exit

# define target hosts where benchmark should be executed on
NUM_HOSTS=2
declare -a HOSTS=("pc-10835.ethz.ch" "cn104-ee-tik.ethz.ch" )
declare -a DIMM_IDS=(23)

for i in $(seq 1 $NUM_HOSTS);
do
  # TODO: Think about if we really want to use scp (directory might be dirty) or use git
  # copy blacksmith project to remote via SSH
  scp ../../blacksmith host:~/

  # run scripts/execute_remotely.sh via ssh in new tmux session
  ssh -t HOSTS[$i] "tmux new-session -d -s my_session 'cd ~/blacksmith/scripts && ./run_benchmark.sh'"
done


# TODO: Think about how we can transfer DIMM ID to remote host, e.g., via file?
#  An alternative could be just passing it via the SSH comand itself or via SendEnv
#  (see https://superuser.com/a/702751/205044)

# move to: scripts/execute_remotely.sh ###########################

# create a new timestamp
TIMESTAMP=`date +"%Y%m%d_%H%M%S"`

# run cmake . && make
cd ~/blacksmith && cmake . && make

# start the benchmark and write stdout to file + JSON export
sudo ./blacksmith | tee ${TIMESTAMP}.log

# upload results to S3 bucket into a folder called "timestamp_hostname"
# note: the credentials only have permission to upload data
export AWS_ACCESS_KEY_ID=AKIATAXHUSSXZXDFXL4S
export AWS_SECRET_ACCESS_KEY=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
export AWS_DEFAULT_REGION=us-east-2
S3_TARGET=s3://blacksmith-evaluation/DIMM_"${DIMM_ID}"/"$(TIMESTAMP)"_"$(HOSTNAME)"/
aws s3 cp stdout.txt ${S3_TARGET}
aws s3 cp export.json ${S3_TARGET}
