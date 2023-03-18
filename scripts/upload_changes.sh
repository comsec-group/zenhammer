#!/bin/bash

hosts=(ee-tik-cn115 ee-tik-cn121 ee-tik-cn123 ee-tik-cn124)
#hosts=(ee-tik-cn115)

for h in "${hosts[@]}"; do
  ssh ${h}.ethz.ch <<'EOF'
declare id=$(grep DIMM_ID ~/git/blacksmith/run_benchmark.sh | head -1 | cut -d= -f2 | tr -d '"')
cd ~/git/blacksmith/build
TIMESTAMP="20230317125037"
DEST="/data/pjattke/ddr5/blacksmith/20230317T010727_3441e1352424dba97e040b4d99f4a188cef2c55a/DIMM_${id}/${TIMESTAMP}_${HOSTNAME}"
sudo -u "pjattke" mkdir -p "${DEST}"
FILE_STDOUT=stdout.log
FILES=("stdout.log" "fuzz-summary.json")
if test -f "${FILE_STDOUT}"; then
  for file in "${FILES[@]}"; do
    sudo -u "pjattke" cp "${file}" "${DEST}/"
  done
fi
EOF
done

