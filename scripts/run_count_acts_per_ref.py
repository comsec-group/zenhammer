#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import datetime
import pathlib
import time

import yaml

yaml_filepath = pathlib.Path(sys.argv[1]).absolute()

EXP_ROOT = pathlib.Path("/data/pjattke/ddr5/act_count_experiments/")
BLACKSMITH_ROOT = pathlib.Path("/local/home/pjattke/dev/blacksmith/")
build_dir = pathlib.Path(BLACKSMITH_ROOT, "build/")
files_to_copy = ["stdout.log", "result.txt"]

# create experiment timestamped directory
ts = datetime.datetime.now().replace(microsecond=0).isoformat()
target_dir = EXP_ROOT.joinpath(ts)
print(f"[+] Creating experiment directory: {target_dir}")
os.makedirs(target_dir, exist_ok=True)

# build blacksmith
os.chdir(BLACKSMITH_ROOT)
shutil.rmtree(build_dir, ignore_errors=True)
shutil.rmtree(BLACKSMITH_ROOT.joinpath("CMakeFiles/"), ignore_errors=True)
try:
    for f in ['build.ninja', 'stdout.log', 'CMakeCache.txt']:
        os.remove(BLACKSMITH_ROOT.joinpath(f))
except:
    pass
os.mkdir("build")
os.chdir("build")
subprocess.Popen("cmake -G Ninja ..", shell=True).wait()
subprocess.Popen("cmake --build .", shell=True).wait()

# copy targets.txt and mapping.txt for DIMM
DIMM_ID = 504
shutil.copy(f"/data/pjattke/ddr5/rowlists/alderlake/dimm_{DIMM_ID}_4bg_4bk/targets.txt", build_dir)
shutil.copy(f"/data/pjattke/ddr5/rowlists/alderlake/dimm_{DIMM_ID}_4bg_4bk/mapping.txt", build_dir)

# read yaml, iterate over all configurations
with open(yaml_filepath) as f:
    yml = yaml.safe_load(f)

    for exp_cfg in yml['experiment_configs']:
        os.chdir(build_dir)
        cfg_id = exp_cfg['config_id']
        print("Processing config #", cfg_id, sep="")

        # create subdirectory for experiment result
        exm = exp_cfg['execution_mode']
        rnds = exp_cfg['num_measurement_rounds']
        syncrows = exp_cfg['num_sync_rows']
        rdist = exp_cfg['row_distance']
        ro_sbg = int(exp_cfg['row_origin']['same_bg'])
        ro_sbk = int(exp_cfg['row_origin']['same_bk'])
        target_subdir = f"expcfg.{cfg_id:02d}__exm.{exm}__syncrows.{syncrows}__rdist.{rdist}__ro-sbgbk.{ro_sbg}{ro_sbk}__rnds.{rnds:07d}"
        exp_home = pathlib.Path(EXP_ROOT, target_dir, target_subdir)
        os.mkdir(exp_home)

        # wait 10 tREFW
        time.sleep(0.32)

        # run blacksmith with yml path and config no
        stdout_file = open("result.txt", "w")
        BS_WORKLOAD = subprocess.Popen(
            "sudo taskset -c 0 ./blacksmith "
            f"--dimm-id {DIMM_ID} "
            "--rowlist targets.txt "
            "--rowlist-bgbk mapping.txt "
            "--runtime-limit 9999 "
            f"--exp-cfg {yaml_filepath} "
            f"--exp-cfg-id {cfg_id}"
            , shell=True, stdout=stdout_file)
        BS_WORKLOAD.wait()
        stdout_file.close()

        if BS_WORKLOAD.returncode != 0:
            print(f"[-] Blacksmith returned error code: {BS_WORKLOAD.returncode}")
            exit(-1)

        # copy result file to subdirectory
        for filename in files_to_copy:
            shutil.copy(pathlib.Path(os.getcwd(), filename), exp_home)

        # plot results using plot_timing_count_acts_per_ref.py
        os.chdir(pathlib.Path("../scripts"))
        subprocess.Popen(f"source ../venv/bin/activate && python3 plot_timing_count_acts_per_ref.py {pathlib.Path(exp_home, 'result.txt')}", shell=True, executable='/bin/bash').wait()
        shutil.copy("plot.pdf", exp_home)
