#! /usr/bin/python3
import shutil
import sys
import random
from pathlib import Path, PurePosixPath
from time import sleep

from dimm_db import DimmDb
from hammerpatt import *
import glob
import os
import ujson as json

from s3utils import get_folder_in_s3_path, get_file, download_file_to


def create_folder(directory: str):
    if os.path.exists(directory):
        return
    try:
        print("[+] Creating folder {}".format(directory))
        os.makedirs(directory)
    except OSError:
        print("Creation of the directory '{}' failed.".format(directory))


def generate_plots(filepath: str):
    patterns = InstanceList()

    with open(filepath, "r") as f:
        data = json.load(f)

    for x in data:
        patterns.append(HammeringPattern.from_json(x))

    # determine instances where bit flips happened
    all_indices = []
    for i in range(len(patterns)):
        if len(patterns[i].instances[0].flips) > 0:
            all_indices.append(i)

    # skip plotting if there exist no patterns with bit flips
    if not all_indices:
        return

    # plot at most 10 randomly chosen pattern instances that lead to bit flips
    indices = random.sample(all_indices, min(10, len(all_indices)))

    parent_dir = PurePosixPath(filepath).parent

    for idx in indices:
        # print(f"base_period: {hamm_patts[idx].base_period}")
        # print(f"len_patt: {len(hamm_patts[idx].order)}")
        inst = patterns[idx].instances[0]

        target_dir = os.path.join(parent_dir, inst.uid)
        if os.path.exists(target_dir):
            print(f'[+] Plot for {inst.uid} already exists. Skipping it.')
            continue
        create_folder(target_dir)

        dimm_id = parent_dir.parent.name
        manufacturer_dimm_chip = DimmDb.get_manufacturer_by_dimm_id(int(dimm_id.replace('DIMM_', '')))
        subtitle = f"{dimm_id.replace('_', ' ')} ({manufacturer_dimm_chip})"

        inst.time_plot(target_dir, subtitle)
        inst.freq_ampl_plot(target_dir, subtitle)
        inst.freq_phase_plot(target_dir, subtitle)

        # this is required to free the memory after calling plt.close()
        gc.collect()


def main():
    if len(sys.argv) == 2:
        generate_plots(sys.argv[1])
        return

    # create data directory
    data_dir = os.path.join(os.getcwd(), 'data')
    create_folder(data_dir)

    # download files from S3 bucket to same directory structure locally
    threads = []
    for f in get_folder_in_s3_path():
        print("[+] Checking folder {}".format(f))

        fn_dimm = os.path.join(data_dir, f.split('/')[0])
        fn_ts = f.split('/')[1]

        path_dimm = os.path.join(data_dir, fn_dimm)
        path_ts = os.path.join(path_dimm, fn_ts)

        # create folder for "DIMM_X"
        create_folder(path_dimm)

        # check that the data is current and not from an old run
        # TODO: Pass this timestamp differently, e.g., as parameter or global var
        if ('20201210' not in fn_ts) and ('20201211' not in fn_ts):
            print(
                "[-] No up-to-date data found for {}. Skipping it.".format(fn_dimm.replace('/', '').replace('_', ' ')))
            continue

        if os.path.exists(path_ts) and len(os.listdir(path=path_ts)) > 0:
            # no need to re-download things as we assume that existing files don't change
            print("[+] Folder {} already exists. Skipping.".format(path_ts))
            continue
        else:
            # if the folder contains any other data, then delete that first by recreating the "DIMM_X" folder
            if len(os.listdir(path=path_dimm)) > 0:
                shutil.rmtree(path_dimm)
                create_folder(path_dimm)
            create_folder(path_ts)

        # download files in new thread so that download continues in background
        for file in get_file(f, '.json'):
            threads.append(download_file_to(file, os.path.join(path_ts, 'raw_data.json')))
        for file in get_file(f, '.log'):
            threads.append(download_file_to(file, os.path.join(path_ts, 'stdout.log')))

    # check if all downloads finished
    while any(t.is_alive() for t in threads):
        print("[+] Download(s) in progress... waiting until all downloads finished.")
        sleep(10)

    # generate plots for each downloaded JSON file
    for filename in glob.iglob('data/**/*.json', recursive=True):
        if not os.path.isfile(filename):
            continue
        print("[+] Generating plots for file {}".format(filename))
        generate_plots(filename)


if __name__ == "__main__":
    main()
