#! /usr/bin/python3

# import json
import shutil
import sys
import code
import random
from time import sleep

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
    # TODO: give make filepath optional, otherwise just use show
    patterns = InstanceList()

    with open(filepath, "r") as f:
        data = json.load(f)

    for x in data:
        patterns.append(HammeringPattern.from_json(x))

    # patterns = random.choices(all_patterns, k=100)

    # determine instances where
    indices = []
    for i in range(len(patterns)):
        if len(patterns[i].instances[0].flips) > 0:
            indices.append(i)


    # TODO: Plot each index in indices


    pp.pprint(patterns)
    # print(f"base_period: {hamm_patts[idx].base_period}")
    # print(f"len_patt: {len(hamm_patts[idx].order)}")
    inst = patterns[indices[0]].instances[0]
    # TODO: add filepath to time_plot
    inst.time_plot()
    code.interact(local=locals())
    # TODO: add filepath to ampl_plot
    inst.freq_ampl_plot()
    # TODO: add filepath to freq_phase_plot
    inst.freq_phase_plot()
    print()
    # pp.pprint(hamm_patt.instances[0])
    # code.interact(local=locals())


def main():
    if len(sys.argv) == 2:
        generate_plots(sys.argv[1])
        return

    cwd = os.getcwd()
    data_dir = os.path.join(cwd, 'data')
    create_folder(data_dir)

    threads = []

    for f in get_folder_in_s3_path():
        print("[+] Checking folder {}".format(f))

        fn_dimm = os.path.join(data_dir, f.split('/')[0])
        fn_ts = f.split('/')[1]

        path_dimm = os.path.join(data_dir, fn_dimm)
        path_ts = os.path.join(path_dimm, fn_ts)

        create_folder(path_dimm)

        if ('20201210' not in fn_ts) and ('20201211' not in fn_ts):
            print(
                "[-] No up-to-date data found for {}. Skipping it.".format(fn_dimm.replace('/', '').replace('_', ' ')))
            continue

        if os.path.exists(path_ts) and len(os.listdir(path=path_ts)) > 0:
            # no need to re-download things as we assume that existing files don't change
            print("[+] Folder {} already exists. Skipping.".format(path_ts))
            continue
        else:
            # if the folder contains any other data, then delete that first by recreating the DIMM folder
            if len(os.listdir(path=path_dimm)) > 0:
                shutil.rmtree(path_dimm)
                create_folder(path_dimm)
            create_folder(path_ts)

        for file in get_file(f, ['.json']):
            threads.append(download_file_to(file, os.path.join(path_ts, 'raw_data.json')))
        for file in get_file(f, ['.log']):
            threads.append(download_file_to(file, os.path.join(path_ts, 'stdout.log')))

    while any(t.is_alive() for t in threads):
        print("[+] Download(s) in progress... waiting until all downloads finished.")
        sleep(10)

    for filename in glob.iglob('data/**/*.json', recursive=True):
        if not os.path.isfile(filename):
            continue
        print("[+] Generating plots for file {}".format(filename))
        generate_plots(filename)
        return


if __name__ == "__main__":
    main()
