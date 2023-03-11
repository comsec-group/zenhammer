#!/usr/bin/env python3
import os.path
import sys

import numpy as np

from statistics import mean, median

from tqdm import tqdm
from matplotlib import pyplot as plt

all_values = list()

stats = dict()
stats['avg'] = list()
stats['min'] = list()
stats['max'] = list()
stats['median'] = list()
stats['first_quartile'] = list()
stats['second_quartile'] = list()
stats['third_quartile'] = list()

filepath = sys.argv[1]
filename = os.path.basename(filepath)

# MAX_LINES = 122

print("Reading results...")
line_cnt = 0
with open(filepath) as f:
    for line in tqdm(f.readlines()):
        if line.startswith("#"):
            print(f"skipping: {line}", end='')
            continue
        line_cnt += 1
        if line_cnt % 10 != 0:
            continue
        for idx, k in enumerate(line.split(",")):
            if len(all_values) > idx:
                all_values[idx].append(int(k,10))
            else:
                all_values.append([int(k,10)])
        if len(stats['avg']) > 0:
            stats['avg'].append(mean([stats['avg'][-1], all_values[2][-1]]))
            stats['min'].append(min([stats['min'][-1], all_values[2][-1]]))
            stats['max'].append(max([stats['max'][-1], all_values[2][-1]]))
        else:
            stats['avg'].append(mean(all_values[2]))
            stats['min'].append(min(all_values[2]))
            stats['max'].append(max(all_values[2]))

        stats['median'].append(median(all_values[2]))
        stats['first_quartile'].append(np.percentile(all_values[2], 25))
        stats['third_quartile'].append(np.percentile(all_values[2], 75))


print("Plotting results...")
plt.figure(1, figsize=(40, 4))
plt.bar(all_values[0], all_values[2])
# plt.bar(all_values[0], all_values[2])
linewidth = 0.5
plt.plot(all_values[0], stats['avg'], color='red', label='avg', linewidth=linewidth)
plt.plot(all_values[0], stats['min'], color='green', label='min', linewidth=linewidth)
plt.plot(all_values[0], stats['max'], color='green', label='max', linewidth=linewidth)
plt.plot(all_values[0], stats['median'], color='black', label='median', linewidth=linewidth)
plt.plot(all_values[0], stats['first_quartile'], color='orange', label='1st quartile', linewidth=linewidth)
plt.plot(all_values[0], stats['third_quartile'], color='orange', label='3rd quartile', linewidth=linewidth)

# plt.ylim(300,1500)

plt.legend()

plt.suptitle("Timing Analysis for ACTs per REF(sb|ab)\n")
plt.title(f"file: {filepath}, #measurements: {len(all_values[0])}", x=0, fontsize=9, loc='left')
plt.xlabel("Measurement Round = (#ACTs x 2)")
# tl = [k for k in range(len(all_values[0]), 500)]
# plt.xticks(tl, tl, major=True, minor=True)
plt.margins(x=0.001, y=0.001)
plt.ylabel("Timing in Cycles (rdtscp)")


print("Writing results to file...")
plt.savefig("plot.pdf", dpi=150)
