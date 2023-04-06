#!/usr/bin/env python3

from collections import defaultdict

with open("/Users/pjattke/Downloads/logfile_timing") as f:
   for th in range(400, 1400, 25):
      for offt in range(50, 300, 500):
         freq = defaultdict(int)
         counter = 0
         for line in f.readlines():
            t = int(line.replace('\n', '').split(',')[0])
            # print(t)
            if t > (th-offt) and t < (th+offt):
               freq[counter] += 1
               counter = 0
            else:
               # we always do 2 acceses per round
               counter += 2
         freq = dict(sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10])
         print(f"th={th-offt},{th+offt} => {freq}")
         f.seek(0)
         


