#! /usr/bin/python3
import json, sys
import code
from hammerpatt import *

patterns = InstanceList() 
if len(sys.argv) != 2:
    raise Exception("Missing file name")

with open(sys.argv[1],"r") as f:
    data = json.load(f)

for x in data:
    patterns.append(HammeringPattern.from_json(x))

    
idx = 0 
pp.pprint(patterns)
#print(f"base_period: {hamm_patts[idx].base_period}")
#print(f"len_patt: {len(hamm_patts[idx].order)}")
#inst = patterns[idx].instances[0]
#inst.time_plot()
#inst.freq_ampl_plot()
#inst.freq_phase_plot()
#pp.pprint(hamm_patt.instances[0])
code.interact(local=locals()) 
