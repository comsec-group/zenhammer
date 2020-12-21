import pprint as pp
import seaborn as sns

import sys, os, json
from hammerpatt import *
import pandas as pd
import collections 

if __name__ == "__main__":
    filepath = sys.argv[1]
    patterns = InstanceList()

    with open(filepath, "r") as f:
        data = json.load(f)

    for x in data:
        patterns.append(HammeringPattern.from_json(x))

    # determine instances where bit flips happened
    aggAccPatts = []
    periods = []
    for patt in patterns:
        periods.append({patt.max_period: collections.Counter([x.period for x in patt.aggr_list])})
        curr_patt = []
#        for inst in patt.instances:
#            curr_patt.extend(inst.extract_effective_agg_patt()) 
#    
#
#        curr_patt = list(set(curr_patt)) 
#        aggAccPatts.extend(curr_patt)

#    data = pd.DataFrame(aggAccPatts)
    pp.pprint(sorted(periods, key=lambda d: list(d.keys()))) 
#    for k,g in data.groupby('max_period'):
#        
#        print(f"Period{k} {collections.Counter(g['period'].tolist())}")
#        sns.swarmplot(data=g, x="period", y="phase", hue="amplitude")
#        plt.title(f"Period: {k}")
#        plt.show()
    #sns.scatterplot(data=data, x="period", y="phase", hue="amplitude")

   
