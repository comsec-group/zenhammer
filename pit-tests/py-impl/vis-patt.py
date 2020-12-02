import re
import pprint as pp
import sys
from matplotlib import pyplot as plt
f_name = "patt.txt"


agg_re = re.compile("agg(\d+)")
flatten = lambda t: [item for sublist in t for item in sublist]

with open(f_name) as f:
    #patts = map(lambda x: agg_re.match(x).group(1), [x.split(" ") for x in f.read().split("\n")])
    #patts = [list(filter(None,x.split(" "))) for x in f.read().split("\n") if x] 
    patts =  list(enumerate(flatten([list(map(lambda x: int(agg_re.match(x).group(1)), list(filter(None,x.split(" "))))) for x in f.read().split("\n") if x])))
    pp.pprint(patts)
    x,y = zip(*patts)
    plt.plot(x,y, ".")
    plt.show()
    #for l in patts:
    #    for x in l:
    #        agg_re.match(x).group(1))

