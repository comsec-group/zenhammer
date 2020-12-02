import sys
import seaborn as sns
import pandas as pd
import pprint as pp
from matplotlib import pyplot as plt
res = []
for l in sys.stdin:
    tmp = map(int,l.split(","))
    res.append(tmp)

dat = pd.DataFrame(res)
dat.columns = ["nops", "dt"]
ax = sns.boxplot(x="nops", y="dt", data=dat)
plt.show()
pp.pprint(dat)
