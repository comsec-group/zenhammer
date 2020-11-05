import sys
from operator import itemgetter

### NOTE THIS THING IS NOT REALLY WORKING. I'LL MANAGE ONE DAY TO DO THE AUTOMATIC CLUSTERING

times = []
for l in sys.stdin:
    times.append(int(l.split(",")[2]))

times = sorted(times)



diff= lambda x: x[1] - x[0]
#res = max([(i, v) for i,v in enumerate(map(diff,zip(times[:-1], times[1:])))], key=itemgetter(1))
diffs = max(enumerate(list(map(diff,zip(times[:-1], times[1:])))), key=itemgetter(1))
print(diffs)
print(f"vals: {times[diffs[0]]} - {times[diffs[0]+1]}")
