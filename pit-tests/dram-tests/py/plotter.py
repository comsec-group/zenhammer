import sys
import matplotlib.pyplot as plt
arr = []
for l in sys.stdin:
#    triplet = l.split(",")
    time = int(l)
    arr.append(time)

#plt.hist(arr)
plt.hist(arr, bins=500)
plt.show()
