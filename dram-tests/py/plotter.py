import sys
import matplotlib.pyplot as plt
arr = []
for l in sys.stdin:
    triplet = l.split(",")
    time = int(triplet[2])
    arr.append(time)

plt.hist(arr, bins=500)
plt.show()
