import sys
import matplotlib.pyplot as plt
arr = []
for l in sys.stdin:
    time = int(l)
    arr.append(time)

plt.plot(arr)
plt.show()

