import sys
import matplotlib.pyplot as plt

x_arr = []
y_arr = []
for l in sys.stdin:
    x,y = eval(l)
    x_arr.append(x)
    y_arr.append(y)

plt.plot(x_arr, y_arr)
plt.show()

