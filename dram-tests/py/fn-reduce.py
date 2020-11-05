import os,sys
import numpy as np
import sympy


def lin_ind(mtx, orig):

    def bool_xor(a,b):
        return a != b
    pvt_col = 0
    filtered_masks = []
    
    while pvt_col < len(mtx[0]): 
        for row in range(len(mtx)):
            if (mtx[row,pvt_col]): 
                filtered_masks.append(orig[pvt_col])
                for c in range(len(mtx[0])):
                    if (c == pvt_col):
                        continue
                    if not ((mtx[row][c])):
                        continue
                    for r in range(len(mtx)): 
                        mtx[r][c] = bool_xor(mtx[r][c], mtx[r][pvt_col])
                break
        pvt_col += 1
  
    for i in range(len(filtered_masks)):
        print(hex(int("0b" + "".join(map(str,filtered_masks[i])),2))) 


mat = [] 
for i, line in enumerate(sys.stdin):
    try:
        val = int(line, 16)
    except ValueError as e:
        print(f"Error in parsing the inputs: {e}")
        sys.exit(1)
    
    mat.append(val)

mtx = np.array([list(map(int,list(f"{x:031b}"))) for x in mat]) # generating boolean matrix from the bitmasks
mtt = mtx
print(mtx)
lin_ind(mtx.T, mtx)

print(mtx)
#lambdas, V =  np.linalg.eig(mtx.T)
#print(mtx[lambdas == 0,:])
#print(len(mtx[lambdas == 0,:]))
#print(mtx)
_, inds = sympy.Matrix(mtx).T.rref()   # index of linearly independet rows
print(inds)
for idx in inds:
    print(f"{mat[idx]:#x}")





