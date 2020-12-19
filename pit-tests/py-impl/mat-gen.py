import sys, os
import numpy as np
import pprint as pp


class BinInt(int):

    def __repr__(s):
        return s.__str__()
    
    def __str__(s):
        return f"{s:#032b}"

class DRAMFunctions():

    def __init__(self, bank_fns, row_fn, col_fn):
        def to_binary_array(v):
            vals = []
            for x in range(30):
                if (v >> x) & 1:
                    vals.append(1<<x) 
            return list(reversed(vals))

        def gen_mask(v):
            len_mask = bin(v).count("1")
            mask = (1 << len_mask )-1
            return (len_mask, mask)

        bank_mask = (1 << len(bank_fns))-1
        row_arr = to_binary_array(row_fn)
        len_row_mask, row_mask = gen_mask(row_fn) 
        col_arr = to_binary_array(col_fn)
        len_col_mask, col_mask = gen_mask(col_fn) 

        self.row_arr = row_arr
        self.col_arr = col_arr
        self.bank_arr = bank_fns
        self.row_shift = 0
        self.col_shift = len_row_mask
        self.bank_shift = len_row_mask + len_col_mask
        self.row_mask = BinInt(row_mask)
        self.col_mask = BinInt(col_mask)
        self.bank_mask = BinInt(bank_mask)

    def to_dram_mtx(self):
        mtx = self.bank_arr + self.col_arr + self.row_arr 
        return list(map(lambda v:BinInt(v),mtx))

    def to_addr_mtx(self):
        dram_mtx =  self.to_dram_mtx()
        mtx = np.array([list(map(int,list(f"{x:030b}"))) for x in dram_mtx])
        assert mtx.shape == (30,30)
        inv_mtx = list(map(abs, np.linalg.inv(mtx).astype('int64')))
        inv_arr = []
        for i in range(len(inv_mtx)):
            inv_arr.append(BinInt("0b" + "".join(map(str,inv_mtx[i])),2))

        return inv_arr


    def __repr__(self):
        dram_mtx = self.to_dram_mtx()  
        print(dram_mtx)
        addr_mtx = self.to_addr_mtx()
        sstr = ""
        sstr += "#define BK_SHIFT {0}\n".format(self.bank_shift)
        sstr += "#define BK_MAKS {0}\n".format(self.bank_mask)
        sstr += "#define ROW_SHIFT {0}\n".format(self.row_shift)
        sstr += "#define ROW_MASK {0}\n".format(self.row_mask)
        sstr += "#define COL_SHIFT {0}\n".format(self.col_shift)
        sstr += "#define COL_MASK {0}\n".format(self.col_mask)
        str_mtx = pp.pformat(dram_mtx, indent=4)
        trans_tab = str_mtx.maketrans('[]','{}')
        str_mtx = str_mtx.translate(trans_tab)
        sstr += f"\n\nsize_t DRAM_MTX[30] = {str_mtx}"
        str_mtx = pp.pformat(addr_mtx, indent=4)
        trans_tab = str_mtx.maketrans('[]','{}')
        str_mtx = str_mtx.translate(trans_tab)
        sstr += f"\n\nsize_t PHYS_MTX[30] = {str_mtx}"
        return sstr

dram_fns = [	0x4080
	, 0x88000
	, 0x110000
	, 0x220000
	, 0x440000
	, 0x4b300
        ] 
row_fn = 0x3ff80000 
col_fn = 8192 - 1
print(DRAMFunctions(dram_fns, row_fn, col_fn))
