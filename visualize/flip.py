from collections import namedtuple
from dramaddr import *

FLIP_STRUCT_SIZE = 16
"""
struct BitFlip {
    size_t      addr,
    uint32_t    patt,
    uint32_t    mask
}
"""


"""
    address: addr of the bit flip. We can recover the DRAMAdrr from the MemConfig
    bitmask: bit mask of the bit flip (We can export 0->1 or 1->0 from the data seed)
"""
class BitFlip(namedtuple("BitFlip", [ "addr","data" ,"bitmask"])):
    
    @classmethod
    def from_json(cls, dd):
        if not set(dd.keys()) == set(("dram_addr","data","bitmask")):
            raise Exception("NOT a flip!!")
        
        dram_addr = DRAMAddr.from_json(dd['dram_addr'])
        return cls(addr=dram_addr, **{k:v for k,v in dd.items() if k != 'dram_addr'})

    def __str__(s):
        return f"BitFlip(row/col:{s.addr.row:>5d}/{s.addr.col:>4d},flip:({s.bitmask:08b})"

    def __repr__(self):
        return self.__str__()


