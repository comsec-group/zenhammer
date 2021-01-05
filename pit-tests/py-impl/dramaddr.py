#!/usr/bin/env python3

from hammerlib import libref 
import struct
import ctypes
import ctypes.util
import functools
import bsutils



@functools.total_ordering
class DRAMAddr(ctypes.Structure):
    _fields_ = [('bank', ctypes.c_uint64),
                ('row', ctypes.c_uint64),
                ('col', ctypes.c_uint64)]
    
    @classmethod
    def from_addr(cls, addr): 
        if isinstance(addr, int):
            return libref().to_dram(addr) 
        else:
            return NotImplemented

    def __init__(self, bank, row, col=0): 
        self.bank   = bank
        self.row    = row
        self.col    = col

    def __str__(s):
        return f"DRAMAddr(b:{s.bank:02d}, r:{s.row:>6d}, c{s.col:>4d})"    

    def __repr__(self):
        return self.__str__()
#    def __repr__(self):
#        return '{0}(b={1.bank},r={1.row},c={1.col})'.format(type(self).__name__, self)

    def __eq__(self, other):
        if isinstance(other, DRAMAddr):
            return self.numeric_value == other.numeric_value
        else:
            return NotImplemented

    def __lt__(self, other):
        if isinstance(other, DRAMAddr):
            return self.numeric_value < other.numeric_value
        else:
            return NotImplemented

    def __hash__(self):
        return self.numeric_value

    def __len__(self):
        return len(self._fields_)


    def same_bank(self, other):
        return  self.bank == other.bank

    @property
    def numeric_value(self):
        return (self.col + (self.row << 16) + (self.bank << 32))
    
    def __add__(self, other):
        if isinstance(other, DRAMAddr):
            return type(self)(
                self.bank + other.bank,
                self.row + other.row,
                self.col + other.col
            )
        elif isinstance(other, int):
            return type(self)(
                self.bank,
                self.row + other,
                self.col 
            )
        else:
            return NotImplemented

    def __sub__(self, other):
        if isinstance(other, DRAMAddr):
            return type(self)(
                self.bank - other.bank,
                self.row - other.row,
                self.col - other.col
            )
        elif isinstance(other, int):
            return type(self)(
                self.bank,
                self.row + other,
                self.col 
            )
        else:
            return NotImplemented


    def to_addr(d):
        return int(libref().to_addr(d))


class AggrAddr(DRAMAddr):
    def __repr__(s):
        return s.__str__()

    def __str__(s):
        return bsutils.col_green(f"{super().__str__()}")

# 
# init hammerlib native functions
#

libref().to_addr.restype = ctypes.c_size_t
libref().to_addr.argtypes = [DRAMAddr]
libref().to_dram.restype = DRAMAddr 
libref().to_dram.argtypes = [ctypes.c_size_t]

