#!/usr/bin/env python3

import os
import sys
import struct
import ctypes
import ctypes.util
import functools

@functools.total_ordering
class DRAMAddr(ctypes.Structure):
    _fields_ = [('bank', ctypes.c_uint64),
                ('row', ctypes.c_uint64),
                ('col', ctypes.c_uint64)]
    
    @classmethod
    def from_json(cls, ddict):
        if set(ddict.keys()) == set(("bank", "row", "col")):
            return DRAMAddr(**ddict)
        else: 
            return NotImplemented

    
    def __init__(self, bank, row, col=0): 
        self.bank   = int(bank)
        self.row    = int(row)
        self.col    = int(col)

    def __str__(s):
        return f"DRAMAddr(b:{s.bank:02d}, r:{s.row:>6d}, c:{s.col:>4d})"   if s.col != 0 else  f"DRAMAddr(b:{s.bank:02d}, r:{s.row:>6d})"

    def __repr__(self):
        return self.__str__()
    
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






