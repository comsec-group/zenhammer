from hammerlib import libref
import dramaddr 
import ctypes


class Flip(ctypes.Structure):
    _fields_ = [
            ("addr", ctypes.c_uint64),
            ("mask", ctypes.c_uint64),
            ("data", ctypes.c_uint64),
            ]

    def __repr__(self):
        return self.__str__()

    def __str__(s):
        d = DRAMAddr.from_addr(addr)
        return f"Flip(row:{d.row:04d}, data: {s.data:02x}, flip: {s.mask:02x})"
    
    def __eq__(s, o):
        if isinstance(o, Flip):
            return s.mask == o.mask and s.addr == o.addr



class FlipScanner():
    
    class FlipList(ctypes.Structure):
        _fields_ = [
            ("cnt", ctypes.c_size_t),
            ("flips", Flip*500)
            ]

    # 
    # init hammerlib native functions
    #
    libref().scan.restype = FlipList
    libref().scan.argstype = [ctypes.c_size_t, ctypes.c_size_t]

    @classmethod
    def scan(cls, d_begin, d_end):
        base_addr = d_begin.to_addr()
        end_addr = d_end.to_addr()
        chunk_size = end_addr - base_addr
        res = libref().scan(ctypes.c_size_t(base_addr), ctypes.c_size_t(end_addr))
        flips = res.flips[:res.cnt]
        return flips


