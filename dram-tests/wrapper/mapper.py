from dramtrans import DRAMAddr


class MemConfig(namedtuple('MemConfig', ['channel','dimm', 'rank', 'bank'])):
    """
    Used to figure out which config file to load
    Configurations are limited and the mapping function is always the same
    so we store the configs into a folder and load the right file at the right time
    """



class Mapper():
    to_dram_mtx = None
    to_addr_mtx = None
    def to_dram(addr):
        """"""
    def to_phys(addr):
        """"""
        if to_addr_mtx == None:
            print("[ERROR] - MemConfig not loaded!!")
            return NotImplemented

        if isinstance(addr, DRAMAddr):
            v_addr = 0
            lin_addr = addr.linearize()
            for b in to_addr_mtx:
                v_addr <<= 1
                v_addr |= parity(lin_addr & b)

            return ctypes.c_uint64(v_addr)
    
    def load_config(config):
