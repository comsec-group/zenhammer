from collections import namedtuple
import copy
import math
import random
import pprint as pp
import itertools
from operator import attrgetter
from dramaddr import *
from flip import *
from params import *

MAX_ROWS        = 8192
GUARD_ROW_CNT   = 5




class AggressorTuple(tuple):
    """
    a tuple containing the relative location of the rows 
    """

    def __new__ (cls, l):
        return super(AggressorTuple, cls).__new__(cls, tuple(l))



class PatternShape():
    """
    num_refs:       number of REF intervals we want our pattern to be repeated
    act_per_ref:    max(ACTs) you can do within the refresh (required for syncing with ref)
    aggr_tuple:     an AggressorTuple which reports the #aggressors and their relative positions 
    amplitude:      how many time the aggr_tuple is repeated
    frequency:      freq is depends on  (num_refs*act_per_ref) period = freq /(num_refs*act_per_ref) 
    pattern:        the pattern is simply the aggr_tuple repeated 'amplitude' times
    """
    

    def __init__(self, num_refs, max_act, aggr_tuple, ampl, freq):
        self.max_period = num_refs*max_act 
        self.act_per_ref = max_act
        self.amplitude = ampl 
        self.frequency = freq 
        self.aggr_tuple = aggr_tuple 
#        self._check() # check if the properties of the Pattern can be used 
    
    def patt(self):
        return self.aggr_tuple*self.amplitude
    
    def real_amplitude(self):
        return len(self.patt())

    def period(self):
        period = int(math.ceil(self.max_period / self.frequency))
        return  period

    def __hash__(self):
        return hash((self.max_period, self.act_per_ref, self.frequency, self.amplitude, self.aggr_tuple))
    
    def __eq__(self, o):
        if not isinstance(o, PatternShape):
            return False
        return self.__hash__() == o.__hash__()
    
    def uid(self):
        return self.__hash__() & 0xffffffff 
   
    def __str__(self):
        dictt = {"uid": self.uid(), "freq": self.frequency, "ampl": self.amplitude, "aggr": self.aggr_tuple, "period": self.period()}
        return str(dictt)

    def __repr__(self):
        return self.__str__()

    def to_signal(self):
        def shift(l,n):
            return itertools.islice(itertools.cycle(l),-n,len(l)-n)
    
        signal = [None]*self.period()   
        signal[0:len(self.patt())] = self.patt()
        return shift(iter(signal),self.phase) 

    def max_phase(self):
        return self.period() - len(self.patt())



    """
    check if the properties of the Pattern are acceptable
    e.g., if the pattern fits in the period
    """
    def _check(self):
        period = int(math.ceil(self.max_period / self.frequency))
        if period < self.real_amplitude():
            raise Exception(f"Period ({period}) < amplitude ({self.real_amplitude()}) ")
        if self.real_amplitude() == 1 and period == 1:
            raise Exception(f"Period can't be one with a single aggressor ")
    

class PhasedPatternShape(PatternShape):
    """
    we extend the class cause we want to be able to compare if the pattern is the same
    and then check if the phase matters (e.g., if freq, amplitude are fine but only the phase matter)
    
    PatternShape +
    phase:          delta from the start of the max_period 
    """

    def __init__(self):
        self.phase = None

    #def __init__(self, num_refs:int, max_act:int, aggr_tuple:AggressorTuple, ampl:int, freq:int, phase:int):
    #    super().__init__(num_refs,max_act,aggr_tuple,ampl,freq)
    #    self.phase = phase
    #    self._check()
    
    @classmethod
    def from_shape(cls, shape, phase):
        if not isinstance(shape, PatternShape):
            raise Exception("Requires PhasedPatternShape as arg")
        
        res = cls()
        res.max_period 	        = shape.max_period 
        res.act_per_ref 	= shape.act_per_ref 
        res.amplitude 	        = shape.amplitude 
        res.frequency 	        = shape.frequency 
        res.aggr_tuple 	        = shape.aggr_tuple 
        res.phase               = phase 

        res._check()
        return res

    def __hash__(self):
        return hash((self.max_period, self.act_per_ref, self.frequency, self.amplitude, self.aggr_tuple, self.phase))
    
    def __eq__(self, o):
        if not isinstance(o, PatternShape):
            return False
        return self.__hash__() == o.__hash__()
   

    def __str__(self):
        dictt = {"uid": self.uid(), "freq": self.frequency, "ampl": self.amplitude, "aggr": self.aggr_tuple, "period": self.period(), "phase": self.phase}
        return str(dictt)

    def to_signal(self):
        def shift(l,n):
            return itertools.islice(itertools.cycle(l),len(l)-n,2*len(l)-n)
    
        signal = [None]*self.period()   
        signal[0:len(self.patt())] = self.patt()
        return shift(signal,self.phase) 
    

    """
    check also if the phase fits within the period 
    """
    def _check(self):
        # NOTE the phase needs to be lower than the period so that
        # we can repeat the same pattern over and over. If we want to have a general shift
        # based on max_period and not only period 
        
        if len(self.patt()) + self.phase > self.period():
            raise Exception("Pattern can't fit within the period")

class PatternInstance(PhasedPatternShape):
    """
    This is a single instance of the PhasedPatternShape
    With instance we simply turn the aggr_tuple into DRAMAddr instances so that we can convert everything
    into addresses for hammering
    """
    
    @classmethod
    def from_phased_shape(cls, shape,  d):
        if not isinstance(shape, PhasedPatternShape):
            raise Exception("Requires PhasedPatternShape as arg")
        if not isinstance(d, DRAMAddr):
            raise Exception("Requires DRAMAddr as arg")

        res = cls()
        res.max_period 	        = shape.max_period 
        res.act_per_ref 	= shape.act_per_ref 
        res.amplitude 	        = shape.amplitude 
        res.frequency 	        = shape.frequency 
        res.phase               = shape.phase 
        res.aggr_tuple          = tuple(AggrAddr(d.bank, d.row+x, d.col) for x in shape.aggr_tuple) 
        return res
    
    def padded_signal(self):

        def generate_blacklist():
            min_row = min(self.aggr_tuple, key=attrgetter("row")).row - GUARD_ROW_CNT
            max_row = max(self.aggr_tuple, key=attrgetter("row")).row + GUARD_ROW_CNT
            for r in range(min_row, max_row):
                yield DRAMAddr(bank,r, 0)
        
        def get_random_addr():
            d = DRAMAddr(bank, random.randint(0, MAX_ROWS), 0)  
            while d in blacklist:
                d = DRAMAddr(bank, random.randint(0, MAX_ROWS), 0)  
            return d
        
        def fill_na(x):
            return get_random_addr() if x is None else x 

        bank = self.aggr_tuple[0].bank
        blacklist = generate_blacklist() 

        signal = self.to_signal()
        signal = map(fill_na, signal) 
        return signal
    
    def hammer(self):
        print([x if isinstance(x[1], AggrAddr) else None for x in enumerate(self.padded_signal())])
        signal = list(map(lambda x:x.to_addr(), self.padded_signal()))
        scan_range = (self.aggr_tuple[0] - 5, self.aggr_tuple[1] + 5) 
        sync_addr = self.aggr_tuple[0] + DRAMAddr(0,10,0) # sync on a different row 
        sync_addr = (ctypes.c_size_t)(sync_addr.to_addr())
        patt = (ctypes.c_void_p * len(signal))(*signal) 
        rounds = (ctypes.c_size_t)(int(4*EXPECTED_ACT/len(signal)))
        act_ref = (ctypes.c_size_t)(int(self.act_per_ref))
        libref.hammer_func(sync_addr, patt, len(patt), rounds,  act_ref ) 
        flips = FlipScanner.scan(*scan_range)        
        return flips
    

libref.hammer_func.restype = ctypes.c_void_p
libref.hammer_func.argstype = [ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t] 




