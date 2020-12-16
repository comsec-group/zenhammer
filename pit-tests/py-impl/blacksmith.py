#!/usr/bin/python3

from hammerlib import initlib
initlib(init_mem=True)

from dramaddr import *
from flip import *
from pattern import *
import genutils 
from params import *
import pprint as pp
import pickle

"""
this generate an inveresely proportional ration between freq/amplitude
ro respect the EXPECTED_ACT value
"""


#def test_shape(shape):
#    expected_iters = int(EXPECTED_ACT_PER_MAX_PERIOD/len(shape.aggr_tuple))
#    total_acts_per_period = shape.real_amplitude()*shape.frequency
#    if not (EXPECTED_ACT_PER_MAX_PERIOD*0.8 < total_acts_per_period and EXPECTED_ACT_PER_MAX_PERIOD*1.2 > total_acts_per_period):
#        print(f"too many/few acts {total_acts_per_period}/{EXPECTED_ACT_PER_MAX_PERIOD}")
#    else:
#        print(f"Golden ratio: {total_acts_per_period}/{EXPECTED_ACT_PER_MAX_PERIOD}")


inst_exports = []
export_file = os.path.join("data",genutils.log_file_name())

if __name__ == "__main__":
    aggr_tuple = AggressorTuple([0,2])
    shapes = (PatternShape(MAX_REFS, MAX_ACT_PER_REF, aggr_tuple, *genutils.gen_ampl_freq(aggr_tuple)) for i in range(MAX_TEST_SHAPE))

    
    for shape in shapes:
        for phase in (genutils.rnd(shape.max_phase()) for s in range(MAX_TEST_PHASE)):

            phased_shape = PhasedPatternShape.from_shape(shape, phase)

            instances = (PatternInstance.from_phased_shape(phased_shape, DRAMAddr(genutils.rnd(16), genutils.rnd(512))) for loc in range(MAX_TEST_INSTANCE))

            print(f"{phased_shape}")
            for inst in instances:

                res = inst.hammer() 
                out = {"instance": inst, "flips": res}
                if res:
                    print("Flips!\n")
                    pp.pprint(out)

                with open(export_file, "ab+") as f:
                    pickle.dump(out , f)                    




# Fin.
