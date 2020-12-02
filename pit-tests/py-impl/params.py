
# Constants
REFS_PER_RI = int(64000/7.8) 

# Parameters per setup 
MAX_REFS = 4 
MAX_ACT_PER_REF = 170


# Config parameters 
MIN_AGGR_DIST   = 1
MAX_AGGR_DIST   = 10
MAX_NUM_AGGR    = 4 
MAX_AGGRESSORS  = 5 
MAX_DIST        = 3 #distance from the first row in the tuple
MAX_FREQ        = 100 #
MAX_AMPL        = 10 

MAX_TEST_SHAPE = 2000
MAX_TEST_PHASE = 20
MAX_TEST_INSTANCE = 5 

# we want 10% of the activations within a refresh to be to our tuple
# this is ~130K
EXPECTED_ACT    = int((REFS_PER_RI*MAX_ACT_PER_REF) * 0.1) 
EXPECTED_ACT_PER_MAX_PERIOD    = int(EXPECTED_ACT / (REFS_PER_RI / MAX_REFS)) 

