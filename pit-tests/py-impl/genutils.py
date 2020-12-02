import random
from params import *

def around(x, base=.1):
  return round(base * round(float(x)/base),1)

def beta_dist(x,a,b):
    return -x/(1.5*b-a)+1

def rand_dist(tpl, fn):
    dist = lambda x : beta_dist(x,*tpl)
    return random.choices(range(*tpl), map(dist, range(*tpl)))[0]

def rnd(max_val, min_val=1):
    return random.randint(min_val, max_val)

def gen_ampl_freq(aggr_tuple):
    tuple_len = len(aggr_tuple)
    expected_iters = int(EXPECTED_ACT_PER_MAX_PERIOD/tuple_len)
    amplitude = rand_dist((1,expected_iters), beta_dist) 
    frequency = around(expected_iters/amplitude) 
    
    #frequency = rnd(int(expected_iters*1.2)) 
    #amplitude = rnd(int(expected_iters*1.1)) 
    return (amplitude, frequency)
    
