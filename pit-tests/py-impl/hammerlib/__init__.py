import os
import ctypes

librefobj = None

def initlib(init_mem=False):
    global librefobj
    path = os.path.dirname(os.path.abspath(__file__))
    librefobj = ctypes.CDLL(os.path.join(path, "libhammer.so"))
    
    if init_mem:
        if librefobj.init() != 0:
            raise Exception("Couldn't initialize the library!") 


def libref():
    global librefobj
    if librefobj == None:
        raise Exception("You didn't initialize the C library.\n from hammerlib import *\n hammerlib.initlib(init_mem=bool)")
    return librefobj
