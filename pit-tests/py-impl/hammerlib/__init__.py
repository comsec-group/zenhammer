import os
import ctypes

libref = None

def initlib(init_mem=False):
    global libref
    path = os.path.dirname(os.path.abspath(__file__))
    libref = ctypes.CDLL(os.path.join(path, "libhammer.so"))
    
    if init_mem:
        if libref.init() != 0:
            raise Exception("Couldn't initialize the library!") 



