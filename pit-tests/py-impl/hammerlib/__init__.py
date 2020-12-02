import os
import ctypes

libref = None

def init_module():
    global libref
    path = os.path.dirname(os.path.abspath(__file__))
    libref = ctypes.CDLL(os.path.join(path, "libhammer.so"))
        
    if libref.init() != 0:
        raise Exception("Couldn't initialize the library!") 



init_module()

