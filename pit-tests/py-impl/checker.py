from hammerlib import initlib
initlib(init_mem=False)

from dramaddr import *
from flip import *
from pattern import *
import genutils 
from params import *
import pprint as pp
import pickle
import sys


def loadall(filename):
    with open(filename, "rb") as f:
        while True:
            try:
                yield pickle.load(f)
            except EOFError:
                break


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise Exception("Missing parameters")


    data =  loadall(sys.argv[1]) 
    fnd = False
    for x in data:
        if x["flips"]:
            fnd = True
            print(x)
            
    
    if not fnd:
        print("NADA")


