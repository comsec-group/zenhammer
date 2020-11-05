
# Should be equivalent to your list of C files, if you don't build selectively
INC=include
SRC=$(wildcard src/*.c)
OBJ=obj/tester
CFLAGS = -I$(INC) -g -lm -msse4.2 

all: 
	echo "Nada"

export: $(SRC)
	#gcc -DEXPORT_TIMES -o $@ $^ $(CFLAGS) 
	gcc -DEXPORT_TIMES -o $(OBJ)  $^ $(CFLAGS) 


functions: $(SRC)
	gcc -DTIME_THRESH=320 -DEXPORT_FUNCTIONS -o $(OBJ) $^ $(CFLAGS) 


hammer: $(SRC)
	gcc -DSYNC -o $(OBJ) $^ $(CFLAGS) 

clean:
	rm -f $(OBJ) 
