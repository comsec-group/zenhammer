
# Should be equivalent to your list of C files, if you don't build selectively
INC=./inc/
SRC=$(wildcard src/*.c)
OBJ=obj/tester
CFLAGS = -I$(INC) -g -lm -msse4.2 

time: $(SRC) 
	gcc -DTIME -o $(OBJ)  $^ $(CFLAGS) 
	./obj/tester

pmu: $(SRC)
	gcc -DPMU -o $(OBJ)  $^ $(CFLAGS) 
	sudo ./obj/tester

run: pmu 
	sudo ./obj/tester
