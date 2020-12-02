
# Should be equivalent to your list of C files, if you don't build selectively
INC=include/
SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)
TARGET=libhammer.so

CFLAGS = -I$(INC) -g -lm -msse4.2 -fpic   #-DDEBUG 
LDFLAGS= -shared

all: $(TARGET) 

$(TARGET): $(OBJ)
	gcc  $(LDFLAGS) $(CFLAGS)  -o $(TARGET) $(OBJ)

$(SRC:.c=.d):%.d:%.c
	gcc  $(CFLAGS) -MM $< >$@

include $(SRC:.c=.d)

clean:
	rm -f $(OBJ) 
	rm -f $(TARGET)
