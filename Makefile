CXX = g++
CXXFLAGS = -Wall -std=c++11 -g
DEPS = utils.h
OBJ = blacksmith.o PatternBuilder.o

%.o: %.c $(DEPS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

blacksmith: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

run: blacksmith
	sudo ./blacksmith

clean:
	rm -f *.o blacksmith
	rm -f *.h.gch
