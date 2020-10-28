CXX = g++
CXXFLAGS = -Wall -std=c++11 -g
DEPS = utils.h
OBJ = blacksmith.o PatternBuilder.o

# force that calling 'make' always rebuilds things
.PHONY: blacksmith

%.o: %.c $(DEPS)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

blacksmith: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^

run: blacksmith
	sudo ./blacksmith 1000

run_eval: blacksmith
	sudo ./blacksmith 1000000

clean:
	rm -f *.o blacksmith
	rm -f *.h.gch
