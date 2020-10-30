CXX = g++
CXXFLAGS = -Wall -std=c++11 -g
OBJ = blacksmith.o PatternBuilder.o DramAnalyzer.o
INCLUDE_ASMJIT = -I /usr/local/include -L /usr/local/lib -lasmjit

# force that calling 'make' always rebuilds things
.PHONY: blacksmith

%.o: %.c
	$(CXX) $(CXXFLAGS) $(INCLUDE_ASMJIT) -c -o $@ $<

blacksmith: $(OBJ)
	$(CXX) $(CXXFLAGS) $(INCLUDE_ASMJIT) -o $@ $^

run: blacksmith
	sudo ./blacksmith 100

benchmark: blacksmith
	sudo ./blacksmith 100000

clean:
	rm -f *.o blacksmith
	rm -f *.h.gch

debug: blacksmith
	sudo gdb blacksmith
