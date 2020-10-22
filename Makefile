all: build run

build:
	g++ -o blacksmith blacksmith.cpp patternBuilder.h patternBuilder.cpp utils.h

run: build
	sudo ./blacksmith
