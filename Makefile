all: build run

build:
	g++ -o blacksmith blacksmith.cpp utils.h

run: build
	sudo ./blacksmith
