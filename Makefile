COMPILER = g++
CCFLAGS = -O2 -std=c++11
CPPFLAGS = -O2 -lstdc++

all: hs

hs: hs.o
	${COMPILER} ${CCFLAGS} hs.o -o hs

hs.o: hs.c hs.h
	${COMPILER} ${CCFLAGS} -c hs.c

clean: 
	rm -rf *.o hs

