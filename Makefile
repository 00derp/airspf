CXX ?= g++
CC ?= gcc
CFLAGS = -Wall -Wconversion -O3 -pedantic -std=c99 -g #-fopenmp
LDFLAGS = -lm -O3 -lpcap # -fopenmp

TARGET = airspf

all: $(TARGET)

airspf: airspf.o

.PHONY: clean
clean:
	rm -f *~ *.o airspf
