#
#
#

all: regexrock
	@echo DONE

CFLAGS += -Wall

regexrock: main.o
	$(CC) $(CFLAGS) -o $@ $^ -lpcre

clean:
	rm -f *.o *.d *.dep
	rm -rf *.dSYM
	rm -f regexrock

.PHONY: all clean

