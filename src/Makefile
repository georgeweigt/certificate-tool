.PHONY: clean
CC = gcc
CFLAGS = -O0

objs := $(shell ls *.c | sed "s/\.c/\.o/g")

ctool: $(objs)
	gcc -o ctool $(objs)

$(objs) : defs.h prototypes.h

clean:
	rm -f ctool *.o *.pem *.der
