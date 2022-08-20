CC = gcc
CFLAGS = -Wall -O0

# := means evaluate then assign result to variable
# sed removes the commas then replaces .c with .o

objects := $(shell ls -m *.c | sed "s/,//g;s/\.c/\.o/g")

ctool: $(objects)
	gcc $(objects) -o ctool

$(objects) : defs.h prototypes.h

clean:
	rm -f ctool *.o *.pem *.der
