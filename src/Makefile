.PHONY: clean

demo: *.h *.c
	gcc -Wall -O0 -o ctool *.c -lm

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f ctool
