.PHONY: clean

CFILES := $(shell ls *.c)

ctool: defs.h prototypes.h $(CFILES)
	gcc -Wall -O0 -o ctool -include defs.h -include prototypes.h $(CFILES) -lm

prototypes.h: $(CFILES)
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f ctool prototypes.h
