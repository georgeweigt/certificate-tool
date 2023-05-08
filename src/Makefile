.PHONY: clean check

ctool: defs.h prototypes.h *.c
	gcc -Wall -O0 -o ctool -include defs.h -include prototypes.h *.c

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes *.c > prototypes.h

clean:
	rm -f ctool prototypes.h

check:
	make -s -C ../tools wcheck
	../tools/wcheck *.c
