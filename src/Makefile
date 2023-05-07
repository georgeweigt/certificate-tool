.PHONY: clean check

ctool: defs.h prototypes.h *.c
	gcc -Wall -O0 -o ctool -include defs.h -include prototypes.h *.c -lm

prototypes.h: *.c
	make -s -C ../tools make-prototypes
	../tools/make-prototypes *.c > prototypes.h

clean:
	rm -f ctool prototypes.h

check:
	make -s -C ../tools wcheck
	for FILE in *.c; do ../tools/wcheck $$FILE; done
