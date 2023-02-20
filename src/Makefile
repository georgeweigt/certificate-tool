.PHONY: clean checkall

HFILES := $(shell ls *.h)
CFILES := $(shell ls *.c)

# specify prototypes.h in case it's missing from HFILES

ctool: prototypes.h $(HFILES) $(CFILES)
	gcc -Wall -O0 -o ctool -include defs.h -include prototypes.h $(CFILES) -lm

prototypes.h: $(CFILES)
	make -s -C ../tools make-prototypes
	../tools/make-prototypes . > prototypes.h

clean:
	rm -f ctool prototypes.h

checkall:
	make -s -C ../tools wcheck
	for FILE in $(HFILES); do ../tools/wcheck $$FILE; done
	for FILE in $(CFILES); do ../tools/wcheck $$FILE; done
