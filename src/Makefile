CC = gcc
CFLAGS = -Wall -O0

objects = \
main.o \
read_certificate.o \
parse_certificate.o \
base64.o \
check_signature.o \
encrypt_signature_rsa.o \
rsa.o \
ec.o \
md5.o \
sha1.o \
sha224.o \
sha256.o \
sha384.o \
sha512.o

ctool : $(objects)
	gcc $(objects) -o ctool

$(objects) : defs.h prototypes.h

clean :
	rm -f ctool *.o *.pem
