Plain and simple encryption code for certificates.

The main function is a demo.

To build and run:

	cd src
	make
	./ctool

Check that certificate A is signed by B:

	./ctool check A.pem B.pem

Print certificate keys:

	./ctool key key.pem

Sign certificate A with B and save as C:

	./ctool sign A.pem B.pem key.pem | tee C.pem

There are scripts in the tools directory for creating certificate files.

Example:

	cd tools
	./m2
	../src/ctool sign a.pem b.pem key.pem | tee c.pem
	../src/ctool check c.pem b.pem

Supported public key algorithms:

	RSA
	prime256v1 (NIST P-256)
	secp384r1 (NIST P-384)

Supported hash algorithms:

	MD5
	SHA1
	SHA224
	SHA256
	SHA384
	SHA512
