ctool is an app that uses the library.

To build and run

```
cd src
make
./ctool
```

Sign certificate A with B and save as C.

```
./ctool sign A.pem B.pem key.pem | tee C.pem
```

Check that certificate C is signed by B.

```
./ctool check C.pem B.pem
```

Print certificate keys.

```
./ctool key key.pem
```

There are scripts in the tools directory for creating certificate files.

Example

```
cd tools
./m2
../src/ctool sign a.pem b.pem key.pem | tee c.pem
../src/ctool check c.pem b.pem
```

Supported public key algorithms

```
RSA
prime256v1 (NIST P-256)
secp384r1 (NIST P-384)
```

Supported hash algorithms

```
MD5
SHA1
SHA224
SHA256
SHA384
SHA512
```
