ctool is an app that uses the crypto library.

To build ctool

```
cd src
make
```

Shell scripts m1-m5 create certificate files for demo.

```
./m1
```

Sign certificate A with B and save as C.

```
./sign
```

Check that certificate C is signed by B.

```
./check
```

Print certificate keys.

```
./ctool key key.pem
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
