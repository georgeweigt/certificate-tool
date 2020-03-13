#include "defs.h"

int
main(int argc, char *argv[])
{
	ec_init();

	if (strcmp(argv[1], "check") == 0) {
		if (argc < 4)
			return 1;
		check(argv[2], argv[3]);
		return 0;
	}

	if (strcmp(argv[1], "key") == 0) {
		if (argc < 3)
			return 1;
		key(argv[2]);
		return 0;
	}

	if (strcmp(argv[1], "sign") == 0) {
		if (argc < 5)
			return 1;
		sign(argv[2], argv[3], argv[4]);
		return 0;
	}

	return 1;
}

void
check(char *certfile1, char *certfile2)
{
	int err;
	struct certinfo *p = NULL, *q = NULL;

	p = read_certificate(certfile1);

	if (p == NULL) {
		printf("error reading certificate %s\n", certfile1);
		goto done;
	}

	err = parse_certificate(p);

	if (err) {
		printf("error parsing certificate %s (see parse_certificate.c, line %d)\n", certfile1, p->line);
		goto done;
	}

	q = read_certificate(certfile2);

	if (q == NULL) {
		printf("error reading certificate %s\n", certfile2);
		goto done;
	}

	err = parse_certificate(q);

	if (err) {
		printf("error parsing certificate %s (see parse_certificate.c, line %d)\n", certfile2, q->line);
		return;
	}

	err = check_signature(p, q);

	if (err == 0)
		printf("yes\n");
	else
		printf("no\n");

done:
	if (p)
		free(p);
	if (q)
		free(q);
}

void
key(char *filename)
{
	int err;
	struct keyinfo *p;

	p = read_key_file(filename);

	if (p == NULL) {
		printf("error reading key file\n");
		return;
	}

	err = parse_key_data(p);

	if (err < 0) {
		printf("error parsing key data (see parse_key_data.c, line %d)\n", p->line);
		return;
	}

	if (p->key_type == 0) {
		printf("unsupported key type\n");
		return;
	}

	print_key_data(p);
}

void
print_key_data(struct keyinfo *p)
{
	switch (p->key_type) {

	case RSA_ENCRYPTION:
		print_bss("modulus", p->key_data + p->modulus_offset, p->modulus_length);
		print_bss("public exponent", p->key_data + p->public_exponent_offset, p->public_exponent_length);
		print_bss("private exponent", p->key_data + p->private_exponent_offset, p->private_exponent_length);
		print_bss("prime1", p->key_data + p->prime1_offset, p->prime1_length);
		print_bss("prime2", p->key_data + p->prime2_offset, p->prime2_length);
		print_bss("exponent1", p->key_data + p->exponent1_offset, p->exponent1_length);
		print_bss("exponent2", p->key_data + p->exponent2_offset, p->exponent2_length);
		print_bss("coefficient", p->key_data + p->coefficient_offset, p->coefficient_length);
		break;

	case PRIME256V1:
		print_bss("prime256v1", p->key_data + p->ec_private_key_offset, p->ec_private_key_length);
		break;

	case SECP384R1:
		print_bss("secp384r1", p->key_data + p->ec_private_key_offset, p->ec_private_key_length);
		break;
	}
}

// print block storage segment

void
print_bss(char *s, uint8_t *buf, int length)
{
	int i;

	printf("%s (%d bytes)\n", s, length);

	for (i = 0; i < length; i++) {

		printf("%02x", buf[i]);

		if (i % 16 == 15)
			printf("\n");
		else
			printf(" ");
	}

	if (length % 16)
		printf("\n");

	printf("\n");
}

#define N 48

void
sign(char *certfile1, char *certfile2, char *keyfile)
{
	int err, i, m, n;
	struct certinfo *p, *q, *r;
	struct keyinfo *key;

	p = read_certificate(certfile1);

	if (p == NULL) {
		fprintf(stderr, "error reading certificate %s\n", certfile1);
		return;
	}

	err = parse_certificate(p);

	if (err) {
		fprintf(stderr, "error parsing certificate %s (see parse_certificate.c, line %d)\n", certfile1, p->line);
		return;
	}

	q = read_certificate(certfile2);

	if (q == NULL) {
		fprintf(stderr, "error reading certificate %s\n", certfile2);
		return;
	}

	err = parse_certificate(q);

	if (err) {
		fprintf(stderr, "error parsing certificate %s (see parse_certificate.c, line %d)\n", certfile2, p->line);
		return;
	}

	key = read_key_file(keyfile);

	if (key == NULL) {
		fprintf(stderr, "error reading key %s\n", keyfile);
		return;
	}

	err = parse_key_data(key);

	if (err < 0) {
		fprintf(stderr, "error parsing key %s (see parse_key_data.c, line %d)\n", keyfile, p->line);
		return;
	}

	if (key->key_type != RSA_ENCRYPTION) {
		fprintf(stderr, "unsupported key type\n");
		return;
	}

	r = sign_certificate(p, q, key);

	if (r == NULL) {
		free(r);
		fprintf(stderr, "failed\n");
		return;
	}

	printf("-----BEGIN CERTIFICATE-----\n");

	n = r->cert_length / N;
	m = r->cert_length % N;

	for (i = 0; i < n; i++) {
		base64_print(stdout, r->cert_data + N * i, N);
		printf("\n");
	}

	if (m) {
		base64_print(stdout, r->cert_data + N * n, m);
		printf("\n");
	}

	printf("-----END CERTIFICATE-----\n");

	free(r);
}

void
malloc_kaput(void)
{
	fprintf(stderr, "malloc kaput\n");
	exit(1);
}
