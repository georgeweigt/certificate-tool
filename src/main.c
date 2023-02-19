int
main(int argc, char *argv[])
{
	srandom(time(NULL));

	ec_init();

	if (argc == 4 && strcmp(argv[1], "check") == 0) {
		check(argv[2], argv[3]);
		return 0;
	}

	if (argc == 3 && strcmp(argv[1], "key") == 0) {
		key(argv[2]);
		return 0;
	}

	if (argc == 5 && strcmp(argv[1], "sign") == 0) {
		sign(argv[2], argv[3], argv[4]);
		return 0;
	}

	printf("what?\n");

	return 1;
}

void
check(char *filename1, char *filename2)
{
	int err;
	struct certinfo *p, *q;

	p = get_cert(filename1);

	if (p == NULL)
		return;

	q = get_cert(filename2);

	if (q == NULL) {
		free(p);
		return;
	}

	err = check_signature(p, q);

	if (err == 0)
		printf("ok\n");
	else
		printf("fail\n");

	free(p);
	free(q);
}

void
key(char *filename)
{
	struct keyinfo *key;

	key = get_key(filename);

	if (key == NULL)
		return;

	if (key->key_type == 0) {
		printf("unsupported key type\n");
		free(key);
		return;
	}

	print_key_data(key);

	free(key);
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
		print_bss("prime256v1 private key", p->key_data + p->ec_private_key_offset, p->ec_private_key_length);
		print_bss("prime256v1 public key", p->key_data + p->ec_public_key_offset, p->ec_public_key_length);
		break;

	case SECP384R1:
		print_bss("secp384r1 private key", p->key_data + p->ec_private_key_offset, p->ec_private_key_length);
		print_bss("secp384r1 public key", p->key_data + p->ec_public_key_offset, p->ec_public_key_length);
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
sign(char *filename1, char *filename2, char *filename3)
{
	int i, m, n;
	struct certinfo *p, *q, *r;
	struct keyinfo *key;

	p = get_cert(filename1);

	if (p == NULL)
		return;

	q = get_cert(filename2);

	if (q == NULL) {
		free(p);
		return;
	}

	key = get_key(filename3);

	if (key == NULL) {
		free(p);
		free(q);
		return;
	}

	r = sign_certificate(p, q, key);

	if (r == NULL) {
		printf("fail\n");
		free(p);
		free(q);
		free(key);
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

	free(p);
	free(q);
	free(r);
	free(key);
}

struct certinfo *
get_cert(char *filename)
{
	int err;
	struct certinfo *p;

	p = read_certificate(filename);

	if (p == NULL) {
		printf("error reading certificate %s\n", filename);
		return NULL;
	}

	err = parse_certificate(p);

	if (err) {
		printf("error parsing certificate %s (see parse_certificate.c, line %d)\n", filename, p->line);
		free(p);
		return NULL;
	}

	return p;
}

struct keyinfo *
get_key(char *filename)
{
	int err;
	struct keyinfo *key;

	key = read_key_file(filename);

	if (key == NULL) {
		printf("error reading key %s\n", filename);
		return NULL;
	}

	err = parse_key_data(key);

	if (err) {
		printf("error parsing key %s (see parse_key_data.c, line %d)\n", filename, key->line);
		free(key);
		return NULL;
	}

	return key;
}

void
malloc_kaput(void)
{
	printf("malloc kaput\n");
	exit(1);
}
