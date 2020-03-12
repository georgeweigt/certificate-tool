#include "defs.h"

int
main(int argc, char *argv[])
{
	if (argc < 3)
		return 1;

	ec_init();

	if (strcmp(argv[1], "check") == 0) {
		check(argv[2]);
		return 0;
	}

	if (strcmp(argv[1], "key") == 0) {
		key(argv[2]);
		return 0;
	}

	return 1;
}

void
check(char *filename)
{
	int err;
	struct certinfo *p;

	printf("checking signature of %s\n", filename);

	p = read_certificate(filename);

	if (p == NULL) {
		printf("error reading certificate\n");
		return;
	}

	err = parse_certificate(p);

	if (err) {
		printf("error parsing certificate (see parse_certificate.c, line %d)\n", p->line);
		return;
	}

	err = check_signature(p, p);

	if (err) {
		printf("error in signature\n");
		return;
	}

	printf("ok\n");
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

void
malloc_kaput(void)
{
	fprintf(stderr, "malloc kaput\n");
	exit(1);
}
