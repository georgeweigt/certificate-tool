#include "defs.h"

int
main(int argc, char *argv[])
{
	int err;
	char *filename;
	struct certinfo *p;

	if (argc < 2)
		filename = "../tools/cert.pem";
	else
		filename = argv[1];

	p = read_certificate(filename);

	if (p == NULL) {
		printf("error reading certificate\n");
		return 1;
	}

	err = parse_certificate(p);

	if (err) {
		printf("error parsing certificate\n");
		return 1;
	}

	printf("ok\n");

	return 0;
}

void
print_buf(uint8_t *buf, int length)
{
	int i;
	for (i = 0; i < length; i++) {
		printf("%02x", buf[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	if (length % 16)
		printf("\n");
}
