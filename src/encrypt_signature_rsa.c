#include "defs.h"

// Returns (signature ** exponent) mod modulus
//
//	p	subject certificate (signature)
//
//	q	issuer certificate (exponent, modulus)

uint8_t *
encrypt_signature_rsa(struct certinfo *p, struct certinfo *q)
{
	int i;
	uint8_t *z;
	uint32_t *a, *b, *c, *y;

	a = buf_to_int(p->cert_data + p->signature_offset, p->signature_length);
	b = buf_to_int(q->cert_data + q->exponent_offset, q->exponent_length);
	c = buf_to_int(q->cert_data + q->modulus_offset, q->modulus_length);

	y = modpow(a, b, c);

	z = malloc(p->signature_length);

	if (z == NULL)
		malloc_kaput();

	bzero(z, p->signature_length);

	for (i = 0; i < y[-1]; i++) {
		if (p->signature_length - 4 * i - 4 < 0)
			break; // buffer overrun
		z[p->signature_length - 4 * i - 4] = y[i] >> 24;
		z[p->signature_length - 4 * i - 3] = y[i] >> 16;
		z[p->signature_length - 4 * i - 2] = y[i] >> 8;
		z[p->signature_length - 4 * i - 1] = y[i];
	}

	mfree(a);
	mfree(b);
	mfree(c);
	mfree(y);

	return z;
}
