#include "defs.h"

// is p signed by q? (returns 0 for yes, -1 for no)

int
check_signature(struct certinfo *p, struct certinfo *q)
{
	int err = -1;

	// check that p->issuer matches q->subject

	if (p->issuer_length != q->subject_length)
		return -1;

	if (memcmp(p->cert_data + p->issuer_offset, q->cert_data + q->subject_offset, p->issuer_length) != 0)
		return -1;

	// switch on issuer's public key algorithm

	switch (q->encryption_algorithm) {

	case RSA_ENCRYPTION:
		err = check_rsa_signature(p, q);
		break;

	case PRIME256V1:
		err = ecdsa256_verify(p, q);
		break;

	case SECP384R1:
		err = ecdsa384_verify(p, q);
		break;
	}

	return err;
}

int
check_rsa_signature(struct certinfo *p, struct certinfo *q)
{
	int err;
	uint8_t *buf, *sig = NULL;

	// switch on subject's signature algorithm

	switch (p->signature_algorithm) {

	case MD5_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_md5_signature(p);
		break;

	case SHA1_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha1_signature(p);
		break;

	case SHA224_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha224_signature(p);
		break;

	case SHA256_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha256_signature(p);
		break;

	case SHA384_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha384_signature(p);
		break;

	case SHA512_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha512_signature(p);
		break;
	}

	if (sig == NULL)
		return -1;

	buf = rsa_encrypt_signature(p, q);

	if (memcmp(buf, sig, p->signature_length) == 0)
		err = 0;
	else
		err = -1;

	free(buf);
	free(sig);

	return err;
}

uint8_t *
gen_pkcs_md5_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf;

	n = p->signature_length - 37; // 3 + 18 + 16 = 37

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10", 18);

	k += 18;

	md5(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, buf + k);

	return buf;
}

uint8_t *
gen_pkcs_sha1_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf;

	n = p->signature_length - 38; // 3 + 15 + 20 = 38 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 15);

	k += 15;

	sha1(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, buf + k);

	return buf;
}

uint8_t *
gen_pkcs_sha224_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf;

	n = p->signature_length - 50; // 3 + 19 + 28 = 50 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x29\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x18", 19);

	memcpy(buf + k, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c", 19);

	k += 19;

	sha224(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, buf + k);

	return buf;
}

uint8_t *
gen_pkcs_sha256_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf;

	n = p->signature_length - 54; // 3 + 19 + 32 = 54 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 19);

	k += 19;

	sha256(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, buf + k);

	return buf;
}

uint8_t *
gen_pkcs_sha384_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf;

	n = p->signature_length - 70; // 3 + 19 + 48 = 70 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30", 19);

	k += 19;

	sha384(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, buf + k);

	return buf;
}

uint8_t *
gen_pkcs_sha512_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf;

	n = p->signature_length - 86; // 3 + 19 + 64 = 86 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40", 19);

	k += 19;

	sha512(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, buf + k);

	return buf;
}
