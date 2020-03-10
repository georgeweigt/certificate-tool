#include "defs.h"

// is p signed by q? (returns 0 for yes, -1 for no)

int
check_signature(struct certinfo *p, struct certinfo *q)
{
	int err = -1;
	uint8_t hash[64], *z;

	// check that issuer matches subject

	if (p->issuer_length != q->subject_length)
		return -1;

	if (memcmp(p->cert_data + p->issuer_offset, q->cert_data + q->subject_offset, p->issuer_length) != 0)
		return -1;

	switch (p->signature_algorithm) {

	case MD5_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = rsa_encrypt_signature(p, q);
		err = check_md5_signature(p, z);
		free(z);
		break;

	case SHA1_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = rsa_encrypt_signature(p, q);
		err = check_sha1_signature(p, z);
		free(z);
		break;

	case SHA224_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = rsa_encrypt_signature(p, q);
		err = check_sha224_signature(p, z);
		free(z);
		break;

	case SHA256_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = rsa_encrypt_signature(p, q);
		err = check_sha256_signature(p, z);
		free(z);
		break;

	case SHA384_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = rsa_encrypt_signature(p, q);
		err = check_sha384_signature(p, z);
		free(z);
		break;

	case SHA512_WITH_RSA_ENCRYPTION:
		if (q->encryption_algorithm != RSA_ENCRYPTION)
			break;
		z = rsa_encrypt_signature(p, q);
		err = check_sha512_signature(p, z);
		free(z);
		break;

	case ECDSA_WITH_SHA1:
		sha1(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 20);
		break;

	case ECDSA_WITH_SHA224:
		sha224(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 28);
		break;

	case ECDSA_WITH_SHA256:
		sha256(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 32);
		break;

	case ECDSA_WITH_SHA384:
		sha384(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		err = check_ecdsa_signature(p, q, hash, 48);
		break;
	}

	return err;
}

int
check_md5_signature(struct certinfo *p, uint8_t *z)
{
	int i, k;
	uint8_t hash[16];

	if (p->signature_length < 37) // 3 + 18 + 16
		return -1;

	md5(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 37; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10", 18) != 0)
		return -1;

	k += 18;

	if (memcmp(z + k, hash, 16) != 0)
		return -1;

	return 0; // ok
}

int
check_sha1_signature(struct certinfo *p, uint8_t *z)
{
	int i, k;
	uint8_t hash[20];

	if (p->signature_length < 38) // 3 + 15 + 20
		return -1;

	sha1(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 38; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 15) != 0)
		return -1;

	k += 15;

	if (memcmp(z + k, hash, 20) != 0)
		return -1;

	return 0; // ok
}

int
check_sha224_signature(struct certinfo *p, uint8_t *z)
{
	int i, k;
	uint8_t hash[28];

	if (p->signature_length < 50) // 3 + 19 + 28
		return -1;

	sha224(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 50; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x29\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x18", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 28) != 0)
		return -1;

	return 0; // ok
}

int
check_sha256_signature(struct certinfo *p, uint8_t *z)
{
	int i, k;
	uint8_t hash[32];

	if (p->signature_length < 54) // 3 + 19 + 32
		return -1;

	sha256(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 54; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 32) != 0)
		return -1;

	return 0; // ok
}

int
check_sha384_signature(struct certinfo *p, uint8_t *z)
{
	int i, k;
	uint8_t hash[48];

	if (p->signature_length < 70) // 3 + 19 + 48 = 70
		return -1;

	sha384(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 70; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 48) != 0)
		return -1;

	return 0; // ok
}

int
check_sha512_signature(struct certinfo *p, uint8_t *z)
{
	int i, k;
	uint8_t hash[64];

	if (p->signature_length < 86) // 3 + 19 + 64 = 86
		return -1;

	sha512(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);

	k = 0;

	if (z[k++] != 0)
		return -1;

	if (z[k++] != 1)
		return -1;

	for (i = 0; i < p->signature_length - 86; i++)
		if (z[k++] != 0xff)
			return -1;

	if (z[k++] != 0)
		return -1;

	if (memcmp(z + k, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40", 19) != 0)
		return -1;

	k += 19;

	if (memcmp(z + k, hash, 64) != 0)
		return -1;

	return 0; // ok
}

int
check_ecdsa_signature(struct certinfo *p, struct certinfo *q, uint8_t *hash, int hashlen)
{
	int err = -1;

	switch (q->encryption_algorithm) {

	case PRIME256V1:
		err = ecdsa256_verify(p, q, hash, hashlen);
		break;

	case SECP384R1:
		err = ecdsa384_verify(p, q, hash, hashlen);
		break;
	}

	return err;
}
