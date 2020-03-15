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
		err = ec256_verify(p, q);
		break;

	case SECP384R1:
		err = ec384_verify(p, q);
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
		sig = pkcs_md5_signature(p);
		break;

	case SHA1_WITH_RSA_ENCRYPTION:
		sig = pkcs_sha1_signature(p);
		break;

	case SHA224_WITH_RSA_ENCRYPTION:
		sig = pkcs_sha224_signature(p);
		break;

	case SHA256_WITH_RSA_ENCRYPTION:
		sig = pkcs_sha256_signature(p);
		break;

	case SHA384_WITH_RSA_ENCRYPTION:
		sig = pkcs_sha384_signature(p);
		break;

	case SHA512_WITH_RSA_ENCRYPTION:
		sig = pkcs_sha512_signature(p);
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
