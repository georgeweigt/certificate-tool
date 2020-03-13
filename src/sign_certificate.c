#include "defs.h"

// Sign p with q and return the result (key is q's private key)

struct certinfo *
sign_certificate(struct certinfo *p, struct certinfo *q, struct keyinfo *key)
{
	int err, i, j, k, n;
	uint8_t *buf, *sig = NULL;
	struct certinfo *r;

	// adjust length for changed issuer and signature

	n = p->cert_length - p->issuer_length + q->issuer_length;
	n = n - p->signature_length + key->modulus_length;

	// malloc with some extra space to accommodate possible changes in length encoding

	r = malloc(sizeof (struct certinfo) + n + 64);

	if (r == NULL)
		malloc_kaput();

	buf = r->cert_data;

	// two SEQUENCE headers occupy 8 bytes

	k = 8;

	// copy from p up to issuer

	i = p->info_offset;
	j = p->algorithm_offset + p->algorithm_length; // start of issuer
	n = j - i;
	memcpy(buf + k, p->cert_data + i, n);
	k += n;

	// copy issuer from q

	i = q->algorithm_offset + q->algorithm_length; // start of issuer
	j = q->issuer_offset + q->issuer_length; // end of issuer
	n = j - i;
	memcpy(buf + k, q->cert_data + i, n);
	k += n;

	// copy from p up to signature algorithm

	i = p->issuer_offset + p->issuer_length; // start of validity
	j = p->info_offset + p->info_length; // start of signature algorithm
	n = j - i;
	memcpy(buf + k, p->cert_data + i, n);
	k += n;

	// write length of cert info

	n = k - 8;
	buf[4] = SEQUENCE;
	buf[5] = 0x82;
	buf[6] = n >> 8;
	buf[7] = n;

	// copy signature algorithm from p

	i = p->info_offset + p->info_length; // start of signature algorithm
	j = p->signature_algorithm_offset + p->signature_algorithm_length;
	n = j - i;
	memcpy(buf + k, p->cert_data + i, n);
	k += n;

	// set up for signature

	n = q->modulus_length;

	if (n & 1)
		n = n - 1; // length might be +1 due to encoding rules

	buf[k++] = BIT_STRING;
	buf[k++] = 0x82;
	buf[k++] = (n + 1) >> 8; // add 1 for remainder byte
	buf[k++] = n + 1;
	buf[k++] = 0; // remainder byte

	k += n;

	// write length of cert

	n = k - 4;
	buf[0] = SEQUENCE;
	buf[1] = 0x82;
	buf[2] = n >> 8;
	buf[3] = n;

	// sign

	r->cert_length = k;

	err = parse_certificate(r);

	if (err) {
		free(r);
		return NULL;
	}

	switch (r->signature_algorithm) {

	case MD5_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_md5_signature(r);
		break;

	case SHA1_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha1_signature(r);
		break;

	case SHA224_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha224_signature(r);
		break;

	case SHA256_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha256_signature(r);
		break;

	case SHA384_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha384_signature(r);
		break;

	case SHA512_WITH_RSA_ENCRYPTION:
		sig = gen_pkcs_sha512_signature(r);
		break;
	}

	if (sig == NULL) {
		free(r);
		return NULL;
	}

	memcpy(r->cert_data + r->signature_offset, sig, r->signature_length);

	rsa_decrypt(r->cert_data + r->signature_offset, r->signature_length, key);

	free(sig);

	return r;
}
