#include "defs.h"

// Sign p with q and return the result (key is q's private key)

struct certinfo *
sign_certificate(struct certinfo *p, struct certinfo *q, struct keyinfo *key)
{
	int err, i, j, k, n;
	uint8_t *buf;
	struct certinfo *r;

	// adjust for length change

	n = p->cert_length - p->issuer_length + q->issuer_length;

	switch (key->key_type) {

	case RSA_ENCRYPTION:
		n = n - p->signature_length + key->modulus_length;
		break;

	case PRIME256V1:
	case SECP384R1:
		n = n - p->signature_length + 2 * key->ec_private_key_length;
		break;

	default:
		return NULL;
	}

	// malloc with some extra space to accommodate possible changes in length encoding

	r = malloc(sizeof (struct certinfo) + n + 64);

	if (r == NULL)
		malloc_kaput();

	buf = r->cert_data;

	// two SEQUENCE headers occupy 8 bytes

	k = 8;

	// copy from p up to first signature algorithm oid

	i = p->info_offset;
	j = p->serial_number_offset + p->serial_number_length; // start of signature algorithm
	n = j - i;
	memcpy(buf + k, p->cert_data + i, n);
	k += n;

	// signature algorithm

	k += sign_signature_algorithm(buf + k, p, key);

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

	// signature algorithm (again)

	k += sign_signature_algorithm(buf + k, p, key);

	// set up for signature

	switch (key->key_type) {

	case RSA_ENCRYPTION:
		n = key->modulus_length;
		if (n & 1)
			n = n - 1; // length might be +1 due to encoding rules
		buf[k++] = BIT_STRING;
		buf[k++] = 0x82;
		buf[k++] = (n + 1) >> 8; // add 1 for remainder byte
		buf[k++] = n + 1;
		buf[k++] = 0; // remainder byte
		k += n;
		break;

	case PRIME256V1:
	case SECP384R1:
		// write a dummy signature for parser
		buf[k++] = BIT_STRING;
		buf[k++] = 9; // length
		buf[k++] = 0; // remainder byte
		buf[k++] = SEQUENCE;
		buf[k++] = 6; // length
		buf[k++] = INTEGER;
		buf[k++] = 1; // length
		buf[k++] = 0; // value
		buf[k++] = INTEGER;
		buf[k++] = 1; // length
		buf[k++] = 0; // value
		break;

	default:
		free(r);
		return NULL;
	}

	// write length of cert

	n = k - 4;
	buf[0] = SEQUENCE;
	buf[1] = 0x82;
	buf[2] = n >> 8;
	buf[3] = n;

	r->cert_length = k;

	err = parse_certificate(r);

	if (err) {
		free(r);
		return NULL;
	}

	// sign certificate

	switch (key->key_type) {

	case RSA_ENCRYPTION:
		sign_rsa(r, key);
		break;

	case PRIME256V1:
		sign_prime256v1(r, key);
		break;

	case SECP384R1:
		sign_secp384r1(r, key);
		break;

	default:
		free(r);
		return NULL;
	}

	return r;
}

#define OID_MD5_WITH_RSA_ENCRYPTION "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04\x05\x00"
#define OID_SHA1_WITH_RSA_ENCRYPTION "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00"
#define OID_SHA224_WITH_RSA_ENCRYPTION "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e\x05\x00"
#define OID_SHA256_WITH_RSA_ENCRYPTION "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"
#define OID_SHA384_WITH_RSA_ENCRYPTION "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0C\x05\x00"
#define OID_SHA512_WITH_RSA_ENCRYPTION "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0D\x05\x00"

#define OID_ECDSA_WITH_SHA1 "\x06\x07\x2a\x86\x48\xce\x3d\x04\x01"
#define OID_ECDSA_WITH_SHA224 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x01"
#define OID_ECDSA_WITH_SHA256 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"
#define OID_ECDSA_WITH_SHA384 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03"
#define OID_ECDSA_WITH_SHA512 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04"

// new signature algorithm is a merge of original algorithm and key

int
sign_signature_algorithm(uint8_t *buf, struct certinfo *p, struct keyinfo *key)
{
	switch (key->key_type) {

	case RSA_ENCRYPTION:

		switch (p->signature_algorithm) {

		case MD5_WITH_RSA_ENCRYPTION:
			*buf++ = SEQUENCE;
			*buf++ = 13;
			memcpy(buf, OID_MD5_WITH_RSA_ENCRYPTION, 13);
			return 15;

		case SHA1_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA1:
			*buf++ = SEQUENCE;
			*buf++ = 13;
			memcpy(buf, OID_SHA1_WITH_RSA_ENCRYPTION, 13);
			return 15;

		case SHA224_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA224:
			*buf++ = SEQUENCE;
			*buf++ = 13;
			memcpy(buf, OID_SHA224_WITH_RSA_ENCRYPTION, 13);
			return 15;

		case SHA256_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA256:
			*buf++ = SEQUENCE;
			*buf++ = 13;
			memcpy(buf, OID_SHA256_WITH_RSA_ENCRYPTION, 13);
			return 15;

		case SHA384_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA384:
			*buf++ = SEQUENCE;
			*buf++ = 13;
			memcpy(buf, OID_SHA384_WITH_RSA_ENCRYPTION, 13);
			return 15;

		case SHA512_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA512:
			*buf++ = SEQUENCE;
			*buf++ = 13;
			memcpy(buf, OID_SHA512_WITH_RSA_ENCRYPTION, 13);
			return 15;

		default:
			break;
		}
		break;

	case PRIME256V1:
	case SECP384R1:

		switch (p->signature_algorithm) {

		case MD5_WITH_RSA_ENCRYPTION:
		case SHA1_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA1:
			*buf++ = SEQUENCE;
			*buf++ = 9;
			memcpy(buf, OID_ECDSA_WITH_SHA1, 9);
			return 11;

		case SHA224_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA224:
			*buf++ = SEQUENCE;
			*buf++ = 10;
			memcpy(buf, OID_ECDSA_WITH_SHA224, 10);
			return 12;

		case SHA256_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA256:
			*buf++ = SEQUENCE;
			*buf++ = 10;
			memcpy(buf, OID_ECDSA_WITH_SHA256, 10);
			return 12;

		case SHA384_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA384:
			*buf++ = SEQUENCE;
			*buf++ = 10;
			memcpy(buf, OID_ECDSA_WITH_SHA384, 10);
			return 12;

		case SHA512_WITH_RSA_ENCRYPTION:
		case ECDSA_WITH_SHA512:
			*buf++ = SEQUENCE;
			*buf++ = 10;
			memcpy(buf, OID_ECDSA_WITH_SHA384, 10);
			return 12;

		default:
			break;
		}
		break;

	default:
		break;
	}

	return 0;
}

void
sign_rsa(struct certinfo *r, struct keyinfo *key)
{
	uint8_t *sig = NULL;

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

	if (sig == NULL)
		return;

	// copy signature

	memcpy(r->cert_data + r->signature_offset, sig, r->signature_length);

	free(sig);

	// encrypt signature (RSA decrypt procedure is used to encrypt signature)

	rsa_decrypt(r->cert_data + r->signature_offset, r->signature_length, key);
}

void
sign_prime256v1(struct certinfo *r, struct keyinfo *key)
{
	int len;
	uint8_t hash[64];

	len = r->info_offset + r->info_length - r->top_offset;

	switch (r->signature_algorithm) {

	case ECDSA_WITH_SHA1:
		sha1(r->cert_data + r->top_offset, len, hash);
		len = 20;
		break;

	case ECDSA_WITH_SHA224:
		sha224(r->cert_data + r->top_offset, len, hash);
		len = 28;
		break;

	case ECDSA_WITH_SHA256:
		sha256(r->cert_data + r->top_offset, len, hash);
		len = 32;
		break;

	case ECDSA_WITH_SHA384:
		sha384(r->cert_data + r->top_offset, len, hash);
		len = 32; // truncate 48 to 32
		break;

	case ECDSA_WITH_SHA512:
		sha512(r->cert_data + r->top_offset, len, hash);
		len = 32; // truncate 64 to 32
		break;

	default:
		return;
	}

	len = ecdsa256_sign_cert(r, key, hash, len);

	// fix up length

	r->signature_length = len - 3; // subtract 3 for BIT STRING header

	r->cert_length = r->signature_algorithm_offset + r->signature_algorithm_length + len;

	r->top_length = r->cert_length - 4;

	r->cert_data[0] = SEQUENCE;
	r->cert_data[1] = 0x82;
	r->cert_data[2] = r->top_length >> 8;
	r->cert_data[3] = r->top_length;
}

void
sign_secp384r1(struct certinfo *r, struct keyinfo *key)
{
	int len;
	uint8_t hash[64];

	len = r->info_offset + r->info_length - r->top_offset;

	switch (r->signature_algorithm) {

	case ECDSA_WITH_SHA1:
		sha1(r->cert_data + r->top_offset, len, hash);
		len = 20;
		break;

	case ECDSA_WITH_SHA224:
		sha224(r->cert_data + r->top_offset, len, hash);
		len = 28;
		break;

	case ECDSA_WITH_SHA256:
		sha256(r->cert_data + r->top_offset, len, hash);
		len = 32;
		break;

	case ECDSA_WITH_SHA384:
		sha384(r->cert_data + r->top_offset, len, hash);
		len = 48;
		break;

	case ECDSA_WITH_SHA512:
		sha512(r->cert_data + r->top_offset, len, hash);
		len = 48; // truncate 64 to 48
		break;

	default:
		return;
	}

	len = ecdsa384_sign_cert(r, key, hash, len);

	// fix up length

	r->signature_length = len - 3; // subtract 3 for BIT STRING header

	r->cert_length = r->signature_algorithm_offset + r->signature_algorithm_length + len;

	r->top_length = r->cert_length - 4;

	r->cert_data[0] = SEQUENCE;
	r->cert_data[1] = 0x82;
	r->cert_data[2] = r->top_length >> 8;
	r->cert_data[3] = r->top_length;
}
