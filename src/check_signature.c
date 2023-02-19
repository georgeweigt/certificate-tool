// Returns 0 if p is signed by q

int
check_signature(struct certinfo *p, struct certinfo *q)
{
	int err = -1;

	// switch on q's encryption algorithm

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

	// switch on p's signature algorithm

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

	buf = rsa_decrypt_signature(p, q);

	if (buf == NULL) {
		free(sig);
		return -1;
	}

	if (memcmp(buf, sig, p->signature_length) == 0)
		err = 0;
	else
		err = -1;

	free(sig);
	free(buf);

	return err;
}
