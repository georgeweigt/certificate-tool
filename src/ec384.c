// encrypts a hash value (48 bytes max) and returns the 96 byte result in sig

void
ec384_encrypt(struct keyinfo *key, uint8_t *hash, int len, uint8_t *sig)
{
	uint32_t *d, *h;

	h = ec_buf_to_bignum(hash, len);
	d = ec_buf_to_bignum(key->key_data + key->ec_private_key_offset, key->ec_private_key_length);

	ec384_encrypt_nib(h, d, sig);

	ec_free(h);
	ec_free(d);
}

void
ec384_encrypt_nib(uint32_t *h, uint32_t *d, uint8_t *sig)
{
	int i, n;
	uint32_t *k, *r, *s, *t;
	struct point G, R;

	G.x = gx384;
	G.y = gy384;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(12);
		for (i = 0; i < 12; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q384);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p384);
		ec_affinify(&R, p384);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q384);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q384);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q384);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q384);

		if (ec_equal(s, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free(s);
			ec_free_xyz(&R);
			continue;
		}

		break;
	}

	// the signature is the pair (r, s)

	memset(sig, 0, 96);

	n = ec_len(r); // number of uint32_t

	if (n <= 12) {
		for (i = 0; i < n; i++) {
			sig[48 - 4 * i - 4] = r[i] >> 24;
			sig[48 - 4 * i - 3] = r[i] >> 16;
			sig[48 - 4 * i - 2] = r[i] >> 8;
			sig[48 - 4 * i - 1] = r[i];
		}
	}

	n = ec_len(s); // number of uint32_t

	if (n <= 12) {
		for (i = 0; i < n; i++) {
			sig[96 - 4 * i - 4] = s[i] >> 24;
			sig[96 - 4 * i - 3] = s[i] >> 16;
			sig[96 - 4 * i - 2] = s[i] >> 8;
			sig[96 - 4 * i - 1] = s[i];
		}
	}

	ec_free(k);
	ec_free(r);
	ec_free(s);

	ec_free(G.z);

	ec_free_xyz(&R);
}

// Returns 0 if p is signed by q
//
// p->signature_algorithm is one of
//
//	ECDSA_WITH_SHA1 (20 byte hash)
//	ECDSA_WITH_SHA224 (28 byte hash)
//	ECDSA_WITH_SHA256 (32 byte hash)
//	ECDSA_WITH_SHA384 (48 byte hash)
//	ECDSA_WITH_SHA512 (64 byte hash)
//
// q->encryption_algorithm is SECP384R1

int
ec384_verify(struct certinfo *p, struct certinfo *q)
{
	int err, len;
	uint8_t *buf, hash[64];
	uint32_t *h, *r, *s, *x, *y;

	if (q->ec_key_length != 97)
		return -1;

	buf = p->cert_data + p->info_start;
	len = p->info_offset + p->info_length - p->info_start;

	switch (p->signature_algorithm) {
	case ECDSA_WITH_SHA1:
		sha1(buf, len, hash);
		len = 20;
		break;
	case ECDSA_WITH_SHA224:
		sha224(buf, len, hash);
		len = 28;
		break;
	case ECDSA_WITH_SHA256:
		sha256(buf, len, hash);
		len = 32;
		break;
	case ECDSA_WITH_SHA384:
		sha384(buf, len, hash);
		len = 48;
		break;
	case ECDSA_WITH_SHA512:
		sha512(buf, len, hash);
		len = 48; // truncate 64 to 48
		break;
	default:
		return -1;
	}

	h = ec_buf_to_bignum(hash, len);

	r = ec_buf_to_bignum(p->cert_data + p->r_offset, p->r_length);
	s = ec_buf_to_bignum(p->cert_data + p->s_offset, p->s_length);

	x = ec_buf_to_bignum(q->cert_data + q->ec_key_offset + 1, 48); // first byte is 04
	y = ec_buf_to_bignum(q->cert_data + q->ec_key_offset + 49, 48);

	err = ec384_verify_nib(h, r, s, x, y);

	ec_free(h);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);

	return err;
}

// Returns 0 if hash value matches signature
//
// All arguments are bignums
//
//	h	hash of certificate p
//
//	r, s	signature (from certificate p)
//
//	x, y	public key (from certificate q)

int
ec384_verify_nib(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx384;
	S.y = gy384;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q384);

	u = ec_mul(h, w);
	ec_mod(u, q384);

	v = ec_mul(r, w);
	ec_mod(v, q384);

	ec_twin_mult(&R, u, &S, v, &T, p384);

	ec_affinify(&R, p384);

	ec_mod(R.x, q384);

	if (ec_cmp(R.x, r) == 0)
		err = 0;
	else
		err = -1;

	ec_free_xyz(&R);

	ec_free(S.z);
	ec_free(T.z);
	ec_free(u);
	ec_free(v);
	ec_free(w);

	return err;
}
