#include "defs.h"

// encrypts a hash value (32 bytes max) and returns the 64 byte result in sig

void
ec256_encrypt(struct keyinfo *key, uint8_t *hash, int len, uint8_t *sig)
{
	uint32_t *d, *h;

	h = ec_buf_to_bignum(hash, len);
	d = ec_buf_to_bignum(key->key_data + key->ec_private_key_offset, key->ec_private_key_length);

	ec256_encrypt_nib(h, d, sig);

	ec_free(h);
	ec_free(d);
}

void
ec256_encrypt_nib(uint32_t *h, uint32_t *d, uint8_t *sig)
{
	int i, n;
	uint32_t *k, *r, *s, *t;
	struct point G, R;

	G.x = gx256;
	G.y = gy256;
	G.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	for (;;) {

		// choose k from [1, n - 1]

		k = ec_new(8);
		for (i = 0; i < 8; i++)
			k[i] = random();
		ec_norm(k);
		ec_mod(k, q256);
		if (ec_equal(k, 0)) {
			ec_free(k);
			continue;
		}

		// R = k * G

		ec_mult(&R, k, &G, p256);
		ec_affinify(&R, p256);

		// r = R.x mod n

		r = ec_dup(R.x);
		ec_mod(r, q256);

		if (ec_equal(r, 0)) {
			ec_free(k);
			ec_free(r);
			ec_free_xyz(&R);
			continue;
		}

		// k = 1 / k

		t = ec_modinv(k, q256);
		ec_free(k);
		k = t;

		// s = k * (h + r * d) mod n

		s = ec_mul(r, d);
		ec_mod(s, q256);

		t = ec_add(h, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

		t = ec_mul(k, s);
		ec_free(s);
		s = t;
		ec_mod(s, q256);

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

	memset(sig, 0, 64);

	n = ec_len(r); // number of uint32_t

	if (n <= 8) {
		for (i = 0; i < n; i++) {
			sig[32 - 4 * i - 4] = r[i] >> 24;
			sig[32 - 4 * i - 3] = r[i] >> 16;
			sig[32 - 4 * i - 2] = r[i] >> 8;
			sig[32 - 4 * i - 1] = r[i];
		}
	}

	n = ec_len(s); // number of uint32_t

	if (n <= 8) {
		for (i = 0; i < n; i++) {
			sig[64 - 4 * i - 4] = s[i] >> 24;
			sig[64 - 4 * i - 3] = s[i] >> 16;
			sig[64 - 4 * i - 2] = s[i] >> 8;
			sig[64 - 4 * i - 1] = s[i];
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
// q->encryption_algorithm is PRIME256V1

int
ec256_verify(struct certinfo *p, struct certinfo *q)
{
	int err, len;
	uint8_t hash[64];
	uint32_t *h, *r, *s, *x, *y;

	if (q->ec_key_length != 65)
		return -1;

	switch (p->signature_algorithm) {
	case ECDSA_WITH_SHA1:
		sha1(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		len = 20;
		break;
	case ECDSA_WITH_SHA224:
		sha224(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		len = 28;
		break;
	case ECDSA_WITH_SHA256:
		sha256(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		len = 32;
		break;
	case ECDSA_WITH_SHA384:
		sha384(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		len = 32; // truncate 48 to 32
		break;
	case ECDSA_WITH_SHA512:
		sha512(p->cert_data + p->top_offset, p->info_offset + p->info_length - p->top_offset, hash);
		len = 32; // truncate 64 to 32
		break;
	default:
		return -1;
	}

	h = ec_buf_to_bignum(hash, len);

	r = ec_buf_to_bignum(p->cert_data + p->r_offset, p->r_length);
	s = ec_buf_to_bignum(p->cert_data + p->s_offset, p->s_length);

	x = ec_buf_to_bignum(q->cert_data + q->ec_key_offset + 1, 32); // first byte is 04
	y = ec_buf_to_bignum(q->cert_data + q->ec_key_offset + 33, 32);

	err = ec256_verify_nib(h, r, s, x, y);

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
ec256_verify_nib(uint32_t *h, uint32_t *r, uint32_t *s, uint32_t *x, uint32_t *y)
{
	int err;
	uint32_t *u, *v, *w;
	struct point R, S, T;

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	S.x = gx256;
	S.y = gy256;
	S.z = ec_int(1);

	T.x = x;
	T.y = y;
	T.z = ec_int(1);

	w = ec_modinv(s, q256);

	u = ec_mul(h, w);
	ec_mod(u, q256);

	v = ec_mul(r, w);
	ec_mod(v, q256);

	ec_twin_mult(&R, u, &S, v, &T, p256);

	ec_affinify(&R, p256);

	ec_mod(R.x, q256);

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
