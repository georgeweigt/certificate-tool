#define MLENGTH(u) (u)[-1]

// Decrypts p's signature using q's public key and returns the result.
//
// On success, result is returned in a malloc'd buffer that caller should free.
//
// Length of buffer is the same as signature length.
//
// Returns NULL on error.

uint8_t *
rsa_decrypt_signature(struct certinfo *p, struct certinfo *q)
{
	int i, n;
	uint8_t *buf;
	uint32_t *a, *b, *c, *d;

	// check length

	if (p->signature_length != q->modulus_length - 1)
		return NULL;

	// compute (signature ** exponent) mod modulus

	a = buf_to_int(p->cert_data + p->signature_offset, p->signature_length);
	b = buf_to_int(q->cert_data + q->exponent_offset, q->exponent_length);
	c = buf_to_int(q->cert_data + q->modulus_offset, q->modulus_length);

	d = modpow(a, b, c);

	mfree(a);
	mfree(b);
	mfree(c);

	n = MLENGTH(d); // number of uint32_t in result

	if (4 * n > p->signature_length) {
		mfree(d);
		return NULL; // bad modulus
	}

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	memset(buf, 0, p->signature_length);

	// convert result to big endian

	for (i = 0; i < n; i++) {
		buf[p->signature_length - 4 * i - 4] = d[i] >> 24;
		buf[p->signature_length - 4 * i - 3] = d[i] >> 16;
		buf[p->signature_length - 4 * i - 2] = d[i] >> 8;
		buf[p->signature_length - 4 * i - 1] = d[i];
	}

	mfree(d);

	return buf;
}

void
rsa_encrypt_signature(uint8_t *sig, int len, struct keyinfo *key)
{
	int i;
	uint32_t *a, *b, *c, *d, *e1, *e2, *h, *m1, *m2, n, *p, *q, *qinv, *t;

	p = buf_to_int(key->key_data + key->prime1_offset, key->prime1_length);
	q = buf_to_int(key->key_data + key->prime2_offset, key->prime2_length);

	e1 = buf_to_int(key->key_data + key->exponent1_offset, key->exponent1_length);
	e2 = buf_to_int(key->key_data + key->exponent2_offset, key->exponent2_length);

	qinv = buf_to_int(key->key_data + key->coefficient_offset, key->coefficient_length);

	c = buf_to_int(sig, len);

	m1 = modpow(c, e1, p);
	m2 = modpow(c, e2, q);

	if (mcmp(m1, m2) < 0) {
		t = step_up(m1, p, q);
		mfree(m1);
		m1 = t;
	}

	d = msub(m1, m2);
	h = mmul(qinv, d);
	mmod(h, p);
	b = mmul(h, q);
	a = madd(m2, b);

	n = MLENGTH(a); // number of uint32_t in result

	memset(sig, 0, len);

	if (4 * n <= len) {
		for (i = 0; i < n; i++) {
			sig[len - 4 * i - 4] = a[i] >> 24;
			sig[len - 4 * i - 3] = a[i] >> 16;
			sig[len - 4 * i - 2] = a[i] >> 8;
			sig[len - 4 * i - 1] = a[i];
		}
	}

	mfree(a);
	mfree(b);
	mfree(c);
	mfree(e1);
	mfree(e2);
	mfree(d);
	mfree(h);
	mfree(m1);
	mfree(m2);
	mfree(p);
	mfree(q);
	mfree(qinv);
}

// returns m + ceil(q / p) * p

uint32_t *
step_up(uint32_t *m, uint32_t *p, uint32_t *q)
{
	uint32_t *a, *t;
	a = mdiv(q, p);
	t = mmul(a, p);
	mfree(a);
	a = t;
	if (mcmp(a, q) == 0)
		; // no remainder
	else {
		t = madd(a, p);
		mfree(a);
		a = t;
	}
	t = madd(m, a);
	mfree(a);
	return t;
}

// returns (a ** b) mod c

uint32_t *
modpow(uint32_t *a, uint32_t *b, uint32_t *c)
{
	uint32_t *t, *y;

	a = mcopy(a);
	b = mcopy(b);

	// y = 1

	y = mint(1);

	for (;;) {

		if (b[0] & 1) {

			// y = (y * a) mod c

			t = mmul(y, a);
			mfree(y);
			y = t;
			mmod(y, c);
		}

		// b = b >> 1

		mshr(b);

		if (MLENGTH(b) == 1 && b[0] == 0)
			break; // b == 0

		// a = (a * a) mod c

		t = mmul(a, a);
		mfree(a);
		a = t;
		mmod(a, c);
	}

	mfree(a);
	mfree(b);

	return y;
}

// u = u >> 1

void
mshr(uint32_t *u)
{
	int i;
	for (i = 0; i < MLENGTH(u) - 1; i++) {
		u[i] >>= 1;
		if (u[i + 1] & 1)
			u[i] |= 0x80000000;
	}
	u[i] >>= 1;
	while (MLENGTH(u) > 1 && u[MLENGTH(u) - 1] == 0)
		MLENGTH(u)--;
}

// returns u + v

uint32_t *
madd(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	if (nu > nv)
		nw = nu + 1;
	else
		nw = nv + 1;
	w = mnew(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (uint64_t) w[i] + v[i];
		w[i] = t;
		t >>= 32;
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t >>= 32;
	}
	mnorm(w);
	return w;
}

// returns u - v

uint32_t *
msub(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	if (nu > nv)
		nw = nu;
	else
		nw = nv;
	w = mnew(nw);
	for (i = 0; i < nu; i++)
		w[i] = u[i];
	for (i = nu; i < nw; i++)
		w[i] = 0;
	t = 0;
	for (i = 0; i < nv; i++) {
		t += (uint64_t) w[i] - v[i];
		w[i] = t;
		t = (int64_t) t >> 32; // cast to extend sign
	}
	for (i = nv; i < nw; i++) {
		t += w[i];
		w[i] = t;
		t = (int64_t) t >> 32; // cast to extend sign
	}
	mnorm(w);
	return w;
}

// returns u * v

uint32_t *
mmul(uint32_t *u, uint32_t *v)
{
	int i, j, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	nw = nu + nv;
	w = mnew(nw);
	for (i = 0; i < nu; i++)
		w[i] = 0;
	for (j = 0; j < nv; j++) {
		t = 0;
		for (i = 0; i < nu; i++) {
			t += (uint64_t) u[i] * v[j] + w[i + j];
			w[i + j] = t;
			t >>= 32;
		}
		w[i + j] = t;
	}
	mnorm(w);
	return w;
}

// returns floor(u / v)

uint32_t *
mdiv(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t *q, qhat, *w;
	uint64_t a, b, t;
	mnorm(u);
	mnorm(v);
	if (MLENGTH(v) == 1 && v[0] == 0)
		return NULL; // v = 0
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	k = nu - nv;
	if (k < 0) {
		q = mnew(1);
		q[0] = 0;
		return q; // u < v, return zero
	}
	u = mcopy(u);
	q = mnew(k + 1);
	w = mnew(nv + 1);
	b = v[nv - 1];
	do {
		q[k] = 0;
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (uint64_t) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (uint64_t) u[i] - w[i - k];
				u[i] = t;
				t = (int64_t) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (uint64_t) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			q[k] += qhat;
			mnorm(u);
			nu = MLENGTH(u);
		}
	} while (--k >= 0);
	mnorm(q);
	mfree(u);
	mfree(w);
	return q;
}

// u = u mod v

void
mmod(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t qhat, *w;
	uint64_t a, b, t;
	mnorm(u);
	mnorm(v);
	if (MLENGTH(v) == 1 && v[0] == 0)
		return; // v = 0
	nu = MLENGTH(u);
	nv = MLENGTH(v);
	k = nu - nv;
	if (k < 0)
		return; // u < v
	w = mnew(nv + 1);
	b = v[nv - 1];
	do {
		while (nu >= nv + k) {
			// estimate 32-bit partial quotient
			a = u[nu - 1];
			if (nu > nv + k)
				a = a << 32 | u[nu - 2];
			if (a < b)
				break;
			qhat = a / (b + 1);
			if (qhat == 0)
				qhat = 1;
			// w = qhat * v
			t = 0;
			for (i = 0; i < nv; i++) {
				t += (uint64_t) qhat * v[i];
				w[i] = t;
				t >>= 32;
			}
			w[nv] = t;
			// u = u - w
			t = 0;
			for (i = k; i < nu; i++) {
				t += (uint64_t) u[i] - w[i - k];
				u[i] = t;
				t = (int64_t) t >> 32; // cast to extend sign
			}
			if (t) {
				// u is negative, restore u
				t = 0;
				for (i = k; i < nu; i++) {
					t += (uint64_t) u[i] + w[i - k];
					u[i] = t;
					t >>= 32;
				}
				break;
			}
			mnorm(u);
			nu = MLENGTH(u);
		}
	} while (--k >= 0);
	mfree(w);
}

// compare u and v

int
mcmp(uint32_t *u, uint32_t *v)
{
	int i;
	mnorm(u);
	mnorm(v);
	if (MLENGTH(u) < MLENGTH(v))
		return -1;
	if (MLENGTH(u) > MLENGTH(v))
		return 1;
	for (i = MLENGTH(u) - 1; i >= 0; i--) {
		if (u[i] < v[i])
			return -1;
		if (u[i] > v[i])
			return 1;
	}
	return 0; // u = v
}

uint32_t *
mint(int k)
{
	uint32_t *u;
	u = mnew(1);
	u[0] = k;
	u[-1] = 1;
	return u;
}

uint32_t *
mnew(int n)
{
	uint32_t *p;
	p = (uint32_t *) malloc((n + 1) * sizeof (uint32_t));
	if (p == NULL)
		malloc_kaput();
	*p = n;
	return p + 1;
}

void
mfree(uint32_t *p)
{
	free(p - 1);
}

uint32_t *
mcopy(uint32_t *u)
{
	int i;
	uint32_t *v;
	v = mnew(MLENGTH(u));
	for (i = 0; i < MLENGTH(u); i++)
		v[i] = u[i];
	return v;
}

// remove leading zeroes

void
mnorm(uint32_t *u)
{
	while (MLENGTH(u) > 1 && u[MLENGTH(u) - 1] == 0)
		MLENGTH(u)--;
}

uint32_t *
buf_to_int(uint8_t *buf, int len)
{
	int i, n, t;
	uint32_t *a;
	n = (len + 3) / 4;
	a = mnew(n);
	t = 0;
	for (i = 0; i < len; i++) {
		t = t << 8 | buf[i];
		if ((len - i - 1) % 4 == 0) {
			a[--n] = t;
			t = 0;
		}
	}
	mnorm(a);
	return a;
}

uint32_t *
str_to_int(char *s)
{
	int d, i, len, n;
	uint32_t *a;
	len = strlen(s);
	n = ((len + 1) / 2 + 3) / 4; // convert len to number of uint32_t
	a = mnew(n);
	for (i = 0; i < n; i++)
		a[i] = 0;
	for (i = 0; i < len; i++) {
		d = s[len - i - 1];
		if (d >= '0' && d <= '9')
			d = d - '0';
		else if (d >= 'A' && d <= 'F')
			d = d - 'A' + 10;
		else if (d >= 'a' && d <= 'f')
			d = d - 'a' + 10;
		else {
			mfree(a);
			return NULL;
		}
		a[i / 8] |= d << (4 * (i % 8));
	}
	mnorm(a);
	return a;
}
