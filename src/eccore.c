int ec_malloc_count;

uint32_t *p256, *q256, *gx256, *gy256;
uint32_t *p384, *q384, *gx384, *gy384;

// returns 1/c mod p

uint32_t *
ec_modinv(uint32_t *c, uint32_t *p)
{
	uint32_t *k, *r, *u, *v, *t, *x1, *x2;
	u = ec_dup(c);
	v = ec_dup(p);
	x1 = ec_int(1);
	x2 = ec_int(0);
	while (!ec_equal(u, 1) && !ec_equal(v, 1)) {
		while ((u[0] & 1) == 0) {
			ec_shr(u);
			if (x1[0] & 1) {
				t = ec_add(x1, p);
				ec_free(x1);
				x1 = t;
			}
			ec_shr(x1);
		}
		while ((v[0] & 1) == 0) {
			ec_shr(v);
			if (x2[0] & 1) {
				t = ec_add(x2, p);
				ec_free(x2);
				x2 = t;
			}
			ec_shr(x2);
		}
		if (ec_cmp(u, v) >= 0) {
			t = ec_sub(u, v);
			ec_free(u);
			u = t;
			// x1 = x1 - x2
			k = ec_sub(p, x2);
			t = ec_add(x1, k);
			ec_free(x1);
			x1 = t;
			ec_mod(x1, p);
			ec_free(k);
		} else {
			t = ec_sub(v, u);
			ec_free(v);
			v = t;
			// x2 = x2 - x1
			k = ec_sub(p, x1);
			t = ec_add(x2, k);
			ec_free(x2);
			x2 = t;
			ec_mod(x2, p);
			ec_free(k);
		}
	}
	if (ec_equal(u, 1)) {
		r = x1;
		ec_free(x2);
	} else {
		r = x2;
		ec_free(x1);
	}
	ec_free(u);
	ec_free(v);
	return r;
}

void
ec_projectify(struct point *S)
{
	ec_free(S->z);
	S->z = ec_int(1);
}

int
ec_affinify(struct point *S, uint32_t *p)
{
	uint32_t *lambda, *lambda2, *lambda3, *x, *y;

	if (ec_equal(S->z, 0))
		return -1;

	lambda = ec_modinv(S->z, p);

	lambda2 = ec_mul(lambda, lambda);
	ec_mod(lambda2, p);

	lambda3 = ec_mul(lambda2, lambda);
	ec_mod(lambda3, p);

	x = ec_mul(lambda2, S->x);
	ec_mod(x, p);

	y = ec_mul(lambda3, S->y);
	ec_mod(y, p);

	ec_free_xyz(S);

	S->x = x;
	S->y = y;

	ec_free(lambda);
	ec_free(lambda2);
	ec_free(lambda3);

	return 0;
}

void
ec_double(struct point *R, struct point *S, uint32_t *p)
{
	uint32_t *k, *t, *t1, *t2, *t3, *t4, *t5;

	// take care to handle the case when R and S are the same pointer

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	ec_free_xyz(R);

	if (ec_equal(t3, 0)) {
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		return;
	}

	// 7: t4 = t3 * t3

	t4 = ec_mul(t3, t3);
	ec_mod(t4, p);

	// 8: t5 = t1 - t4

	t = ec_sub(p, t4);
	t5 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t5, p);

	// 9: t4 = t1 + t4

	t = ec_add(t1, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 10: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 11: t4 = 3 * t5

	k = ec_int(3);
	ec_free(t4);
	t4 = ec_mul(k, t5);
	ec_free(k);
	ec_mod(t4, p);

	// 12: t3 = t3 * t2

	t = ec_mul(t3, t2);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 13: t3 = 2 * t3

	t = ec_add(t3, t3);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 14: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 15: t5 = t1 * t2

	t = ec_mul(t1, t2);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 16: t5 = 4 * t5

	k = ec_int(4);
	t = ec_mul(k, t5);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 17: t1 = t4 * t4

	ec_free(t1);
	t1 = ec_mul(t4, t4);
	ec_mod(t1, p);

	// 18: t1 = t1 - 2 * t5

	k = ec_sub(p, t5);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t1, p);

	// 19: t2 = t2 * t2

	t = ec_mul(t2, t2);
	ec_free(t2);
	t2 = t;
	ec_mod(t2, p);

	// 20: t2 = 8 * t2

	k = ec_int(8);
	t = ec_mul(k, t2);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	// 21: t5 = t5 - t1

	k = ec_sub(p, t1);
	t = ec_add(t5, k);
	ec_free(t5);
	t5 = t;
	ec_free(k);
	ec_mod(t5, p);

	// 22: t5 = t4 * t5

	t = ec_mul(t4, t5);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 23: t2 = t5 - t2

	t = ec_sub(p, t2);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
}

void
ec_add_xyz(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	uint32_t *k, *t, *t1, *t2, *t3, *t4, *t5, *t6, *t7;

	t1 = ec_dup(S->x);
	t2 = ec_dup(S->y);
	t3 = ec_dup(S->z);

	t4 = ec_dup(T->x);
	t5 = ec_dup(T->y);
	t6 = ec_dup(T->z);

	ec_free_xyz(R);

	if (!ec_equal(t6, 1)) {

		// 4: t7 = t6 * t6

		t7 = ec_mul(t6, t6);
		ec_mod(t7, p);

		// 5: t1 = t1 * t7

		t = ec_mul(t1, t7);
		ec_free(t1);
		t1 = t;
		ec_mod(t1, p);

		// 6: t7 = t6 * t7

		t = ec_mul(t6, t7);
		ec_free(t7);
		t7 = t;
		ec_mod(t7, p);

		// 7: t2 = t2 * t7

		t = ec_mul(t2, t7);
		ec_free(t2);
		t2 = t;
		ec_mod(t2, p);

		ec_free(t7);
	}

	// 9: t7 = t3 * t3

	t7 = ec_mul(t3, t3);
	ec_mod(t7, p);

	// 10: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 11: t7 = t3 * t7

	t = ec_mul(t3, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 12: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 13: t4 = t1 - t4

	t = ec_sub(p, t4);
	ec_free(t4);
	t4 = ec_add(t1, t);
	ec_free(t);
	ec_mod(t4, p);

	// 14: t5 = t2 - t5

	t = ec_sub(p, t5);
	ec_free(t5);
	t5 = ec_add(t2, t);
	ec_free(t);
	ec_mod(t5, p);

	if (ec_equal(t4, 0)) {
		if (ec_equal(t5, 0)) {
			R->x = ec_int(0);
			R->y = ec_int(0);
			R->z = ec_int(0);
		} else {
			R->x = ec_int(1);
			R->y = ec_int(1);
			R->z = ec_int(0);
		}
		ec_free(t1);
		ec_free(t2);
		ec_free(t3);
		ec_free(t4);
		ec_free(t5);
		ec_free(t6);
		ec_free(t7);
		return;
	}

	// 22: t1 = 2 * t1 - t4

	t = ec_add(t1, t1);
	ec_free(t1);
	t1 = t;
	k = ec_sub(p, t4);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 23: t2 = 2 * t2 - t5

	t = ec_add(t2, t2);
	ec_free(t2);
	t2 = t;
	k = ec_sub(p, t5);
	t = ec_add(t2, k);
	ec_free(t2);
	t2 = t;
	ec_free(k);
	ec_mod(t2, p);

	if (!ec_equal(t6, 1)) {

		// 25: t3 = t3 * t6

		t = ec_mul(t3, t6);
		ec_free(t3);
		t3 = t;
		ec_mod(t3, p);
	}

	// 27: t3 = t3 * t4

	t = ec_mul(t3, t4);
	ec_free(t3);
	t3 = t;
	ec_mod(t3, p);

	// 28: t7 = t4 * t4

	t = ec_mul(t4, t4);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 29: t4 = t4 * t7

	t = ec_mul(t4, t7);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 30: t7 = t1 * t7

	t = ec_mul(t1, t7);
	ec_free(t7);
	t7 = t;
	ec_mod(t7, p);

	// 31: t1 = t5 * t5

	ec_free(t1);
	t1 = ec_mul(t5, t5);
	ec_mod(t1, p);

	// 32: t1 = t1 - t7

	k = ec_sub(p, t7);
	t = ec_add(t1, k);
	ec_free(t1);
	t1 = t;
	ec_free(k);
	ec_mod(t1, p);

	// 33: t7 = t7 - 2 * t1

	k = ec_sub(p, t1);
	t = ec_add(t7, k);
	ec_free(t7);
	t7 = ec_add(t, k);
	ec_free(k);
	ec_free(t);
	ec_mod(t7, p);

	// 34: t5 = t5 * t7

	t = ec_mul(t5, t7);
	ec_free(t5);
	t5 = t;
	ec_mod(t5, p);

	// 35: t4 = t2 * t4

	t = ec_mul(t2, t4);
	ec_free(t4);
	t4 = t;
	ec_mod(t4, p);

	// 36: t2 = t5 - t4

	t = ec_sub(p, t4);
	ec_free(t2);
	t2 = ec_add(t5, t);
	ec_free(t);
	ec_mod(t2, p);

	// 37: t2 = t2 / 2

	if (t2[0] & 1) {
		t = ec_add(t2, p);
		ec_free(t2);
		t2 = t;
	}
	ec_shr(t2);

	R->x = t1;
	R->y = t2;
	R->z = t3;

	ec_free(t4);
	ec_free(t5);
	ec_free(t6);
	ec_free(t7);
}

void
ec_full_add(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	uint32_t *x, *y, *z;
	struct point U;

	if (ec_equal(S->z, 0)) {
		x = ec_dup(T->x);
		y = ec_dup(T->y);
		z = ec_dup(T->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(T->z, 0)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	U.x = NULL;
	U.y = NULL;
	U.z = NULL;

	ec_add_xyz(&U, S, T, p);

	if (ec_equal(U.x, 0) && ec_equal(U.y, 0) && ec_equal(U.z, 0)) {
		ec_free_xyz(&U);
		ec_double(&U, S, p);
	}

	ec_free_xyz(R);

	R->x = U.x;
	R->y = U.y;
	R->z = U.z;
}

void
ec_full_sub(struct point *R, struct point *S, struct point *T, uint32_t *p)
{
	struct point U;

	U.x = ec_dup(T->x);
	U.y = ec_sub(p, T->y);
	U.z = ec_dup(T->z);

	ec_full_add(R, S, &U, p);

	ec_free_xyz(&U);
}

void
ec_mult(struct point *R, uint32_t *d, struct point *S, uint32_t *p)
{
	int h, i, k, l;
	uint32_t *t, *u, *x, *y, *z;
	struct point U;

	if (ec_equal(d, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (ec_equal(d, 1)) {
		x = ec_dup(S->x);
		y = ec_dup(S->y);
		z = ec_dup(S->z);
		ec_free_xyz(R);
		R->x = x;
		R->y = y;
		R->z = z;
		return;
	}

	if (ec_equal(S->z, 0)) {
		ec_free_xyz(R);
		R->x = ec_int(1);
		R->y = ec_int(1);
		R->z = ec_int(0);
		return;
	}

	if (!ec_equal(S->z, 1)) {
		ec_affinify(S, p);
		ec_projectify(S);
	}

	x = ec_dup(S->x);
	y = ec_dup(S->y);
	z = ec_dup(S->z);

	ec_free_xyz(R);

	R->x = x;
	R->y = y;
	R->z = z;

	u = ec_int(3);
	t = ec_mul(u, d);
	ec_free(u);

	l = ec_get_msbit_index(t);

	for (i = l - 1; i > 0; i--) {

		U.x = NULL;
		U.y = NULL;
		U.z = NULL;

		ec_double(R, R, p);

		h = ec_get_bit(t, i);
		k = ec_get_bit(d, i);

		if (h == 1 && k == 0)
			ec_full_add(&U, R, S, p);

		if (h == 0 && k == 1)
			ec_full_sub(&U, R, S, p);

		if (h != k) {
			ec_free_xyz(R);
			R->x = U.x;
			R->y = U.y;
			R->z = U.z;
		}
	}

	ec_free(t);
}

int
ec_get_msbit_index(uint32_t *u)
{
	int k, n;
	uint32_t m;
	m = 0x80000000;
	n = ec_len(u);
	k = 32 * n - 1;
	while (m > 1) {
		if (u[n - 1] & m)
			break;
		m >>= 1;
		k--;
	}
	return k;
}

int
ec_get_bit(uint32_t *u, int k)
{
	int j;
	uint32_t m;
	if (k < 0)
		return 0;
	j = k / 32;
	if (j >= ec_len(u))
		return 0;
	m = 1 << (k % 32);
	if (u[j] & m)
		return 1;
	else
		return 0;
}

int
ec_F(int t)
{
	if (18 <= t && t < 22)
		return 9;

	if (14 <= t && t < 18)
		return 10;

	if (22 <= t && t < 24)
		return 11;

	if (4 <= t && t < 12)
		return 14;

	return 12;
}

// R cannot point to S or T

void
ec_twin_mult(struct point *R, uint32_t *d0, struct point *S, uint32_t *d1, struct point *T, uint32_t *p)
{
	int c[2][6], h[2], i, k, m, m0, m1, u[2];
	struct point SpT, SmT;

	SpT.x = NULL;
	SpT.y = NULL;
	SpT.z = NULL;

	SmT.x = NULL;
	SmT.y = NULL;
	SmT.z = NULL;

	ec_full_add(&SpT, S, T, p);
	ec_full_sub(&SmT, S, T, p);

	m0 = ec_get_msbit_index(d0) + 1;
	m1 = ec_get_msbit_index(d1) + 1;

	if (m0 > m1)
		m = m0;
	else
		m = m1;

	c[0][0] = 0;
	c[0][1] = 0;
	c[0][2] = ec_get_bit(d0, m - 1);
	c[0][3] = ec_get_bit(d0, m - 2);
	c[0][4] = ec_get_bit(d0, m - 3);
	c[0][5] = ec_get_bit(d0, m - 4);

	c[1][0] = 0;
	c[1][1] = 0;
	c[1][2] = ec_get_bit(d1, m - 1);
	c[1][3] = ec_get_bit(d1, m - 2);
	c[1][4] = ec_get_bit(d1, m - 3);
	c[1][5] = ec_get_bit(d1, m - 4);

	R->x = ec_int(1);
	R->y = ec_int(1);
	R->z = ec_int(0);

	for (k = m; k > -1; k--) {

		for (i = 0; i < 2; i++) {
			h[i] = 16 * c[i][1] + 8 * c[i][2] + 4 * c[i][3] + 2 * c[i][4] + c[i][5];
			if (c[i][0] == 1)
				h[i] = 31 - h[i];
		}

		for (i = 0; i < 2; i++) {
			if (h[i] < ec_F(h[1 - i]))
				u[i] = 0;
			else {
				if (c[i][0] & 1)
					u[i] = -1;
				else
					u[i] = 1;
			}
		}

		c[0][0] = abs(u[0]) ^ c[0][1];
		c[0][1] = c[0][2];
		c[0][2] = c[0][3];
		c[0][3] = c[0][4];
		c[0][4] = c[0][5];
		c[0][5] = ec_get_bit(d0, k - 5);

		c[1][0] = abs(u[1]) ^ c[1][1];
		c[1][1] = c[1][2];
		c[1][2] = c[1][3];
		c[1][3] = c[1][4];
		c[1][4] = c[1][5];
		c[1][5] = ec_get_bit(d1, k - 5);

		ec_double(R, R, p);

		if (u[0] == -1 && u[1] == -1)
			ec_full_sub(R, R, &SpT, p);

		if (u[0] == -1 && u[1] == 0)
			ec_full_sub(R, R, S, p);

		if (u[0] == -1 && u[1] == 1)
			ec_full_sub(R, R, &SmT, p);

		if (u[0] == 0 && u[1] == -1)
			ec_full_sub(R, R, T, p);

		if (u[0] == 0 && u[1] == 1)
			ec_full_add(R, R, T, p);

		if (u[0] == 1 && u[1] == -1)
			ec_full_add(R, R, &SmT, p);

		if (u[0] == 1 && u[1] == 0)
			ec_full_add(R, R, S, p);

		if (u[0] == 1 && u[1] == 1)
			ec_full_add(R, R, &SpT, p);
	}

	ec_free_xyz(&SpT);
	ec_free_xyz(&SmT);
}

void
ec_free_xyz(struct point *u)
{
	ec_free(u->x);
	ec_free(u->y);
	ec_free(u->z);
	u->x = NULL;
	u->y = NULL;
	u->z = NULL;
}

// returns u + v

uint32_t *
ec_add(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = ec_len(u);
	nv = ec_len(v);
	if (nu > nv)
		nw = nu + 1;
	else
		nw = nv + 1;
	w = ec_new(nw);
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
	ec_norm(w);
	return w;
}

// returns u - v

uint32_t *
ec_sub(uint32_t *u, uint32_t *v)
{
	int i, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = ec_len(u);
	nv = ec_len(v);
	if (nu > nv)
		nw = nu;
	else
		nw = nv;
	w = ec_new(nw);
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
	ec_norm(w);
	return w;
}

// returns u * v

uint32_t *
ec_mul(uint32_t *u, uint32_t *v)
{
	int i, j, nu, nv, nw;
	uint64_t t;
	uint32_t *w;
	nu = ec_len(u);
	nv = ec_len(v);
	nw = nu + nv;
	w = ec_new(nw);
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
	ec_norm(w);
	return w;
}

// returns floor(u / v)

uint32_t *
ec_div(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t *q, qhat, *w;
	uint64_t a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (ec_len(v) == 1 && v[0] == 0)
		return NULL; // v = 0
	nu = ec_len(u);
	nv = ec_len(v);
	k = nu - nv;
	if (k < 0) {
		q = ec_new(1);
		q[0] = 0;
		return q; // u < v, return zero
	}
	u = ec_dup(u);
	q = ec_new(k + 1);
	w = ec_new(nv + 1);
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
			ec_norm(u);
			nu = ec_len(u);
		}
	} while (--k >= 0);
	ec_norm(q);
	ec_free(u);
	ec_free(w);
	return q;
}

// u = u mod v

void
ec_mod(uint32_t *u, uint32_t *v)
{
	int i, k, nu, nv;
	uint32_t qhat, *w;
	uint64_t a, b, t;
	ec_norm(u);
	ec_norm(v);
	if (ec_len(v) == 1 && v[0] == 0)
		return; // v = 0
	nu = ec_len(u);
	nv = ec_len(v);
	k = nu - nv;
	if (k < 0)
		return; // u < v
	w = ec_new(nv + 1);
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
			ec_norm(u);
			nu = ec_len(u);
		}
	} while (--k >= 0);
	ec_free(w);
}

// returns u ** v

uint32_t *
ec_pow(uint32_t *u, uint32_t *v)
{
	uint32_t *t, *w;
	u = ec_dup(u);
	v = ec_dup(v);
	// w = 1
	w = ec_new(1);
	w[0] = 1;
	for (;;) {
		if (v[0] & 1) {
			// w = w * u
			t = ec_mul(w, u);
			ec_free(w);
			w = t;
		}
		// v = v >> 1
		ec_shr(v);
		// v = 0?
		if (ec_len(v) == 1 && v[0] == 0)
			break;
		// u = u * u
		t = ec_mul(u, u);
		ec_free(u);
		u = t;
	}
	ec_free(u);
	ec_free(v);
	return w;
}

// u = u >> 1

void
ec_shr(uint32_t *u)
{
	int i;
	for (i = 0; i < ec_len(u) - 1; i++) {
		u[i] >>= 1;
		if (u[i + 1] & 1)
			u[i] |= 0x80000000;
	}
	u[i] >>= 1;
	ec_norm(u);
}

// compare u and v

int
ec_cmp(uint32_t *u, uint32_t *v)
{
	int i;
	ec_norm(u);
	ec_norm(v);
	if (ec_len(u) < ec_len(v))
		return -1;
	if (ec_len(u) > ec_len(v))
		return 1;
	for (i = ec_len(u) - 1; i >= 0; i--) {
		if (u[i] < v[i])
			return -1;
		if (u[i] > v[i])
			return 1;
	}
	return 0; // u = v
}

int
ec_equal(uint32_t *u, uint32_t v)
{
	if (ec_len(u) == 1 && u[0] == v)
		return 1;
	else
		return 0;
}

uint32_t *
ec_int(int k)
{
	uint32_t *u;
	u = ec_new(1);
	u[0] = k;
	return u;
}

uint32_t *
ec_new(int n)
{
	uint32_t *p;
	p = (uint32_t *) malloc((n + 1) * sizeof (uint32_t));
	if (p == NULL)
		malloc_kaput();
	*p = n;
	ec_malloc_count++;
	return p + 1;
}

void
ec_free(uint32_t *p)
{
	if (p) {
		free(p - 1);
		ec_malloc_count--;
	}
}

uint32_t *
ec_dup(uint32_t *u)
{
	int i;
	uint32_t *v;
	v = ec_new(ec_len(u));
	for (i = 0; i < ec_len(u); i++)
		v[i] = u[i];
	return v;
}

// remove leading zeroes

void
ec_norm(uint32_t *u)
{
	while (ec_len(u) > 1 && u[ec_len(u) - 1] == 0)
		ec_len(u)--;
}

uint32_t *
ec_hexstr_to_bignum(char *s)
{
	int d, i, len, n;
	uint32_t *u;
	len = strlen(s);
	n = (len + 7) / 8; // convert len to number of uint32_t
	u = ec_new(n);
	for (i = 0; i < n; i++)
		u[i] = 0;
	for (i = 0; i < len; i++) {
		d = s[len - i - 1];
		if ('0' <= d && d <= '9')
			d -= '0';
		else if ('A' <= d && d <= 'F')
			d -= 'A' - 10;
		else if ('a' <= d && d <= 'f')
			d -= 'a' - 10;
		else {
			ec_free(u);
			return NULL;
		}
		u[i / 8] |= d << (4 * (i % 8));
	}
	ec_norm(u);
	return u;
}

uint32_t *
ec_buf_to_bignum(uint8_t *buf, int len)
{
	int i, n, t;
	uint32_t *u;
	n = (len + 3) / 4;
	u = ec_new(n);
	t = 0;
	for (i = 0; i < len; i++) {
		t = t << 8 | buf[i];
		if ((len - i - 1) % 4 == 0) {
			u[--n] = t;
			t = 0;
		}
	}
	ec_norm(u);
	return u;
}

static char *str_p256 =
	"ffffffff00000001000000000000000000000000ffffffff"
	"ffffffffffffffff";

static char *str_q256 =
	"ffffffff00000000ffffffffffffffffbce6faada7179e84"
	"f3b9cac2fc632551";

static char *str_gx256 =
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0"
	"f4a13945d898c296";

static char *str_gy256 =
	"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ece"
	"cbb6406837bf51f5";

static char *str_p384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"fffffffffffffffeffffffff0000000000000000ffffffff";

static char *str_q384 =
	"ffffffffffffffffffffffffffffffffffffffffffffffff"
	"c7634d81f4372ddf581a0db248b0a77aecec196accc52973";

static char *str_gx384 =
	"aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b98"
	"59f741e082542a385502f25dbf55296c3a545e3872760ab7";

static char *str_gy384 =
	"3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147c"
	"e9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f";

void
ec_init()
{
	p256 = ec_hexstr_to_bignum(str_p256);
	q256 = ec_hexstr_to_bignum(str_q256);
	gx256 = ec_hexstr_to_bignum(str_gx256);
	gy256 = ec_hexstr_to_bignum(str_gy256);

	p384 = ec_hexstr_to_bignum(str_p384);
	q384 = ec_hexstr_to_bignum(str_q384);
	gx384 = ec_hexstr_to_bignum(str_gx384);
	gy384 = ec_hexstr_to_bignum(str_gy384);
}
