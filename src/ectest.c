void
ec_test()
{
	int t = ec_malloc_count;
	ec_test_full_add();
	ec_test_full_sub();
	ec_test_double();
	ec_test_mult();
	ec_test_twin_mult();
	ec_test256();
	ec_test384();
	ecdh_test();
	if (t != ec_malloc_count)
		printf("err: ec_memory_leak\n");
}

void
ec_test_full_add()
{
	uint32_t *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_xr =
		"12dc5ce7acdfc5844d939f40b4df012e68f865b89c3213ba"
		"97090a247a2fc009075cf471cd2e85c489979b65ee0b5eed";

	char *str_yr =
		"167312e58fe0c0afa248f2854e3cddcb557f983b3189b67f"
		"21eee01341e7e9fe67f6ee81b36988efa406945c8804a4b0";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_full_add(&R, &S, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_full_add\n");
	else
		printf("err: ec_full_add\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

void
ec_test_full_sub()
{
	uint32_t *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_xr =
		"6afdaf8da8b11c984cf177e551cee542cda4ac2f25cd522d"
		"0cd710f88059c6565aef78f6b5ed6cc05a6666def2a2fb59";

	char *str_yr =
		"7bed0e158ae8cc70e847a60347ca1548c348decc6309f48b"
		"59bd5afc9a9b804e7f7876178cb5a7eb4f6940a9c73e8e5e";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_full_sub(&R, &S, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_full_sub\n");
	else
		printf("err: ec_full_sub\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

void
ec_test_double()
{
	uint32_t *p, *x, *y;
	struct point R, S;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xr =
		"2a2111b1e0aa8b2fc5a1975516bc4d58017ff96b25e1bdff"
		"3c229d5fac3bacc319dcbec29f9478f42dee597b4641504c";

	char *str_yr =
		"fa2e3d9dc84db8954ce8085ef28d7184fddfd1344b4d4797"
		"343af9b5f9d837520b450f726443e4114bd4e5bdb2f65ddd";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_double(&R, &S, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_double\n");
	else
		printf("err: ec_double\n");

	ec_free(p);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

void
ec_test_mult()
{
	uint32_t *d, *p, *x, *y;
	struct point R, S;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_d =
		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fd"
		"ac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480";

	char *str_xr =
		"e4f77e7ffeb7f0958910e3a680d677a477191df166160ff7"
		"ef6bb5261f791aa7b45e3e653d151b95dad3d93ca0290ef2";

	char *str_yr =
		"ac7dee41d8c5f4a7d5836960a773cfc1376289d3373f8cf7"
		"417b0c6207ac32e913856612fc9ff2e357eb2ee05cf9667f";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	d = ec_hexstr_to_bignum(str_d);

	R.x = NULL;
	R.y = NULL;
	R.z = NULL;

	ec_mult(&R, d, &S, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_mult\n");
	else
		printf("err: ec_mult\n");

	ec_free(p);
	ec_free(d);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
}

void
ec_test_twin_mult()
{
	uint32_t *d, *e, *p, *x, *y;
	struct point R, S, T;

	char *str_p384 =
		"ffffffffffffffffffffffffffffffffffffffffffffffff"
		"fffffffffffffffeffffffff0000000000000000ffffffff";

	char *str_xs =
		"fba203b81bbd23f2b3be971cc23997e1ae4d89e69cb6f923"
		"85dda82768ada415ebab4167459da98e62b1332d1e73cb0e";

	char *str_ys =
		"5ffedbaefdeba603e7923e06cdb5d0c65b22301429293376"
		"d5c6944e3fa6259f162b4788de6987fd59aed5e4b5285e45";

	char *str_xt =
		"aacc05202e7fda6fc73d82f0a66220527da8117ee8f8330e"
		"ad7d20ee6f255f582d8bd38c5a7f2b40bcdb68ba13d81051";

	char *str_yt =
		"84009a263fefba7c2c57cffa5db3634d286131afc0fca8d2"
		"5afa22a7b5dce0d9470da89233cee178592f49b6fecb5092";

	char *str_d =
		"a4ebcae5a665983493ab3e626085a24c104311a761b5a8fd"
		"ac052ed1f111a5c44f76f45659d2d111a61b5fdd97583480";

	char *str_e =
		"afcf88119a3a76c87acbd6008e1349b29f4ba9aa0e12ce89"
		"bcfcae2180b38d81ab8cf15095301a182afbc6893e75385d";

	char *str_xr =
		"917ea28bcd641741ae5d18c2f1bd917ba68d34f0f0577387"
		"dc81260462aea60e2417b8bdc5d954fc729d211db23a02dc";

	char *str_yr =
		"1a29f7ce6d074654d77b40888c73e92546c8f16a5ff6bcbd"
		"307f758d4aee684beff26f6742f597e2585c86da908f7186";

	p = ec_hexstr_to_bignum(str_p384);

	S.x = ec_hexstr_to_bignum(str_xs);
	S.y = ec_hexstr_to_bignum(str_ys);
	S.z = ec_int(1);

	T.x = ec_hexstr_to_bignum(str_xt);
	T.y = ec_hexstr_to_bignum(str_yt);
	T.z = ec_int(1);

	d = ec_hexstr_to_bignum(str_d);
	e = ec_hexstr_to_bignum(str_e);

	ec_twin_mult(&R, d, &S, e, &T, p);

	ec_affinify(&R, p);

	x = ec_hexstr_to_bignum(str_xr);
	y = ec_hexstr_to_bignum(str_yr);

	if (ec_cmp(R.x, x) == 0 && ec_cmp(R.y, y) == 0)
		printf("ok: ec_twin_mult\n");
	else
		printf("err: ec_twin_mult\n");

	ec_free(p);
	ec_free(d);
	ec_free(e);
	ec_free(x);
	ec_free(y);

	ec_free_xyz(&R);
	ec_free_xyz(&S);
	ec_free_xyz(&T);
}

// Key file for prime256v1
//
//   0 119: SEQUENCE {
//   2   1:   INTEGER 1
//   5  32:   OCTET STRING
//        :     3C 7A C4 FE 35 55 88 CE 3D 5B 0A 46 A5 51 37 1C   Private key d
//        :     2E 25 33 09 3A 71 0D 33 66 43 2D 59 7A AA 5C 27
//  39  10:   [0] {
//  41   8:     OBJECT IDENTIFIER '1 2 840 10045 3 1 7'
//        :     }
//  51  68:   [1] {
//  53  66:     BIT STRING
//        :       04 EF 7B A2 0E 11 D7 EF BB 6B DD 9A A1 AD 3D B2   Public key (x, y)
//        :       8F 8C FC 1E 7D D8 0E BD E3 CA 99 34 35 94 EF 31
//        :       16 26 E6 F3 4E B2 13 9B 6D 55 0A 91 9A 37 3A 17
//        :       86 57 92 A4 79 F5 6F 09 A6 77 6F 85 93 90 69 A8
//        :       C0
//        :     }
//        :   }

void
ec_test256()
{
	uint32_t *d, *h, *r, *s, *x, *y;
	uint8_t sig[64];

	// certificate's SHA1 hash

	char *str_h = "ce89669c8efcfe2c4f84e517339110908bb7303c";

	// private key

	char *str_d =
		"3C7AC4FE355588CE3D5B0A46A551371C"
		"2E2533093A710D3366432D597AAA5C27";

	// public key

	char *str_x =
		"EF7BA20E11D7EFBB6BDD9AA1AD3DB2"
		"8F8CFC1E7DD80EBDE3CA99343594EF31"
		"16";

	char *str_y =
		"26E6F34EB2139B6D550A919A373A17"
		"865792A479F56F09A6776F85939069A8"
		"C0";

	h = ec_hexstr_to_bignum(str_h);
	d = ec_hexstr_to_bignum(str_d);
	x = ec_hexstr_to_bignum(str_x);
	y = ec_hexstr_to_bignum(str_y);

	ec256_encrypt_nib(h, d, sig);

	r = ec_buf_to_bignum(sig, 32);
	s = ec_buf_to_bignum(sig + 32, 32);

	if (ec256_verify_nib(h, r, s, x, y) == 0)
		printf("ok: ec_test256\n");
	else
		printf("err: ec_test256\n");

	ec_free(h);
	ec_free(d);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);
}

// Key file for secp384r1
//
//  0 164: SEQUENCE {
//  3   1:   INTEGER 1
//  6  48:   OCTET STRING
//       :     6D 46 21 67 FB B1 A9 00 07 E3 ED 34 3E 69 4C E4   Private key d
//       :     11 34 1B 8A 85 A6 B3 7F 87 4C 7F 6A 18 C4 E7 A3
//       :     7B CB AF 2A B3 31 7F D7 56 FE 51 E7 2C FD 2B 50
// 56   7:   [0] {
// 58   5:     OBJECT IDENTIFIER secp384r1 (1 3 132 0 34)
//       :     }
// 65 100:   [1] {
// 67  98:     BIT STRING
//       :       04 04 7E 6E 9A 1A A8 FF AC 27 9A 22 8C 4D 1E C4   Public key (x, y)
//       :       F8 C6 30 65 70 C4 56 8F 3C 09 33 F5 E0 60 98 00
//       :       6D 74 8F DB CD B4 29 F2 24 39 F1 51 CB 7F D4 B8
//       :       03 36 AA 35 72 EB 38 6D 08 0D 5C 10 C3 CA AD F5
//       :       BF 08 35 DE 99 1F 98 4B 04 F9 DE 49 9C 01 57 73
//       :       54 64 C3 3B BF BE A0 19 CE FD 76 4D 26 99 B7 2D
//       :       FE
//       :     }
//       :   }

void
ec_test384()
{
	uint32_t *d, *h, *r, *s, *x, *y;
	uint8_t sig[96];

	// certificate's SHA1 hash

	char *str_h = "ce89669c8efcfe2c4f84e517339110908bb7303c";

	// private key

	char *str_d =
		"6D462167FBB1A90007E3ED343E694CE4"
		"11341B8A85A6B37F874C7F6A18C4E7A3"
		"7BCBAF2AB3317FD756FE51E72CFD2B50";

	// public key

	char *str_x =
		"047E6E9A1AA8FFAC279A228C4D1EC4"
		"F8C6306570C4568F3C0933F5E0609800"
		"6D748FDBCDB429F22439F151CB7FD4B8"
		"03";

	char *str_y =
		"36AA3572EB386D080D5C10C3CAADF5"
		"BF0835DE991F984B04F9DE499C015773"
		"5464C33BBFBEA019CEFD764D2699B72D"
		"FE";

	h = ec_hexstr_to_bignum(str_h);
	d = ec_hexstr_to_bignum(str_d);
	x = ec_hexstr_to_bignum(str_x);
	y = ec_hexstr_to_bignum(str_y);

	ec384_encrypt_nib(h, d, sig);

	r = ec_buf_to_bignum(sig, 48);
	s = ec_buf_to_bignum(sig + 48, 48);

	if (ec384_verify_nib(h, r, s, x, y) == 0)
		printf("ok: ec_test384\n");
	else
		printf("err: ec_test384\n");

	ec_free(h);
	ec_free(d);
	ec_free(r);
	ec_free(s);
	ec_free(x);
	ec_free(y);
}

void
ecdh_test()
{
	uint32_t *dA, *dB;
	struct point RA, RB, SA, SB;

	// private key A

	static char *str_dA =
		"6D462167FBB1A90007E3ED343E694CE4"
		"11341B8A85A6B37F874C7F6A18C4E7A3"
		"7BCBAF2AB3317FD756FE51E72CFD2B50";

	// public key A

	static char *str_xA =
		"047E6E9A1AA8FFAC279A228C4D1EC4"
		"F8C6306570C4568F3C0933F5E0609800"
		"6D748FDBCDB429F22439F151CB7FD4B8"
		"03";

	static char *str_yA =
		"36AA3572EB386D080D5C10C3CAADF5"
		"BF0835DE991F984B04F9DE499C015773"
		"5464C33BBFBEA019CEFD764D2699B72D"
		"FE";

	// private key B

	static char *str_dB =
		"D2D5EABC6FD9BCFF6E98162F0A145B40"
		"DFBD81FA7CB328A96F217320727FD023"
		"F8DED1A475BFD02BA13999B1F9989BB6";

	// public key B

	static char *str_xB =
		"B6A4A9F5432CCB8D2E3D5FAA519FFC"
		"F898469995DDC622285027412268BE4A"
		"CA9B4C25730432ED22F8796915FE5393"
		"E2";

	static char *str_yB =
		"16E95C98ED178B592962FD5321A803"
		"8C3A12DE7540065DC564849D3FEC2A52"
		"A0A693254E47D506558D836C06D5C3C4"
		"6D";

	dA = ec_hexstr_to_bignum(str_dA);
	dB = ec_hexstr_to_bignum(str_dB);

	RA.x = ec_hexstr_to_bignum(str_xA);
	RA.y = ec_hexstr_to_bignum(str_yA);
	RA.z = ec_int(1);

	RB.x = ec_hexstr_to_bignum(str_xB);
	RB.y = ec_hexstr_to_bignum(str_yB);
	RB.z = ec_int(1);

	SA.x = NULL;
	SA.y = NULL;
	SA.z = NULL;

	ec_mult(&SA, dB, &RA, p384);
	ec_affinify(&SA, p384);

	SB.x = NULL;
	SB.y = NULL;
	SB.z = NULL;

	ec_mult(&SB, dA, &RB, p384);
	ec_affinify(&SB, p384);

	if (ec_cmp(SA.x, SB.x) == 0)
		printf("ok: ecdh_test\n");
	else
		printf("err: ecdh_test\n");
#if 0
	// print A's pre-master secret

	int i;
	char buf[48];

	memset(buf, 0, 48);

	for (i = 0; i < len(SA.x); i++) {
		buf[48 - 4 * i - 4] = SA.x[i] >> 24;
		buf[48 - 4 * i - 3] = SA.x[i] >> 16;
		buf[48 - 4 * i - 2] = SA.x[i] >> 8;
		buf[48 - 4 * i - 1] = SA.x[i];
	}

	print_buf("A", buf, 48);

	// print B's pre-master secret

	memset(buf, 0, 48);

	for (i = 0; i < len(SB.x); i++) {
		buf[48 - 4 * i - 4] = SB.x[i] >> 24;
		buf[48 - 4 * i - 3] = SB.x[i] >> 16;
		buf[48 - 4 * i - 2] = SB.x[i] >> 8;
		buf[48 - 4 * i - 1] = SB.x[i];
	}

	print_buf("B", buf, 48);
#endif
	ec_free(dA);
	ec_free(dB);

	ec_free_xyz(&RA);
	ec_free_xyz(&RB);
	ec_free_xyz(&SA);
	ec_free_xyz(&SB);
}
