int
base64_decode(uint8_t *buf, char *s, int length)
{
	int a, b, c, d, i, k;
	uint32_t w;

	if (length % 4 != 0)
		return -1;

	k = 0;

	for (i = 0; i < length; i += 4) {

		a = base64_decode_digit(s[0]);
		b = base64_decode_digit(s[1]);

		if (a < 0 || b < 0)
			return -1;

		if (s[2] == '=' && s[3] == '=') {
			if (i + 4 != length)
				return -1;
			w = a << 18 | b << 12;
			buf[k++] = w >> 16;
			break;
		}

		c = base64_decode_digit(s[2]);

		if (c < 0)
			return -1;

		if (s[3] == '=') {
			if (i + 4 != length)
				return -1;
			w = a << 18 | b << 12 | c << 6;
			buf[k++] = w >> 16;
			buf[k++] = w >> 8;
			break;
		}

		d = base64_decode_digit(s[3]);

		if (d < 0)
			return -1;

		w = a << 18 | b << 12 | c << 6 | d;

		buf[k++] = w >> 16;
		buf[k++] = w >> 8;
		buf[k++] = w;

		s += 4;
	}

	return k;
}

int
base64_decode_digit(int c)
{
	if ('A' <= c && c <= 'Z')
		return c - 'A';
	if ('a' <= c && c <= 'z')
		return c - 'a' + 26;
	if ('0' <= c && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

static char base64_encode_digit[64] = {
	'A','B','C','D','E','F','G','H','I','J','K','L','M',
	'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
	'a','b','c','d','e','f','g','h','i','j','k','l','m',
	'n','o','p','q','r','s','t','u','v','w','x','y','z',
	'0','1','2','3','4','5','6','7','8','9','+','/',
};

void
base64_print(FILE *f, uint8_t *buf, int len)
{
	int a, b, c, d, i, m, n;
	uint32_t w;

	n = len / 3;
	m = len % 3;

	for (i = 0; i < n; i++) {

		w = buf[0] << 16 | buf[1] << 8 | buf[2];

		a = base64_encode_digit[w >> 18 & 0x3f];
		b = base64_encode_digit[w >> 12 & 0x3f];
		c = base64_encode_digit[w >> 6 & 0x3f];
		d = base64_encode_digit[w & 0x3f];

		fprintf(f, "%c%c%c%c", a, b, c, d);

		buf += 3;
	}

	switch (m) {

	case 1:
		w = buf[0] << 16;

		a = base64_encode_digit[w >> 18 & 0x3f];
		b = base64_encode_digit[w >> 12 & 0x3f];

		fprintf(f, "%c%c==", a, b);
		break;

	case 2:
		w = buf[0] << 16 | buf[1] << 8;

		a = base64_encode_digit[w >> 18 & 0x3f];
		b = base64_encode_digit[w >> 12 & 0x3f];
		c = base64_encode_digit[w >> 6 & 0x3f];

		fprintf(f, "%c%c%c=", a, b, c);
		break;
	}
}
