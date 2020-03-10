#include "defs.h"

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
