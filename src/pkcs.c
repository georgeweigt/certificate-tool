// generate pkcs signatures (caller must free result)

uint8_t *
pkcs_md5_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf, *d;

	n = p->signature_length - 37; // 3 + 18 + 16 = 37

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10", 18);

	k += 18;

	d = p->cert_data + p->info_start;
	n = p->info_offset + p->info_length - p->info_start;

	md5(d, n, buf + k);

	return buf;
}

uint8_t *
pkcs_sha1_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf, *d;

	n = p->signature_length - 38; // 3 + 15 + 20 = 38 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 15);

	k += 15;

	d = p->cert_data + p->info_start;
	n = p->info_offset + p->info_length - p->info_start;

	sha1(d, n, buf + k);

	return buf;
}

uint8_t *
pkcs_sha224_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf, *d;

	n = p->signature_length - 50; // 3 + 19 + 28 = 50 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x29\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x18", 19);

	memcpy(buf + k, "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c", 19);

	k += 19;

	d = p->cert_data + p->info_start;
	n = p->info_offset + p->info_length - p->info_start;

	sha224(d, n, buf + k);

	return buf;
}

uint8_t *
pkcs_sha256_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf, *d;

	n = p->signature_length - 54; // 3 + 19 + 32 = 54 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 19);

	k += 19;

	d = p->cert_data + p->info_start;
	n = p->info_offset + p->info_length - p->info_start;

	sha256(d, n, buf + k);

	return buf;
}

uint8_t *
pkcs_sha384_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf, *d;

	n = p->signature_length - 70; // 3 + 19 + 48 = 70 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30", 19);

	k += 19;

	d = p->cert_data + p->info_start;
	n = p->info_offset + p->info_length - p->info_start;

	sha384(d, n, buf + k);

	return buf;
}

uint8_t *
pkcs_sha512_signature(struct certinfo *p)
{
	int k, n;
	uint8_t *buf, *d;

	n = p->signature_length - 86; // 3 + 19 + 64 = 86 bytes

	if (n < 0)
		return NULL;

	buf = malloc(p->signature_length);

	if (buf == NULL)
		malloc_kaput();

	k = 0;

	buf[k++] = 0;
	buf[k++] = 1;

	memset(buf + k, 0xff, n);

	k += n;

	buf[k++] = 0;

	memcpy(buf + k, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40", 19);

	k += 19;

	d = p->cert_data + p->info_start;
	n = p->info_offset + p->info_length - p->info_start;

	sha512(d, n, buf + k);

	return buf;
}
