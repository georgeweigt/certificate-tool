struct keyinfo *
read_key_file(char *filename)
{
	FILE *f;
	char buf[16];

	// peek to determine RSA or EC

	f = fopen(filename, "r");

	if (f == NULL)
		return NULL;

	if (fgets(buf, sizeof buf, f) == NULL) {
		fclose(f);
		return NULL;
	}

	fclose(f);

	if (strncmp(buf, "-----BEGIN RSA", 14) == 0)
		return read_rsa_key_file(filename);

	if (strncmp(buf, "-----BEGIN EC ", 14) == 0)
		return read_ec_key_file(filename);

	return NULL;
}

struct keyinfo *
read_rsa_key_file(char *filename)
{
	int err, k, n;
	char *s;
	FILE *f;
	struct keyinfo *p;

	f = fopen(filename, "r");

	if (f == NULL)
		return NULL;

	// get file size

	err = fseek(f, 0, SEEK_END);

	if (err) {
		fclose(f);
		return NULL;
	}

	n = (int) ftell(f);

	if (n < 0) {
		fclose(f);
		return NULL;
	}

	rewind(f);

	p = malloc(sizeof (struct keyinfo) + n);

	if (p == NULL)
		malloc_kaput();

	memset(p, 0, sizeof (struct keyinfo));

	p->key_type = RSA_ENCRYPTION;

	s = (char *) p->key_data;

	if (fgets(s, n, f) == NULL) {
		fclose(f);
		free(p);
		return NULL;
	}

	if (strcmp(s, "-----BEGIN RSA PRIVATE KEY-----\n") != 0) {
		fclose(f);
		free(p);
		return NULL;
	}

	k = 0;

	for (;;) {

		if (fgets(s + k, n - k, f) == NULL) {
			fclose(f);
			free(p);
			return NULL;
		}

		if (strcmp(s + k, "-----END RSA PRIVATE KEY-----\n") == 0)
			break;

		k += strlen(s + k) - 1; // subtract 1 for newline
	}

	fclose(f);

	n = base64_decode(p->key_data, s, k);

	if (n < 0) {
		free(p);
		return NULL;
	}

	p->key_data_length = n;

	return p;
}

struct keyinfo *
read_ec_key_file(char *filename)
{
	int err, k, n;
	char *s;
	FILE *f;
	struct keyinfo *p;

	f = fopen(filename, "r");

	if (f == NULL)
		return NULL;

	// get file size

	err = fseek(f, 0, SEEK_END);

	if (err) {
		fclose(f);
		return NULL;
	}

	n = (int) ftell(f);

	if (n < 0) {
		fclose(f);
		return NULL;
	}

	rewind(f);

	p = malloc(sizeof (struct keyinfo) + n);

	if (p == NULL)
		malloc_kaput();

	memset(p, 0, sizeof (struct keyinfo));

	s = (char *) p->key_data;

	for (;;) {

		if (fgets(s, n, f) == NULL) {
			fclose(f);
			free(p);
			return NULL;
		}

		if (strcmp(s, "-----BEGIN EC PRIVATE KEY-----\n") == 0)
			break;
	}

	k = 0;

	for (;;) {

		if (fgets(s + k, n - k, f) == NULL) {
			fclose(f);
			free(p);
			return NULL;
		}

		if (strcmp(s + k, "-----END EC PRIVATE KEY-----\n") == 0)
			break;

		k += strlen(s + k) - 1; // subtract 1 for newline
	}

	fclose(f);

	n = base64_decode(p->key_data, s, k);

	if (n < 0) {
		free(p);
		return NULL;
	}

	p->key_data_length = n;

	return p;
}
