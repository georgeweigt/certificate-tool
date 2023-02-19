struct certinfo *
read_certificate(char *filename)
{
	int err, k, n;
	char *s;
	FILE *f;
	struct certinfo *p;

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

	p = malloc(sizeof (struct certinfo) + n);

	if (p == NULL)
		malloc_kaput();

	memset(p, 0, sizeof (struct certinfo));

	s = (char *) p->cert_data;

	// advance to beginning of certificate data

	for (;;) {

		if (fgets(s, n, f) == NULL) {
			fclose(f);
			free(p);
			return NULL;
		}

		if (strcmp(s, "-----BEGIN CERTIFICATE-----\n") == 0)
			break;
	}

	k = 0;

	for (;;) {

		if (fgets(s + k, n - k, f) == NULL) {
			fclose(f);
			free(p);
			return NULL;
		}

		if (strcmp(s + k, "-----END CERTIFICATE-----\n") == 0)
			break;

		k += strlen(s + k) - 1; // subtract 1 for newline
	}

	fclose(f);

	n = base64_decode(p->cert_data, s, k);

	if (n < 0) {
		free(p);
		return NULL;
	}

	p->cert_length = n;

	return p;
}
