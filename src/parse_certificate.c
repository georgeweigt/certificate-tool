// Outline of a certificate (not all TLVs shown)
//
//   SEQUENCE
//   | SEQUENCE           Certificate Info
//   | | INTEGER          Serial Number
//   | | SEQUENCE         Certificate Signature Algorithm (sha1WithRSAEncryption)
//   | | SEQUENCE         Issuer
//   | | SEQUENCE         Validity
//   | | | UTCTIME
//   | | | UTCTIME
//   | | SEQUENCE         Subject
//   | | SEQUENCE         Subject Public Key Info
//   | | | SEQUENCE
//   | | | | OBJECT ID    Subject Public Key Algorithm (rsaEncryption)
//   | | | | NULL
//   | | | BIT STRING     Subject's Public Key
//   | | | | SEQUENCE
//   | | | | | INTEGER    Modulus
//   | | | | | INTEGER    Exponent
//   | SEQUENCE
//   | | OBJECT ID        Certificate Signature Algorithm (sha1WithRSAEncryption)
//   | | NULL
//   | BIT STRING         Certificate Signature Value

// encryption algorithm identifiers

#define STR_RSA_ENCRYPTION "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
#define STR_SECP384R1 "\x30\x10\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x05\x2B\x81\x04\x00\x22"
#define STR_PRIME256V1 "\x30\x13\x06\x07\x2A\x86\x48\xCE\x3D\x02\x01\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"

// signature algorithm identifiers

#define STR_MD5_WITH_RSA_ENCRYPTION "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04\x05\x00"
#define STR_SHA1_WITH_RSA_ENCRYPTION "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05\x05\x00"
#define STR_SHA224_WITH_RSA_ENCRYPTION "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e\x05\x00"
#define STR_SHA256_WITH_RSA_ENCRYPTION "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"
#define STR_SHA384_WITH_RSA_ENCRYPTION "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0C\x05\x00"
#define STR_SHA512_WITH_RSA_ENCRYPTION "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0D\x05\x00"

#define STR_ECDSA_WITH_SHA1 "\x06\x07\x2a\x86\x48\xce\x3d\x04\x01"
#define STR_ECDSA_WITH_SHA224 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x01"
#define STR_ECDSA_WITH_SHA256 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"
#define STR_ECDSA_WITH_SHA384 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x03"
#define STR_ECDSA_WITH_SHA512 "\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x04"

int
parse_certificate(struct certinfo *p)
{
	int err, j, k;

	err = parse_cert_level_1(p, p->cert_data, p->cert_length);

	if (err)
		return -1;

	j = p->top_offset;
	k = p->top_offset + p->top_length;

	err = parse_cert_level_2(p, p->cert_data, j, k);

	if (err)
		return -1;

	j = p->info_offset;
	k = p->info_offset + p->info_length;

	err = parse_cert_level_3(p, p->cert_data, j, k);

	if (err)
		return -1;

	// signature algorithms must match

	if (p->algorithm_length != p->signature_algorithm_length) {
		p->line = __LINE__;
		return -1;
	}

	if (memcmp(p->cert_data + p->algorithm_offset, p->cert_data + p->signature_algorithm_offset, p->algorithm_length) != 0) {
		p->line = __LINE__;
		return -1;
	}

	// parse the signature algorithm

	j = p->signature_algorithm_offset;
	k = p->signature_algorithm_offset + p->signature_algorithm_length;

	err = parse_signature_algorithm(p, p->cert_data, j, k);

	if (err)
		return -1;

	// parse the validity field

	j = p->validity_offset;
	k = p->validity_offset + p->validity_length;

	err = parse_validity(p, p->cert_data, j, k);

	if (err)
		return -1;

	// parse the public key

	j = p->public_key_offset;
	k = p->public_key_offset + p->public_key_length;

	err = parse_public_key(p, p->cert_data, j, k);

	if (err)
		return -1;

	// parse the signature (call after parsing public key)

	j = p->signature_offset;
	k = p->signature_offset + p->signature_length;

	err = parse_signature(p, p->cert_data, j, k);

	if (err)
		return -1;

	return 0;
}

int
parse_cert_level_1(struct certinfo *p, uint8_t *cert, int end)
{
	int err, type, length, offset = 0;

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}

	p->top_offset = offset;
	p->top_length = length;

	return 0;
}

int
parse_cert_level_2(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err, type, length;

	// certificate info

	p->info_start = offset;
	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->info_offset = offset;
	p->info_length = length;
	offset += length;

	// signature algorithm

	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->signature_algorithm_offset = offset;
	p->signature_algorithm_length = length;
	offset += length;

	// signature

	p->signature_start = offset;
	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != BIT_STRING || length < 2) {
		p->line = __LINE__;
		return -1;
	}
	p->signature_offset = offset + 1; // skip remainder byte
	p->signature_length = length - 1;

	return 0;
}

int
parse_cert_level_3(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err, type, length;

	// skip version (if present) and serial number

	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err) {
		p->line = __LINE__;
		return -1;
	}
	if (type == INTEGER) {
		p->serial_number_offset = offset;
		p->serial_number_length = length;
		offset += length;
	} else {
		offset += length;
		err = get_type_and_length(cert, end, &offset, &type, &length);
		if (err || type != INTEGER) {
			p->line = __LINE__;
			return -1;
		}
		p->serial_number_offset = offset;
		p->serial_number_length = length;
		offset += length;
	}

	// certificate signature algorithm

	p->algorithm_start = offset;
	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->algorithm_offset = offset;
	p->algorithm_length = length;
	offset += length;

	// issuer

	p->issuer_start = offset;
	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->issuer_offset = offset;
	p->issuer_length = length;
	offset += length;

	// validity

	p->validity_start = offset;
	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->validity_offset = offset;
	p->validity_length = length;
	offset += length;

	// subject

	p->subject_start = offset;
	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->subject_offset = offset;
	p->subject_length = length;
	offset += length;

	// subject public key info

	err = get_type_and_length(cert, end, &offset, &type, &length);
	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}
	p->public_key_offset = offset;
	p->public_key_length = length;

	return 0;
}

int
parse_public_key(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err, type, length;

	// rsaEncryption?

	if (end - offset > 15 && memcmp(cert + offset, STR_RSA_ENCRYPTION, 15) == 0) {
		offset += 15;
		err = get_type_and_length(cert, end, &offset, &type, &length);
		if (err || type != BIT_STRING) {
			p->line = __LINE__;
			return -1;
		}
		err = parse_rsa_info(p, cert, offset, offset + length);
		if (err) {
			p->line = __LINE__;
			return -1;
		}
		p->encryption_algorithm = RSA_ENCRYPTION;
		return 0;
	}

	// ecPublicKey secp384r1?

	if (end - offset > 18 && memcmp(cert + offset, STR_SECP384R1, 18) == 0) {
		offset += 18;
		err = get_type_and_length(cert, end, &offset, &type, &length);
		if (err || type != BIT_STRING || length != 98) {
			p->line = __LINE__;
			return -1;
		}
		p->ec_key_offset = offset + 1; // skip remainder byte
		p->ec_key_length = length - 1;
		p->encryption_algorithm = SECP384R1;
		return 0;
	}

	// ecPublicKey prime256v1?

	if (end - offset > 21 && memcmp(cert + offset, STR_PRIME256V1, 21) == 0) {
		offset += 21;
		err = get_type_and_length(cert, end, &offset, &type, &length);
		if (err || type != BIT_STRING || length != 66) {
			p->line = __LINE__;
			return -1;
		}
		p->ec_key_offset = offset + 1; // skip remainder byte
		p->ec_key_length = length - 1;
		p->encryption_algorithm = PRIME256V1;
		return 0;
	}

	p->line = __LINE__;

	return -1;
}

int
parse_rsa_info(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err, type, length;

	// jump over 1st byte of BIT STRING (bit remainder byte)

	offset++;

	// BIT STRING encapsulates more TLVs

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}

	end = offset + length; // cannot go past end of SEQUENCE

	// modulus

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != INTEGER || length == 0) {
		p->line = __LINE__;
		return -1;
	}

	p->modulus_offset = offset;
	p->modulus_length = length;

	offset += length;

	// exponent

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != INTEGER || length == 0) {
		p->line = __LINE__;
		return -1;
	}

	p->exponent_offset = offset;
	p->exponent_length = length;

	return 0;
}

int
parse_signature_algorithm(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int len = end - offset;

	// md5WithRSAEncryption?

	if (len == 13 && memcmp(cert + offset, STR_MD5_WITH_RSA_ENCRYPTION, 13) == 0) {
		p->signature_algorithm = MD5_WITH_RSA_ENCRYPTION;
		return 0;
	}

	// sha1WithRSAEncryption?

	if (len == 13 && memcmp(cert + offset, STR_SHA1_WITH_RSA_ENCRYPTION, 13) == 0) {
		p->signature_algorithm = SHA1_WITH_RSA_ENCRYPTION;
		return 0;
	}

	// sha224WithRSAEncryption?

	if (len == 13 && memcmp(cert + offset, STR_SHA224_WITH_RSA_ENCRYPTION, 13) == 0) {
		p->signature_algorithm = SHA224_WITH_RSA_ENCRYPTION;
		return 0;
	}

	// sha256WithRSAEncryption?

	if (len == 13 && memcmp(cert + offset, STR_SHA256_WITH_RSA_ENCRYPTION, 13) == 0) {
		p->signature_algorithm = SHA256_WITH_RSA_ENCRYPTION;
		return 0;
	}

	// sha384WithRSAEncryption?

	if (len == 13 && memcmp(cert + offset, STR_SHA384_WITH_RSA_ENCRYPTION, 13) == 0) {
		p->signature_algorithm = SHA384_WITH_RSA_ENCRYPTION;
		return 0;
	}

	// sha512WithRSAEncryption?

	if (len == 13 && memcmp(cert + offset, STR_SHA512_WITH_RSA_ENCRYPTION, 13) == 0) {
		p->signature_algorithm = SHA512_WITH_RSA_ENCRYPTION;
		return 0;
	}

	// ecdsaWithSHA1?

	if (len == 9 && memcmp(cert + offset, STR_ECDSA_WITH_SHA1, 9) == 0) {
		p->signature_algorithm = ECDSA_WITH_SHA1;
		return 0;
	}

	// ecdsaWithSHA224?

	if (len == 10 && memcmp(cert + offset, STR_ECDSA_WITH_SHA224, 10) == 0) {
		p->signature_algorithm = ECDSA_WITH_SHA224;
		return 0;
	}

	// ecdsaWithSHA256?

	if (len == 10 && memcmp(cert + offset, STR_ECDSA_WITH_SHA256, 10) == 0) {
		p->signature_algorithm = ECDSA_WITH_SHA256;
		return 0;
	}

	// ecdsaWithSHA384?

	if (len == 10 && memcmp(cert + offset, STR_ECDSA_WITH_SHA384, 10) == 0) {
		p->signature_algorithm = ECDSA_WITH_SHA384;
		return 0;
	}

	// ecdsaWithSHA512?

	if (len == 10 && memcmp(cert + offset, STR_ECDSA_WITH_SHA512, 10) == 0) {
		p->signature_algorithm = ECDSA_WITH_SHA512;
		return 0;
	}

	p->line = __LINE__;

	return -1;
}

int
parse_signature(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err = -1;

	switch (p->signature_algorithm) {
	case MD5_WITH_RSA_ENCRYPTION:
	case SHA1_WITH_RSA_ENCRYPTION:
	case SHA224_WITH_RSA_ENCRYPTION:
	case SHA256_WITH_RSA_ENCRYPTION:
	case SHA384_WITH_RSA_ENCRYPTION:
	case SHA512_WITH_RSA_ENCRYPTION:
		err = 0;
		break;
	case ECDSA_WITH_SHA1:
	case ECDSA_WITH_SHA224:
	case ECDSA_WITH_SHA256:
	case ECDSA_WITH_SHA384:
	case ECDSA_WITH_SHA512:
		err = parse_ecdsa_signature(p, cert, offset, end);
		break;
	default:
		p->line = __LINE__;
		break;
	}

	return err;
}

// Example:
//
// 547 104:   BIT STRING, encapsulates {
// 550 101:     SEQUENCE {
// 552  49:       INTEGER
//        :         00 EF 03 5B 7A AC B7 78 0A 72 B7 88 DF FF B5 46
//        :         14 09 0A FA A0 E6 7D 08 C6 1A 87 BD 18 A8 73 BD
//        :         26 CA 60 0C 9D CE 99 9F CF 5C 0F 30 E1 BE 14 31
//        :         EA
// 603  48:       INTEGER
//        :         14 F4 93 3C 49 A7 33 7A 90 46 47 B3 63 7D 13 9B
//        :         4E B7 6F 18 37 80 53 FE DD 20 E0 35 9A 36 D1 C7
//        :         01 B9 E6 DC DD F3 FF 1D 2C 3A 16 57 D9 92 39 D6
//        :       }
//        :     }
//        :   }
//
// offset = 550, the start of SEQUENCE

int
parse_ecdsa_signature(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err, length, type;

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != INTEGER || length == 0) {
		p->line = __LINE__;
		return -1;
	}

	p->r_offset = offset;
	p->r_length = length;

	offset += length;

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err || type != INTEGER || length == 0) {
		p->line = __LINE__;
		return -1;
	}

	p->s_offset = offset;
	p->s_length = length;

	return 0;
}

int
parse_validity(struct certinfo *p, uint8_t *cert, int offset, int end)
{
	int err, length, type;

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err) {
		p->line = __LINE__;
		return -1;
	}

	switch (type) {
	case UTCTIME:
		p->not_before = convert_utc_time(cert + offset, length);
		break;
	case GENERALIZEDTIME:
		p->not_before = convert_generalized_time(cert + offset, length);
		break;
	default:
		p->line = __LINE__;
		return -1;
	}

	if (p->not_before == (time_t) -1) {
		p->line = __LINE__;
		return -1;
	}

	offset += length;

	err = get_type_and_length(cert, end, &offset, &type, &length);

	if (err) {
		p->line = __LINE__;
		return -1;
	}

	switch (type) {
	case UTCTIME:
		p->not_after = convert_utc_time(cert + offset, length);
		break;
	case GENERALIZEDTIME:
		p->not_after = convert_generalized_time(cert + offset, length);
		break;
	default:
		p->line = __LINE__;
		return -1;
	}

	if (p->not_after == (time_t) -1) {
		p->line = __LINE__;
		return -1;
	}

	return 0;
}

time_t
convert_utc_time(uint8_t *s, int len)
{
	int d[17], h, i, j, m;
	struct tm tm;
	time_t t;

	switch (len) {
	case 11:
		// YYMMDDhhmmZ
		j = 10;
		if (s[j] != 'Z')
			return (time_t) -1;
		break;
	case 13:
		// YYMMDDhhmmssZ
		j = 12;
		if (s[j] != 'Z')
			return (time_t) -1;
		break;
	case 15:
		// YYMMDDhhmm+hhmm
		// YYMMDDhhmm-hhmm
		j = 10;
		if (s[j] != '+' && s[j] != '-')
			return (time_t) -1;
		break;
	case 17:
		// YYMMDDhhmmss+hhmm
		// YYMMDDhhmmss-hhmm
		j = 12;
		if (s[j] != '+' && s[j] != '-')
			return (time_t) -1;
		break;
	default:
		return (time_t) -1;
	}

	// check that all digits are 0-9

	for (i = 0; i < len; i++) {
		if (i == j)
			continue;
		if (s[i] < '0' || s[i] > '9')
			return (time_t) -1;
		d[i] = s[i] - '0';
	}

	memset(&tm, 0, sizeof tm);

	tm.tm_year = 10 * d[0] + d[1];

	if (tm.tm_year < 50)
		tm.tm_year += 100; // RFC 5280, p. 23

	tm.tm_mon = 10 * d[2] + d[3] - 1;
	tm.tm_mday = 10 * d[4] + d[5];
	tm.tm_hour = 10 * d[6] + d[7];
	tm.tm_min = 10 * d[8] + d[9];

	if (j == 12)
		tm.tm_sec = 10 * d[10] + d[11];

	// work-around for 32-bit overflow in mktime
	if (sizeof (time_t) == 4 && tm.tm_year > 135) {
		//printf("mktime overflow year %d\n", tm.tm_year + 1900);
		tm.tm_year = 135;
	}

	t = timegm(&tm);

	if (t == (time_t) -1)
		return t;

	if (s[j] == 'Z')
		return t;

	h = 10 * d[j + 1] + d[j + 2];
	m = 10 * d[j + 3] + d[j + 4];

	if (h > 23 || m > 59)
		return (time_t) -1;

	if (s[j] == '+')
		t -= 3600 * h + 60 * m;
	else
		t += 3600 * h + 60 * m;

	return t;
}

time_t
convert_generalized_time(uint8_t *s, int len)
{
	int i, d[14];
	struct tm tm;
	time_t t;

	if (len != 15 || s[14] != 'Z') // RFC 5280, p. 23
		return (time_t) -1;

	// check that all digits are 0-9

	for (i = 0; i < 14; i++) {
		if (s[i] < '0' || s[i] > '9')
			return (time_t) -1;
		d[i] = s[i] - '0';
	}

	memset(&tm, 0, sizeof tm);

	tm.tm_year = 1000 * d[0] + 100 * d[1] + 10 * d[2] + d[3] - 1900;
	tm.tm_mon = 10 * d[4] + d[5] - 1;
	tm.tm_mday = 10 * d[6] + d[7];
	tm.tm_hour = 10 * d[8] + d[9];
	tm.tm_min = 10 * d[10] + d[11];
	tm.tm_sec = 10 * d[12] + d[13];

	// work-around for 32-bit overflow in mktime
	if (sizeof (time_t) == 4 && tm.tm_year > 135) {
		//printf("mktime overflow year %d\n", tm.tm_year + 1900);
		tm.tm_year = 135;
	}

	t = timegm(&tm);

	return t;
}

// offset is advanced to beginning of V in TLV

int
get_type_and_length(uint8_t *cert, int end, int *offset, int *type, int *length)
{
	int i, k, l, n, t;
	k = *offset;
	if (k + 2 > end)
		return -1;
	t = cert[k++];
	l = cert[k++];
	if (l < 128) {
		if (k + l > end)
			return -1;
		*offset = k;
		*type = t;
		*length = l;
		return 0;
	}
	n = l & 0x7f;
	if (k + n > end)
		return -1;
	l = 0;
	for (i = 0; i < n; i++) {
		if (l & 0xff000000)
			return -1;
		l = l << 8 | cert[k++];
	}
	if (k + l > end)
		return -1;
	*offset = k;
	*type = t;
	*length = l;
	return 0;
}
