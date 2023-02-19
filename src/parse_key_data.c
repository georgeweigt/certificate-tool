int
parse_key_data(struct keyinfo *p)
{
	if (p->key_type == RSA_ENCRYPTION)
		return parse_rsa_key_data(p);
	else
		return parse_ec_key_data(p);
}

int
parse_rsa_key_data(struct keyinfo *p)
{
	int end, err, length, offset, type;

	end = p->key_data_length;
	offset = 0;

	// SEQUENCE

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}

	end = offset + length; // cannot go past end of this sequence

	// version

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	offset += length;

	// modulus

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->modulus_offset = offset;
	p->modulus_length = length;

	offset += length;

	// public exponent

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->public_exponent_offset = offset;
	p->public_exponent_length = length;

	offset += length;

	// private exponent

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->private_exponent_offset = offset;
	p->private_exponent_length = length;

	offset += length;

	// prime1

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->prime1_offset = offset;
	p->prime1_length = length;

	offset += length;

	// prime2

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->prime2_offset = offset;
	p->prime2_length = length;

	offset += length;

	// exponent1

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->exponent1_offset = offset;
	p->exponent1_length = length;

	offset += length;

	// exponent2

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->exponent2_offset = offset;
	p->exponent2_length = length;

	offset += length;

	// coefficient

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	p->coefficient_offset = offset;
	p->coefficient_length = length;

	offset += length;

	return 0;
}

#define STR_PRIME256V1 "\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define STR_SECP384R1 "\x2b\x81\x04\x00\x22"

int
parse_ec_key_data(struct keyinfo *p)
{
	int end, err, length, offset, t, type;

	end = p->key_data_length;
	offset = 0;

	// SEQUENCE

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != SEQUENCE) {
		p->line = __LINE__;
		return -1;
	}

	end = offset + length; // cannot go past end of this sequence

	// INTEGER

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != INTEGER) {
		p->line = __LINE__;
		return -1;
	}

	offset += length;

	// OCTET STRING

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != OCTET_STRING) {
		p->line = __LINE__;
		return -1;
	}

	p->ec_private_key_offset = offset;
	p->ec_private_key_length = length;

	offset += length;

	// [0] { OID }

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != 0xa0) {
		p->line = __LINE__;
		return -1;
	}

	t = offset + length; // embedded length

	err = get_type_and_length(p->key_data, t, &offset, &type, &length);

	if (err || type != OID) {
		p->line = __LINE__;
		return -1;
	}

	p->ec_oid_offset = offset;
	p->ec_oid_length = length;

	offset += length;

	if (offset != t) {
		p->line = __LINE__;
		return -1; // alignment error
	}

	// [1] { BIT STRING }

	err = get_type_and_length(p->key_data, end, &offset, &type, &length);

	if (err || type != 0xa1) {
		p->line = __LINE__;
		return -1;
	}

	t = offset + length; // embedded length

	err = get_type_and_length(p->key_data, t, &offset, &type, &length);

	if (err || type != BIT_STRING) {
		p->line = __LINE__;
		return -1;
	}

	p->ec_public_key_offset = offset + 1; // skip over remainder byte
	p->ec_public_key_length = length - 1;

	offset += length;

	if (offset != t) {
		p->line = __LINE__;
		return -1; // alignment error
	}

	// check oid

	if (p->ec_oid_length == 8 && memcmp(p->key_data + p->ec_oid_offset, STR_PRIME256V1, 8) == 0) {
		p->key_type = PRIME256V1;
		return 0;
	}

	if (p->ec_oid_length == 5 && memcmp(p->key_data + p->ec_oid_offset, STR_SECP384R1, 5) == 0) {
		p->key_type = SECP384R1;
		return 0;
	}

	p->key_type = 0; // unsupported key type

	return 0;
}
