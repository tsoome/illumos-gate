/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

#include <stand.h>
#include <sys/param.h>
#include <libzfs.h>

static const char *typenames[] = {
	"DATA_TYPE_UNKNOWN",
	"DATA_TYPE_BOOLEAN",
	"DATA_TYPE_BYTE",
	"DATA_TYPE_INT16",
	"DATA_TYPE_UINT16",
	"DATA_TYPE_INT32",
	"DATA_TYPE_UINT32",
	"DATA_TYPE_INT64",
	"DATA_TYPE_UINT64",
	"DATA_TYPE_STRING",
	"DATA_TYPE_BYTE_ARRAY",
	"DATA_TYPE_INT16_ARRAY",
	"DATA_TYPE_UINT16_ARRAY",
	"DATA_TYPE_INT32_ARRAY",
	"DATA_TYPE_UINT32_ARRAY",
	"DATA_TYPE_INT64_ARRAY",
	"DATA_TYPE_UINT64_ARRAY",
	"DATA_TYPE_STRING_ARRAY",
	"DATA_TYPE_HRTIME",
	"DATA_TYPE_NVLIST",
	"DATA_TYPE_NVLIST_ARRAY",
	"DATA_TYPE_BOOLEAN_VALUE",
	"DATA_TYPE_INT8",
	"DATA_TYPE_UINT8",
	"DATA_TYPE_BOOLEAN_ARRAY",
	"DATA_TYPE_INT8_ARRAY",
	"DATA_TYPE_UINT8_ARRAY"
};

int
nvpair_type_from_name(const char *name)
{
	unsigned i;

	for (i = 0; i < nitems(typenames); i++) {
		if (strcmp(name, typenames[i]) == 0)
			return (i);
	}
	return (0);
}

static uint_t
nvpair_nelem(nvpair_t *nvp)
{
	uint_t nelem;
	data_type_t type;
	void *val, **valp;

	type = nvpair_type(nvp);
	switch (type) {
	case DATA_TYPE_BOOLEAN:
	case DATA_TYPE_BOOLEAN_VALUE:
	case DATA_TYPE_BYTE:
	case DATA_TYPE_INT8:
	case DATA_TYPE_UINT8:
	case DATA_TYPE_INT16:
	case DATA_TYPE_UINT16:
	case DATA_TYPE_INT32:
	case DATA_TYPE_UINT32:
	case DATA_TYPE_INT64:
	case DATA_TYPE_UINT64:
	case DATA_TYPE_STRING:
	case DATA_TYPE_NVLIST:
	default:
		nelem = 1;
		break;

	case DATA_TYPE_BOOLEAN_ARRAY:
		(void) nvpair_value_boolean_array(nvp,
		    (boolean_t **)&val, &nelem);
		break;
	case DATA_TYPE_BYTE_ARRAY:
		(void) nvpair_value_byte_array(nvp, (uchar_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT8_ARRAY:
		(void) nvpair_value_int8_array(nvp, (int8_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT8_ARRAY:
		(void) nvpair_value_uint8_array(nvp, (uint8_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT16_ARRAY:
		(void) nvpair_value_int16_array(nvp, (int16_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT16_ARRAY:
		(void) nvpair_value_uint16_array(nvp,
		    (uint16_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT32_ARRAY:
		(void) nvpair_value_int32_array(nvp, (int32_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT32_ARRAY:
		(void) nvpair_value_uint32_array(nvp,
		    (uint32_t **)&val, &nelem);
		break;
	case DATA_TYPE_INT64_ARRAY:
		(void) nvpair_value_int64_array(nvp, (int64_t **)&val, &nelem);
		break;
	case DATA_TYPE_UINT64_ARRAY:
		(void) nvpair_value_uint64_array(nvp,
		    (uint64_t **)&val, &nelem);
		break;
	case DATA_TYPE_STRING_ARRAY:
		(void) nvpair_value_string_array(nvp, (char ***)&valp, &nelem);
		break;
	case DATA_TYPE_NVLIST_ARRAY:
		(void) nvpair_value_nvlist_array(nvp,
		    (nvlist_t ***)&valp, &nelem);
		break;
	}
	return (nelem);
}

void
nvpair_print(nvpair_t *nvp, uint_t indent)
{
	uint_t i, nelem;
	data_type_t type;

	for (i = 0; i < indent; i++)
		printf(" ");

	type = nvpair_type(nvp);
	nelem = nvpair_nelem(nvp);
	printf("%s [%d] %s = ", typenames[nvpair_type(nvp)],
	    nelem, nvpair_name(nvp));

	switch (type) {
	case DATA_TYPE_BOOLEAN:
		printf("TRUE");
		break;
	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;
		if (nvpair_value_boolean_value(nvp, &val) == 0)
			printf("%s", val? "B_TRUE" : "B_FALSE");
		break;
	}
	case DATA_TYPE_BYTE: {
		uchar_t val;
		if (nvpair_value_byte(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_INT8: {
		int8_t val;
		if (nvpair_value_int8(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_UINT8: {
		uint8_t val;
		if (nvpair_value_uint8(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_INT16: {
		int16_t val;
		if (nvpair_value_int16(nvp, &val) == 0)
			printf("0x%hx", val);
		break;
	}
	case DATA_TYPE_UINT16: {
		uint16_t val;
		if (nvpair_value_uint16(nvp, &val) == 0)
			printf("0x%hx", val);
		break;
	}
	case DATA_TYPE_INT32: {
		int32_t val;
		if (nvpair_value_int32(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_UINT32: {
		uint32_t val;
		if (nvpair_value_uint32(nvp, &val) == 0)
			printf("0x%x", val);
		break;
	}
	case DATA_TYPE_INT64: {
		int64_t val;
		if (nvpair_value_int64(nvp, &val) == 0)
			printf("0x%jx", (intmax_t)val);
		break;
	}
	case DATA_TYPE_UINT64: {
		uint64_t val;
		if (nvpair_value_uint64(nvp, &val) == 0)
			printf("0x%jx", (uintmax_t)val);
		break;
	}
	case DATA_TYPE_STRING: {
		char *val;
		if (nvpair_value_string(nvp, &val) == 0)
			printf("\"%s\"", val);
		break;
	}
	case DATA_TYPE_NVLIST: {
		nvlist_t *val;
		if (nvpair_value_nvlist(nvp, &val) == 0) {
			printf("\n");
			nvlist_print(val, indent + 2);
		}
		break;
	}
	case DATA_TYPE_BOOLEAN_ARRAY: {
		boolean_t *val;
		if (nvpair_value_boolean_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = %s", i,
				    val[i]? "B_TRUE" : "B_FALSE");
			}
		}
		break;
	}
	case DATA_TYPE_BYTE_ARRAY: {
		uchar_t *val;
		if (nvpair_value_byte_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT8_ARRAY: {
		int8_t *val;
		if (nvpair_value_int8_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT8_ARRAY: {
		uint8_t *val;
		if (nvpair_value_uint8_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT16_ARRAY: {
		int16_t *val;
		if (nvpair_value_int16_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%hx", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT16_ARRAY: {
		uint16_t *val;
		if (nvpair_value_uint16_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%hx", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT32_ARRAY: {
		int32_t *val;
		if (nvpair_value_int32_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT32_ARRAY: {
		uint32_t *val;
		if (nvpair_value_uint32_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%x", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_INT64_ARRAY: {
		int64_t *val;
		if (nvpair_value_int64_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%jx", i, (intmax_t)val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_UINT64_ARRAY: {
		uint64_t *val;
		if (nvpair_value_uint64_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = 0x%jx", i, (uintmax_t)val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_STRING_ARRAY: {
		char **val;
		if (nvpair_value_string_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				printf(" [%u] = \"%s\"", i, val[i]);
			}
		}
		break;
	}
	case DATA_TYPE_NVLIST_ARRAY: {
		nvlist_t **val;
		if (nvpair_value_nvlist_array(nvp, &val, &nelem) == 0) {
			for (i = 0; i < nelem; i++) {
				nvlist_print(val[i], indent + 2);
			}
		}
		break;
	}
	default:
		printf("unknown type");
	}
	printf("\n");
}

void
nvlist_print(nvlist_t *nvl, unsigned int indent)
{
	nvpair_t *nvp;

	for (nvp = nvlist_next_nvpair(nvl, NULL); nvp != NULL;
	    nvp = nvlist_next_nvpair(nvl, nvp)) {
		nvpair_print(nvp, indent);
	}

	printf("%*s\n", indent + 13, "End of nvlist");
}

int
nvpair_sprintf(char **valp, nvpair_t *nvp)
{
	int rv;
	char *value;

	if (nvp == NULL)
		return (EINVAL);

	value = NULL;
	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BYTE: {
		uchar_t val;
		rv = nvpair_value_byte(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%uc", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT8: {
		int8_t val;
		rv = nvpair_value_int8(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%c", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT8: {
		uint8_t val;
		rv = nvpair_value_uint8(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%uc", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT16: {
		int16_t val;
		rv = nvpair_value_int16(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%hd", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT16: {
		uint16_t val;
		rv = nvpair_value_uint16(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%hu", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_BOOLEAN_VALUE: {
		boolean_t val;
		rv = nvpair_value_boolean_value(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%d", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT32: {
		int32_t val;
		rv = nvpair_value_int32(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%d", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT32: {
		uint32_t val;
		rv = nvpair_value_uint32(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%u", val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_INT64: {
		int64_t val;
		rv = nvpair_value_int64(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%jd", (intmax_t)val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_UINT64: {
		uint64_t val;
		rv = nvpair_value_uint64(nvp, &val);
		if (rv == 0) {
			(void) asprintf(&value, "%ju", (uintmax_t)val);
			if (value == NULL)
				rv = ENOMEM;
		}
		break;
	}

	case DATA_TYPE_STRING: {
		char *val;
		rv = nvpair_value_string(nvp, &val);
		if (rv == 0) {
			value = strdup(val);
			if (value == NULL)
				rv = ENOMEM;
			break;
		}
		break;
	}

	default:
		rv = EINVAL;
		break;
	}
	if (rv == 0)
		*valp = value;
	return (rv);
}
