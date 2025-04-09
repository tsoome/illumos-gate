/*
 * This is a simple program to reproduce the problems with the mod functions
 * for the NIST-P192 and NIST-P224 primes.
 *
 * The file is copied from
 * https://bugzilla.mozilla.org/attachment.cgi?id=620796&action=edit
 * The first version was provided by Owen Kirby, updated by Robert Relyea.
 * Adopted for illumos test suite by Toomas Soome.
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "mpi.h"
#include "mpi-priv.h"
#include "ecl.h"
#include "ecl-priv.h"

/* Expose internal ECL functions so that we're not using generic arithmetic. */
ECGroup *ecgroup_fromNameAndHex(const ECCurveName name,const ECCurveParams * params);

/* Curve parameters for NIST-P192, NIST-P224 and NIST-P256 */
static const ECCurveParams ec_curve_nist_p192 = {
    "NIST-P192", ECField_GFp, 192,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", /* prime */
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", /* a */
    "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", /* b */
    "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", /* x */
    "07192b95ffc8da78631011ed6b24cdd573f977a11e794811", /* y */
    "FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", /* order */
    1 /* cofactor */
};

static const ECCurveParams ec_curve_nist_p224 = {
    "NIST-P224", ECField_GFp, 224,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", /* prime */
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", /* a */
    "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", /* b */
    "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", /* x */
    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", /* y */
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", /* order */
    1 /* cofactor */
};

static const ECCurveParams ec_curve_nist_p256 = {
    "NIST-P256", ECField_GFp, 256,
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", /* prime */
    "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", /* a */
    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", /* b */
    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", /* x */
    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", /* y */
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", /* order */
    1 /* cofactor */
};

static const ECCurveParams ec_curve_nist_p384 = {
    "NIST-P384", ECField_GFp, 384,
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
    "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
    "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
    "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    1
};

static const ECCurveParams ec_curve_nist_p521 = {
    "NIST-P521", ECField_GFp, 521,
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
    "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
    "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
    "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    1
};

static int
test_mod(const ECGroup *group)
{
    int error = 0, i, range = 0xffff;
    mp_err  res;
    mp_int  g, e, r, x;
    MP_CHECKOK(mp_init(&g, 0));
    MP_CHECKOK(mp_init(&e, 0));
    MP_CHECKOK(mp_init(&r, 0));
    MP_CHECKOK(mp_init(&x, 0));

    /* First do a really easy test... p mod p == 0 and p^2 mod p == 0 */
    MP_CHECKOK(group->meth->field_mod(&group->meth->irr, &x, group->meth));
    MP_CHECKOK(group->meth->field_sqr(&group->meth->irr, &r, group->meth));
    MP_CHECKOK(group->meth->field_mod(&r, &r, group->meth));
    if (mp_cmp_z(&x) != 0) {
        fprintf(stderr, "p (mod p) != 0 for p=%s!\n", group->text);
	error = 1;
        goto CLEANUP;
    }
    if (mp_cmp_z(&r)) {
        fprintf(stderr, "p^2 (mod p) != 0 for p=%s!\n", group->text);
	error = 1;
        goto CLEANUP;
    }

    /*
     * Pick some numbers out of a hat...  I stumbled across these particular set of numbers
     * while testing an exptmod() function using field arithmetic. I've reduced my test case
     * to a small set of operations which reproduce the bug.
     */
    /* Set e=p-range and g=(p-1)/2 */
    MP_CHECKOK(mp_sub_d(&group->meth->irr, range, &e));
    MP_CHECKOK(mp_div_2(&group->meth->irr, &g));

    /* Compute g^e mod p using the MPI library. */
    MP_CHECKOK(s_mp_exptmod(&g, &e, &group->meth->irr, &x));

    /* Iterate with different exponents.  */
    for (i=0; i<range; i++) {
        /* Increment e. */
        MP_CHECKOK(mp_add_d(&e, 1, &e));

        /* Compute g^(e+1) mod p = g * g^e mod p using the MPI library. */
        MP_CHECKOK(mp_mul(&x, &g, &x));
        MP_CHECKOK(mp_mod(&x, &group->meth->irr, &r));

        /* Compute g^(e+1) mod p = g * g^e mod p using the ECL library. */
        MP_CHECKOK(group->meth->field_mod(&x, &x, group->meth));

        /* Check that we got the same result. */
        if (mp_cmp(&r, &x) != 0) {
            fprintf(stderr, "field_mod disagrees with mp_mod for p=%s!\n",
		group->text);
	    error = 1;
            goto CLEANUP;
        }
    } /* for */
    if (i >= range) {
        printf("field_mod agrees with mp_mod for p=%s!\n", group->text);
    }

  CLEANUP:
    if (res != MP_OKAY) {
        fprintf(stderr, "Library error for p=%s!\n", group->text);
    }
    mp_clear(&g);
    mp_clear(&e);
    mp_clear(&r);
    mp_clear(&x);
    return (error);
} /* test_mod */

int
main(int argc, char *argv[])
{
    ECGroup *group;
    mp_err   res = MP_OKAY;
    int errors = 0;

    /* Run the test for NIST-P192. */
    group = ecgroup_fromNameAndHex(ECCurve_SECG_PRIME_192R1, &ec_curve_nist_p192);
    if (!group) {res = MP_MEM; goto CLEANUP;}
    errors += test_mod(group);
    ECGroup_free(group);

    /* Run the test for NIST-P224 */
    group = ecgroup_fromNameAndHex(ECCurve_SECG_PRIME_224R1, &ec_curve_nist_p224);
    if (!group) {res = MP_MEM; goto CLEANUP;}
    errors += test_mod(group);
    ECGroup_free(group);

    /* Run the test for NIST-P256 */
    group = ecgroup_fromNameAndHex(ECCurve_SECG_PRIME_256R1, &ec_curve_nist_p256);
    if (!group) {res = MP_MEM; goto CLEANUP;}
    errors += test_mod(group);
    ECGroup_free(group);

    /* Run the test for NIST-P384 */
    group = ecgroup_fromNameAndHex(ECCurve_SECG_PRIME_384R1, &ec_curve_nist_p384);
    if (!group) {res = MP_MEM; goto CLEANUP;}
    errors += test_mod(group);
    ECGroup_free(group);

    /* Run the test for NIST-P521 */
    group = ecgroup_fromNameAndHex(ECCurve_SECG_PRIME_521R1, &ec_curve_nist_p521);
    if (!group) {res = MP_MEM; goto CLEANUP;}
    errors += test_mod(group);
    ECGroup_free(group);

  CLEANUP:
    if (res != MP_OKAY) {
        fprintf(stderr, "Really bad library error!\n");
	errors++;
    }
    /* 3 or 4 is SKIP, we do not skip here anything, only PASS or FAIL */
    return (errors == 0? 0 : 1);
} /* main */

/*------------------------------------------------------------------------*/
/* HERE THERE BE DRAGONS                                                  */
