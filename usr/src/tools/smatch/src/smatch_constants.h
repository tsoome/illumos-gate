#include "expression.h"

#ifndef   	SMATCH_CONSTANTS_H_
#define   	SMATCH_CONSTANTS_H_

static const sval_t int_zero = { .type = &int_ctype, .value = 0 };
static const sval_t int_one  = { .type = &int_ctype, .value = 1 };
static const sval_t int_minus_one  = { .type = &int_ctype, .value = -1 };
static const sval_t err_min  = { .type = &int_ctype, .value = -4095 };
static const sval_t err_max  = { .type = &int_ctype, .value = -1 };
static const sval_t int_max  = { .type = &int_ctype, .value = INT_MAX };

static const sval_t bool_false = { .type = &bool_ctype, .value = 0 };
static const sval_t bool_true = { .type = &bool_ctype, .value = 1 };

extern sval_t ptr_err_min;
extern sval_t ptr_err_max;
static const sval_t ptr_null = { .type = &ptr_ctype, .value = 0 };

static const sval_t ulong_zero	= { .type = &ulong_ctype, .value = 0 };
static const sval_t ulong_one	= { .type = &ulong_ctype, .value = 1 };
static const sval_t ulong_INT_MAX = { .type = &ulong_ctype, .value = INT_MAX };
extern sval_t ulong_ULONG_MAX;

#define MTAG_ALIAS_BIT (1ULL << 63)
#define MTAG_OFFSET_MASK 0xfffULL
#define MTAG_SEED 0xdead << 12

const extern unsigned long valid_ptr_min;
extern unsigned long valid_ptr_max;
extern const sval_t valid_ptr_min_sval;
extern sval_t valid_ptr_max_sval;
extern struct range_list *valid_ptr_rl;
void alloc_ptr_constants(void);

static const sval_t array_min_sval = {
	.type = &ptr_ctype,
	{.value = 100000},
};
static const sval_t array_max_sval = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t text_seg_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t text_seg_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t data_seg_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t data_seg_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t bss_seg_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t bss_seg_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t stack_seg_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t stack_seg_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t kmalloc_seg_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t kmalloc_seg_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t vmalloc_seg_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t vmalloc_seg_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};
static const sval_t fn_ptr_min = {
	.type = &ptr_ctype,
	{.value = 4096},
};
static const sval_t fn_ptr_max = {
	.type = &ptr_ctype,
	{.value = ULONG_MAX - 4095},
};

#endif
