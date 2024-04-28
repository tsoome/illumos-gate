/*
 * Copyright (C) 2006 Dan Carpenter.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

/*
 * Miscellaneous helper functions.
 */

#include <stdlib.h>
#include <stdio.h>
#include "allocate.h"
#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

#define VAR_LEN 512

static struct expression *strip_expr_helper(struct expression *expr, bool set_parent, bool cast, int *nest);

char *alloc_string(const char *str)
{
	char *tmp;

	if (!str)
		return NULL;
	tmp = malloc(strlen(str) + 1);
	strcpy(tmp, str);
	return tmp;
}

char *alloc_string_newline(const char *str)
{
	char *tmp;
	int len;

	if (!str)
		return NULL;
	len = strlen(str);
	tmp = malloc(len + 2);
	snprintf(tmp, len + 2, "%s\n", str);
	return tmp;
}

void free_string(char *str)
{
	free(str);
}

void remove_parens(char *str)
{
	char *src, *dst;

	dst = src = str;
	while (*src != '\0') {
		if (*src == '(' || *src == ')') {
			src++;
			continue;
		}
		*dst++ = *src++;
	}
	*dst = *src;
}

struct smatch_state *alloc_state_num(int num)
{
	struct smatch_state *state;
	static char buff[256];

	state = __alloc_smatch_state(0);
	snprintf(buff, 255, "%d", num);
	buff[255] = '\0';
	state->name = alloc_string(buff);
	state->data = INT_PTR(num);
	return state;
}

struct smatch_state *alloc_state_str(const char *name)
{
	struct smatch_state *state;

	state = __alloc_smatch_state(0);
	state->name = alloc_string(name);
	return state;
}

struct smatch_state *merge_str_state(struct smatch_state *s1, struct smatch_state *s2)
{
	if (!s1->name || !s2->name)
		return &merged;
	if (strcmp(s1->name, s2->name) == 0)
		return s1;
	return &merged;
}

struct smatch_state *alloc_state_expr(struct expression *expr)
{
	struct smatch_state *state;
	char *name;

	expr = strip_expr(expr);
	name = expr_to_str(expr);
	if (!name)
		return NULL;

	state = __alloc_smatch_state(0);
	state->name = alloc_sname(name);
	free_string(name);
	state->data = expr;
	return state;
}

static int FORMAT_ATTR(4) append(char *dest, int off, int len, const char *fmt, ...)
{
	int n;
	va_list args;

	if (len <= 0 || off < 0 || off >= len - 1)
		return 0;

	va_start(args, fmt);
	n = vsnprintf(dest + off, len - off, fmt, args);
	va_end(args);

	if (n > len - off - 1)
		return len - off - 1;
	return n;
}

struct expression *get_assigned_call(struct expression *expr)
{
	while (expr && expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (!expr || expr->type != EXPR_CALL)
		return NULL;
	return expr;
}

/*
 * If you have "foo(a, b, 1);" then use
 * get_argument_from_call_expr(expr, 0) to return the expression for
 * a.  Yes, it does start counting from 0.
 */
struct expression *get_argument_from_call_expr(struct expression_list *args,
					       int num)
{
	struct expression *expr;
	int i = 0;

	if (!args)
		return NULL;

	FOR_EACH_PTR(args, expr) {
		if (i == num)
			return expr;
		i++;
	} END_FOR_EACH_PTR(expr);
	return NULL;
}

struct expression *get_array_expr(struct expression *expr)
{
	struct expression *parent;
	struct symbol *type;

	if (expr->type != EXPR_BINOP || expr->op != '+')
		return NULL;

	type = get_type(expr->left);
	if (!type)
		return NULL;
	if (type->type == SYM_ARRAY)
		return expr->left;
	if (type->type != SYM_PTR)
		return NULL;

	parent = expr_get_parent_expr(expr);
	if (!parent)  /* Sometimes we haven't set up the ->parent yet. FIXME!! */
		return expr->left;
	if (parent->type == EXPR_PREOP && parent->op == '*')
		return expr->left;

	return NULL;
}

static struct expression *strip_star_address(struct expression *expr)
{
	struct expression *unop;

	if (expr->type != EXPR_PREOP || expr->op != '*')
		return expr;
	unop = strip_parens(expr->unop);
	if (unop->type != EXPR_PREOP || unop->op != '&')
		return expr;

	return unop->unop;
}

static struct expression *strip_parens_symbol(struct expression *expr)
{
	struct expression *unop;

	if (expr->type != EXPR_PREOP || expr->op != '(')
		return expr;
	/*
	 * This should probably be strip_parens() but expr_to_str() doesn't
	 * print casts so we may as well strip those too.  In other words,
	 * instead of fixing the code to print the cast, it's easier to just
	 * write even more code that relies on the bug.  ;)
	 */
	unop = strip_expr(expr->unop);
	if (unop->type != EXPR_SYMBOL)
		return expr;
	return unop;
}

static int __get_variable_from_expr(struct symbol **sym_ptr, char *buf,
				     struct expression *expr, int off, int len,
				     int *complicated)
{
	int orig_off = off;

	if (!expr) {
		/* can't happen on valid code */
		*complicated = 1;
		return 0;
	}

	expr = strip_star_address(expr);
	expr = strip_parens_symbol(expr);

	switch (expr->type) {
	case EXPR_DEREF: {
		struct expression *deref;
		int op;

		op = expr->op;
		deref = expr->deref;

		/* this is pure guess work and nonsense programming */
		if (deref->type == EXPR_PREOP && deref->op == '*') {
			op = '*';
			deref = deref->unop;
		}

		off += __get_variable_from_expr(sym_ptr, buf, deref, off, len, complicated);

		if (op == '*')
			off += append(buf, off, len, "->");
		else
			off += append(buf, off, len, ".");

		if (expr->member)
			off += append(buf, off, len, "%s", expr->member->name);
		else
			off += append(buf, off, len, "unknown_member");
		return off - orig_off;
	}
	case EXPR_SYMBOL:
		if (expr->symbol_name)
			off += append(buf, off, len, "%s", expr->symbol_name->name);
		if (sym_ptr) {
			if (*sym_ptr)
				*complicated = 1;
			*sym_ptr = expr->symbol;
		}
		return off - orig_off;
	case EXPR_PREOP: {
		const char *tmp;

		if (get_expression_statement(expr)) {
			*complicated = 2;
			return 0;
		}
		if (expr->op == SPECIAL_DECREMENT ||
		    expr->op == SPECIAL_INCREMENT)
			*complicated = 1;

		if (expr->op == '*' && get_array_expr(expr->unop))
			tmp = "";
		else
			tmp = show_special(expr->op);

		off += append(buf, off, len, "%s", tmp);
		off += __get_variable_from_expr(sym_ptr, buf, expr->unop, off,
						len, complicated);
		if (expr->op == '(')
			off += append(buf, off, len, ")");

		return off - orig_off;
	}
	case EXPR_POSTOP: {
		off += __get_variable_from_expr(sym_ptr, buf, expr->unop, off, len,
						complicated);
		off += append(buf, off, len, "%s", show_special(expr->op));

		if (expr->op == SPECIAL_DECREMENT || expr->op == SPECIAL_INCREMENT)
			*complicated = 1;
		return off - orig_off;
	}
	case EXPR_ASSIGNMENT:
	case EXPR_COMPARE:
	case EXPR_LOGICAL:
	case EXPR_BINOP:
	case EXPR_COMMA: {
		struct expression *array_expr;

		*complicated = 1;
		array_expr = get_array_expr(expr);
		if (array_expr) {
			off += __get_variable_from_expr(sym_ptr, buf, array_expr, off, len, complicated);
			off += append(buf, off, len, "[");
		} else {
			off += __get_variable_from_expr(sym_ptr, buf, expr->left, off, len, complicated);
			off += append(buf, off, len, "%s%s ",
				      (expr->type == EXPR_COMMA) ? "" : " ",
				      show_special(expr->op));
		}
		off += __get_variable_from_expr(NULL, buf, expr->right, off, len, complicated);
		if (array_expr)
			off += append(buf, off, len, "]");
		return off - orig_off;
	}
	case EXPR_VALUE: {
		sval_t sval = {};

		*complicated = 1;
		if (!get_value(expr, &sval))
			return 0;
		off += append(buf, off, len, "%s", sval_to_numstr(sval));
		return off - orig_off;
	}
	case EXPR_FVALUE: {
		sval_t sval = {};

		*complicated = 1;
		if (!get_value(expr, &sval))
			return 0;

		off += append(buf, off, len, "%s", sval_to_numstr(sval));
		return off - orig_off;
	}
	case EXPR_STRING:
		off += append(buf, off, len, "\"");
		if (expr->string)
			off += append(buf, off, len, "%s", expr->string->data);
		off += append(buf, off, len, "\"");
		return off - orig_off;
	case EXPR_CALL: {
		struct expression *tmp;
		int i;

		*complicated = 1;
		off += __get_variable_from_expr(NULL, buf, expr->fn, off, len, complicated);
		off += append(buf, off, len, "(");
		i = 0;
		FOR_EACH_PTR(expr->args, tmp) {
			if (i++)
				off += append(buf, off, len, ", ");
			off += __get_variable_from_expr(NULL, buf, tmp, off, len, complicated);
		} END_FOR_EACH_PTR(tmp);
		off += append(buf, off, len, ")");
		return off - orig_off;
	}
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
		return __get_variable_from_expr(sym_ptr, buf,
						expr->cast_expression, off, len,
						complicated);
	case EXPR_SIZEOF: {
		sval_t sval;
		int size;

		if (expr->cast_type && get_base_type(expr->cast_type)) {
			size = type_bytes(get_base_type(expr->cast_type));
			off += append(buf, off, len, "%d", size);
		} else if (get_value(expr, &sval)) {
			off += append(buf, off, len, "%s", sval_to_str(sval));
		}
		return off - orig_off;
	}
	case EXPR_IDENTIFIER:
		*complicated = 1;
		if (expr->expr_ident)
			off += append(buf, off, len, "%s", expr->expr_ident->name);
		return off - orig_off;
	case EXPR_SELECT:
	case EXPR_CONDITIONAL:
		*complicated = 1;
		off += append(buf, off, len, "(");
		off += __get_variable_from_expr(NULL, buf, expr->conditional, off, len, complicated);
		off += append(buf, off, len, ") ?");
		if (expr->cond_true)
			off += __get_variable_from_expr(NULL, buf, expr->cond_true, off, len, complicated);
		off += append(buf, off, len, ":");
		off += __get_variable_from_expr(NULL, buf, expr->cond_false, off, len, complicated);
		return off - orig_off;
	default:
		off += append(buf, off, len, "$expr_%p(%d)", expr, expr->type);
		return off - orig_off;
	}
}

struct expr_str_cache_results {
	struct expression *expr;
	char str[VAR_LEN];
	struct symbol *sym;
	int complicated;
};

static void get_variable_from_expr(struct symbol **sym_ptr, char *buf,
				     struct expression *expr, int len,
				     int *complicated)
{
	static struct expr_str_cache_results cached[8];
	struct symbol *tmp_sym = NULL;
	static int idx;
	int i;

	for (i = 0; i < ARRAY_SIZE(cached); i++) {
		if (expr == cached[i].expr) {
			strncpy(buf, cached[i].str, len);
			if (sym_ptr)
				*sym_ptr = cached[i].sym;
			*complicated = cached[i].complicated;
			return;
		}
	}

	__get_variable_from_expr(&tmp_sym, buf, expr, 0, len, complicated);
	if (sym_ptr)
		*sym_ptr = tmp_sym;

	if (expr->smatch_flags & Tmp)
		return;

	cached[idx].expr = expr;
	strncpy(cached[idx].str, buf, VAR_LEN);
	cached[idx].sym = tmp_sym;
	cached[idx].complicated = *complicated;

	idx = (idx + 1) % ARRAY_SIZE(cached);
}

/*
 * This is returns a stylized "c looking" representation of the
 * variable name.
 *
 * It uses the same buffer every time so you have to save the result
 * yourself if you want to keep it.
 *
 */

char *expr_to_str_sym(struct expression *expr, struct symbol **sym_ptr)
{
	static char var_name[VAR_LEN];
	int complicated = 0;

	if (sym_ptr)
		*sym_ptr = NULL;
	var_name[0] = '\0';

	if (!expr)
		return NULL;
	get_variable_from_expr(sym_ptr, var_name, expr, sizeof(var_name),
			       &complicated);
	if (complicated < 2)
		return alloc_string(var_name);
	else
		return NULL;
}

char *expr_to_str(struct expression *expr)
{
	return expr_to_str_sym(expr, NULL);
}

/*
 * get_variable_from_expr_simple() only returns simple variables.
 * If it's a complicated variable like a->foo[x] instead of just 'a->foo'
 * then it returns NULL.
 */
char *expr_to_var_sym(struct expression *expr,
				    struct symbol **sym_ptr)
{
	static char var_name[VAR_LEN];
	int complicated = 0;

	if (sym_ptr)
		*sym_ptr = NULL;
	var_name[0] = '\0';

	if (!expr)
		return NULL;
	expr = strip_expr(expr);
	get_variable_from_expr(sym_ptr, var_name, expr, sizeof(var_name),
			       &complicated);

	if (complicated) {
		if (sym_ptr)
			*sym_ptr = NULL;
		return NULL;
	}
	return alloc_string(var_name);
}

char *expr_to_var(struct expression *expr)
{
	return expr_to_var_sym(expr, NULL);
}

struct symbol *expr_to_sym(struct expression *expr)
{
	struct symbol *sym;
	char *name;

	name = expr_to_var_sym(expr, &sym);
	free_string(name);
	return sym;
}

int get_complication_score(struct expression *expr)
{
	expr = strip_expr(expr);

	/*
	 * Don't forget to keep get_complication_score() and store_all_links()
	 * in sync.
	 *
	 */

	if (!expr)
		return 990;

	switch (expr->type) {
	case EXPR_CALL:
		return 991;
	case EXPR_COMPARE:
	case EXPR_BINOP:
		return get_complication_score(expr->left) +
		       get_complication_score(expr->right);
	case EXPR_SYMBOL:
		return 1;
	case EXPR_PREOP:
		if (expr->op == '*' || expr->op == '(')
			return get_complication_score(expr->unop);
		return 993;
	case EXPR_DEREF:
		return get_complication_score(expr->deref);
	case EXPR_VALUE:
	case EXPR_SIZEOF:
		return 0;
	default:
		return 994;
	}
}

struct expression *reorder_expr_alphabetically(struct expression *expr)
{
	struct expression *ret;
	char *left, *right;

	if (expr->type != EXPR_BINOP)
		return expr;
	if (expr->op != '+' && expr->op != '*')
		return expr;

	left = expr_to_var(expr->left);
	right = expr_to_var(expr->right);
	ret = expr;
	if (!left || !right)
		goto free;
	if (strcmp(left, right) <= 0)
		goto free;

	ret = binop_expression(expr->right, expr->op, expr->left);
free:
	free_string(left);
	free_string(right);

	return ret;
}

char *expr_to_chunk_helper(struct expression *expr, struct symbol **sym, struct var_sym_list **vsl)
{
	struct var_sym_list *tmp_vsl;
	char *name;
	struct symbol *tmp;
	int score;

	if (vsl)
		*vsl = NULL;
	if (sym)
		*sym = NULL;

	expr = strip_parens(expr);
	if (!expr)
		return NULL;

	name = expr_to_var_sym(expr, &tmp);
	if (name && tmp) {
		if (sym)
			*sym = tmp;
		if (vsl)
			add_var_sym(vsl, name, tmp);
		return name;
	}
	free_string(name);

	score = get_complication_score(expr);
	if (score <= 0 || score > 2)
		return NULL;

	tmp_vsl = expr_to_vsl(expr);
	if (vsl) {
		*vsl = tmp_vsl;
		if (!*vsl)
			return NULL;
	}
	if (sym) {
		if (ptr_list_size((struct ptr_list *)tmp_vsl) == 1) {
			struct var_sym *vs;

			vs = first_ptr_list((struct ptr_list *)tmp_vsl);
			*sym = vs->sym;
		}
	}

	expr = reorder_expr_alphabetically(expr);

	return expr_to_str(expr);
}

char *expr_to_known_chunk_sym(struct expression *expr, struct symbol **sym)
{
	return expr_to_chunk_helper(expr, sym, NULL);
}

char *expr_to_chunk_sym_vsl(struct expression *expr, struct symbol **sym, struct var_sym_list **vsl)
{
	return expr_to_chunk_helper(expr, sym, vsl);
}

int sym_name_is(const char *name, struct expression *expr)
{
	if (!expr)
		return 0;
	if (expr->type != EXPR_SYMBOL)
		return 0;
	if (!strcmp(expr->symbol_name->name, name))
		return 1;
	return 0;
}

int expr_is_zero(struct expression *expr)
{
	sval_t sval;

	if (get_value(expr, &sval) && sval.value == 0)
		return 1;
	return 0;
}

int is_array(struct expression *expr)
{
	struct symbol *type;

	expr = strip_expr(expr);
	if (!expr)
		return 0;

	if (expr->type == EXPR_PREOP && expr->op == '*') {
		expr = strip_expr(expr->unop);
		if (!expr)
			return 0;
		if (expr->type == EXPR_BINOP && expr->op == '+')
			return 1;
	}

	if (expr->type != EXPR_BINOP || expr->op != '+')
		return 0;

	type = get_type(expr->left);
	if (!type || type->type != SYM_ARRAY)
		return 0;

	return 1;
}

struct expression *get_array_base(struct expression *expr)
{
	if (!is_array(expr))
		return NULL;
	expr = strip_expr(expr);
	if (expr->type == EXPR_PREOP && expr->op == '*')
		expr = strip_expr(expr->unop);
	if (expr->type != EXPR_BINOP || expr->op != '+')
		return NULL;
	return strip_parens(expr->left);
}

struct expression *get_array_offset(struct expression *expr)
{
	if (!is_array(expr))
		return NULL;
	expr = strip_expr(expr);
	if (expr->type == EXPR_PREOP && expr->op == '*')
		expr = strip_expr(expr->unop);
	if (expr->type != EXPR_BINOP || expr->op != '+')
		return NULL;
	expr = strip_parens(expr->right);
	if (expr->type == EXPR_POSTOP)
		expr = strip_parens(expr->unop);
	return expr;
}

const char *show_state(struct smatch_state *state)
{
	if (!state)
		return NULL;
	return state->name;
}

struct statement *get_expression_statement(struct expression *expr)
{
	/* What are those things called? if (({....; ret;})) { ...*/

	if (expr->type != EXPR_PREOP)
		return NULL;
	if (expr->op != '(')
		return NULL;
	if (!expr->unop)
		return NULL;
	if (expr->unop->type != EXPR_STATEMENT)
		return NULL;
	if (expr->unop->statement->type != STMT_COMPOUND)
		return NULL;
	return expr->unop->statement;
}

struct expression *strip_parens(struct expression *expr)
{
	if (!expr)
		return NULL;

	if (expr->type == EXPR_PREOP) {
		if (!expr->unop)
			return expr;  /* parsing invalid code */

		if (expr->op == '(' && expr->unop->type == EXPR_STATEMENT &&
			expr->unop->statement->type == STMT_COMPOUND)
			return expr;
		if (expr->op == '(')
			return strip_parens(expr->unop);
	}
	return expr;
}

struct expression *strip__builtin_choose_expr(struct expression *expr)
{
	struct expression *const_expr, *expr1, *expr2;
	sval_t sval;

	if (expr->type != EXPR_CALL)
		return expr;

	if (!sym_name_is("__builtin_choose_expr", expr->fn))
		return expr;

	const_expr = get_argument_from_call_expr(expr->args, 0);
	expr1 = get_argument_from_call_expr(expr->args, 1);
	expr2 = get_argument_from_call_expr(expr->args, 2);

	if (!get_value(const_expr, &sval) || !expr1 || !expr2)
		return expr;

	if (sval.value)
		return strip_expr(expr1);
	else
		return strip_expr(expr2);
}

struct expression *strip_Generic(struct expression *expr)
{
	struct type_expression *map;
	struct symbol *type, *tmp;

	if (!expr || expr->type != EXPR_GENERIC)
		return expr;

	type = get_type(expr->control);

	for (map = expr->map; map; map = map->next) {
		tmp = get_real_base_type(map->type);
		if (!types_equiv(type, tmp))
			continue;
		if (!map->expr)
			return expr;
		return map->expr;
	}

	if (!expr->def)
		return expr;

	return expr->def;
}

static struct expression *strip_plus_zero(struct expression *expr, bool set_parent, bool cast, int *nest)
{
	struct symbol *left_type, *right_type;

	if (*nest > 4)
		return expr;

	if (expr->type != EXPR_BINOP || expr->op != '+')
		return expr;

	/* don't strip away zero from the my_array[0] */
	if (!is_array(expr->left))
		return expr;

	left_type = get_type(expr->left);
	right_type = get_type(expr->right);
	if (!left_type || !right_type)
		return expr;

	if (expr_is_zero(expr->left)) {
		if (type_positive_bits(left_type) > 31 &&
		    type_positive_bits(left_type) > type_positive_bits(right_type))
			return expr;
		return strip_expr_helper(expr->right, set_parent, cast, nest);
	}
	if (expr_is_zero(expr->right)) {
		if (type_positive_bits(right_type) > 31 &&
		    type_positive_bits(right_type) > type_positive_bits(left_type))
			return expr;
		return strip_expr_helper(expr->left, set_parent, cast, nest);
	}

	return expr;
}

static struct expression *strip_expr_helper(struct expression *expr, bool set_parent, bool cast, int *nest)
{
	(*nest)++;

	if (!expr)
		return NULL;

	switch (expr->type) {
	case EXPR_FORCE_CAST:
	case EXPR_CAST:
		if (set_parent)
			expr_set_parent_expr(expr->cast_expression, expr);

		if (!expr->cast_expression)
			return expr;
		if (!cast) {
			struct symbol *type;

			type = get_type(expr->cast_expression);
			if (type != expr->cast_type)
				return expr;
		}
		return strip_expr_helper(expr->cast_expression, set_parent, cast, nest);
	case EXPR_PREOP: {
		struct expression *unop;

		if (!expr->unop)  /* parsing invalid code */
			return expr;
		if (set_parent)
			expr_set_parent_expr(expr->unop, expr);

		while (expr->op == '(' &&
		       expr->unop->type == EXPR_PREOP &&
		       expr->unop->op == '(')
			expr = expr->unop;

		if (expr->op == '(' && expr->unop->type == EXPR_STATEMENT &&
			expr->unop->statement->type == STMT_COMPOUND)
			return expr;

		unop = strip_expr_helper(expr->unop, set_parent, cast, nest);

		if (expr->op == '*' && unop &&
		    unop->type == EXPR_PREOP && unop->op == '&') {
			struct symbol *type = get_type(unop->unop);

			if (type && type->type == SYM_ARRAY)
				return expr;
			return strip_expr_helper(unop->unop, set_parent, cast, nest);
		}

		if (expr->op == '(')
			return unop;

		return expr;
	}
	case EXPR_CONDITIONAL:
		if (known_condition_true(expr->conditional)) {
			if (expr->cond_true) {
				if (set_parent)
					expr_set_parent_expr(expr->cond_true, expr);
				return strip_expr_helper(expr->cond_true, set_parent, cast, nest);
			}
			if (set_parent)
				expr_set_parent_expr(expr->conditional, expr);
			return strip_expr_helper(expr->conditional, set_parent, cast, nest);
		}
		if (known_condition_false(expr->conditional)) {
			if (set_parent)
				expr_set_parent_expr(expr->cond_false, expr);
			return strip_expr_helper(expr->cond_false, set_parent, cast, nest);
		}
		return expr;
	case EXPR_CALL:
		if (sym_name_is("__builtin_expect", expr->fn) ||
		    sym_name_is("__builtin_bswap16", expr->fn) ||
		    sym_name_is("__builtin_bswap32", expr->fn) ||
		    sym_name_is("__builtin_bswap64", expr->fn)) {
			expr = get_argument_from_call_expr(expr->args, 0);
			return strip_expr_helper(expr, set_parent, cast, nest);
		}
		if (sym_name_is("__builtin_choose_expr", expr->fn))
			return strip__builtin_choose_expr(expr);
		return expr;
	case EXPR_BINOP:
		return strip_plus_zero(expr, set_parent, cast, nest);
	case EXPR_GENERIC:
		return strip_Generic(expr);
	}
	return expr;
}

struct strip_cache_res {
	struct expression *expr;
	struct expression *res;
};
#define STRIP_CACHE_SIZE 4
static struct strip_cache_res strip_cache[STRIP_CACHE_SIZE];
static struct strip_cache_res strip_no_cast_cache[STRIP_CACHE_SIZE];
static struct strip_cache_res strip_set_parent_cache[STRIP_CACHE_SIZE];

static struct expression *call_strip_helper(struct expression *expr,
					    struct strip_cache_res *cache,
					    int *idx,
					    bool set_parent,
					    bool cast)
{
	struct expression *ret;
	int nest = 0;
	int i;

	if (!expr)
		return NULL;

	for (i = 0; i < ARRAY_SIZE(strip_cache); i++) {
		if (cache[i].expr == expr)
			return cache[i].res;
	}

	ret = strip_expr_helper(expr, set_parent, cast, &nest);
	*idx = (*idx + 1) % STRIP_CACHE_SIZE;
	cache[*idx].expr = expr;
	cache[*idx].res = ret;
	return ret;
}

struct expression *strip_expr(struct expression *expr)
{
	static int cache_idx;

	return call_strip_helper(expr, strip_cache, &cache_idx, false, true);
}

struct expression *strip_no_cast(struct expression *expr)
{
	static int cache_idx;

	return call_strip_helper(expr, strip_no_cast_cache, &cache_idx, false, false);
}

struct expression *strip_expr_set_parent(struct expression *expr)
{
	static int cache_idx;

	return call_strip_helper(expr, strip_set_parent_cache, &cache_idx, true, true);
}

void clear_strip_cache(void)
{
	memset(strip_cache, 0, sizeof(strip_cache));
	memset(strip_no_cast_cache, 0, sizeof(strip_no_cast_cache));
	memset(strip_set_parent_cache, 0, sizeof(strip_set_parent_cache));
}

int is_error_return(struct expression *expr)
{
	struct symbol *cur_func = cur_func_sym;
	struct range_list *rl;
	sval_t sval;

	if (!expr)
		return 0;
	if (cur_func->type != SYM_NODE)
		return 0;
	cur_func = get_base_type(cur_func);
	if (cur_func->type != SYM_FN)
		return 0;
	cur_func = get_base_type(cur_func);
	if (cur_func == &void_ctype)
		return 0;
	if (option_project == PROJ_KERNEL &&
	    get_implied_rl(expr, &rl) &&
	    rl_type(rl) == &int_ctype &&
	    sval_is_negative(rl_min(rl)) &&
	    rl_max(rl).value == -1)
		return 1;
	if (!get_implied_value(expr, &sval))
		return 0;
	if (sval.value < 0)
		return 1;
	if (cur_func->type == SYM_PTR && sval.value == 0)
		return 1;
	return 0;
}

int getting_address(struct expression *expr)
{
	int deref_count = 0;

	while ((expr = expr_get_parent_expr(expr))) {
		if (expr->type == EXPR_PREOP && expr->op == '*') {
			/* &foo->bar->baz dereferences "foo->bar" */
			if (deref_count == 0)
				deref_count++;
			return false;
		}
		if (expr->type == EXPR_PREOP && expr->op == '&')
			return true;
	}
	return false;
}

int get_struct_and_member(struct expression *expr, const char **type, const char **member)
{
	struct symbol *sym;

	expr = strip_expr(expr);
	if (expr->type != EXPR_DEREF)
		return 0;
	if (!expr->member)
		return 0;

	sym = get_type(expr->deref);
	if (!sym)
		return 0;
	if (sym->type == SYM_UNION)
		return 0;
	if (!sym->ident)
		return 0;

	*type = sym->ident->name;
	*member = expr->member->name;
	return 1;
}

char *get_member_name(struct expression *expr)
{
	char buf[256];
	struct symbol *sym;

	expr = strip_expr(expr);
	if (!expr || expr->type != EXPR_DEREF)
		return NULL;
	if (!expr->member)
		return NULL;

	sym = get_type(expr->deref);
	if (!sym)
		return NULL;
	if (sym->type == SYM_PTR)
		sym = get_real_base_type(sym);
	if (sym->type == SYM_UNION) {
		snprintf(buf, sizeof(buf), "(union %s)->%s",
			 sym->ident ? sym->ident->name : "anonymous",
			 expr->member->name);
		return alloc_string(buf);
	}
	if (!sym->ident) {
		struct expression *deref;
		char *full, *outer;
		int len;

		/*
		 * If we're in an anonymous struct then maybe we can find an
		 * outer struct name to use as a name.  This code should be
		 * recursive and cleaner.  I am not very proud of it.
		 *
		 */

		deref = strip_parens(expr->deref);
		if (deref->type != EXPR_DEREF || !deref->member)
			return NULL;
		sym = get_type(deref->deref);
		if (!sym || sym->type != SYM_STRUCT || !sym->ident)
			return NULL;

		full = expr_to_str(expr);
		if (!full)
			return NULL;
		deref = deref->deref;
		if (deref->type == EXPR_PREOP && deref->op == '*')
			deref = deref->unop;
		outer = expr_to_str(deref);
		if (!outer) {
			free_string(full);
			return NULL;
		}
		len = strlen(outer);
		if (strncmp(outer, full, len) != 0) {
			free_string(full);
			free_string(outer);
			return NULL;
		}
		if (full[len] == '-' && full[len + 1] == '>')
			len += 2;
		if (full[len] == '.')
			len++;
		snprintf(buf, sizeof(buf), "(struct %s)->%s", sym->ident->name, full + len);
		free_string(outer);
		free_string(full);

		return alloc_string(buf);
	}
	snprintf(buf, sizeof(buf), "(struct %s)->%s", sym->ident->name, expr->member->name);
	return alloc_string(buf);
}

int cmp_pos(struct position pos1, struct position pos2)
{
	/* the stream position is ... */
	if (pos1.stream > pos2.stream)
		return -1;
	if (pos1.stream < pos2.stream)
		return 1;

	if (pos1.line < pos2.line)
		return -1;
	if (pos1.line > pos2.line)
		return 1;

	if (pos1.pos < pos2.pos)
		return -1;
	if (pos1.pos > pos2.pos)
		return 1;

	return 0;
}

int positions_eq(struct position pos1, struct position pos2)
{
	if (pos1.line != pos2.line)
		return 0;
	if (pos1.pos != pos2.pos)
		return 0;
	if (pos1.stream != pos2.stream)
		return 0;
	return 1;
}

struct statement *get_current_statement(void)
{
	struct statement *prev, *tmp;

	prev = last_ptr_list((struct ptr_list *)big_statement_stack);

	if (!prev || !get_macro_name(prev->pos))
		return prev;

	FOR_EACH_PTR_REVERSE(big_statement_stack, tmp) {
		if (positions_eq(tmp->pos, prev->pos))
			continue;
		if (prev->pos.line > tmp->pos.line)
			return prev;
		return tmp;
	} END_FOR_EACH_PTR_REVERSE(tmp);
	return prev;
}

struct statement *get_prev_statement(void)
{
	struct statement *tmp;
	int i;

	i = 0;
	FOR_EACH_PTR_REVERSE(big_statement_stack, tmp) {
		if (i++ == 1)
			return tmp;
	} END_FOR_EACH_PTR_REVERSE(tmp);
	return NULL;
}

struct expression *get_last_expr_from_expression_stmt(struct expression *expr)
{
	struct statement *stmt;
	struct statement *last_stmt;

	while (expr->type == EXPR_PREOP && expr->op == '(')
		expr = expr->unop;
	if (expr->type != EXPR_STATEMENT)
		return NULL;
	stmt = expr->statement;
	if (!stmt)
		return NULL;
	if (stmt->type == STMT_COMPOUND) {
		last_stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
		if (!last_stmt)
			return NULL;
		if (last_stmt->type == STMT_LABEL)
			last_stmt = last_stmt->label_statement;
		if (last_stmt->type != STMT_EXPRESSION)
			return NULL;
		return last_stmt->expression;
	}
	if (stmt->type == STMT_EXPRESSION)
		return stmt->expression;
	return NULL;
}

int ms_since(struct timeval *start)
{
	struct timeval end;
	double diff;

	gettimeofday(&end, NULL);
	diff = (end.tv_sec - start->tv_sec) * 1000.0;
	diff += (end.tv_usec - start->tv_usec) / 1000.0;
	return (int)diff;
}

int parent_is_gone_var_sym(const char *name, struct symbol *sym)
{
	if (!name || !sym)
		return 0;

	if (parent_is_err_or_null_var_sym(name, sym) ||
	    parent_is_free_var_sym(name, sym))
		return 1;
	return 0;
}

int parent_is_gone(struct expression *expr)
{
	struct symbol *sym;
	char *var;
	int ret = 0;

	expr = strip_expr(expr);
	var = expr_to_var_sym(expr, &sym);
	if (!var || !sym)
		goto free;
	ret = parent_is_gone_var_sym(var, sym);
free:
	free_string(var);
	return ret;
}

int invert_op(int op)
{
	switch (op) {
	case '*':
		return '/';
	case '/':
		return '*';
	case '+':
		return '-';
	case '-':
		return '+';
	case SPECIAL_LEFTSHIFT:
		return SPECIAL_RIGHTSHIFT;
	case SPECIAL_RIGHTSHIFT:
		return SPECIAL_LEFTSHIFT;
	}
	return 0;
}

int op_remove_assign(int op)
{
	switch (op) {
	case SPECIAL_ADD_ASSIGN:
		return '+';
	case SPECIAL_SUB_ASSIGN:
		return '-';
	case SPECIAL_MUL_ASSIGN:
		return '*';
	case SPECIAL_DIV_ASSIGN:
		return '/';
	case SPECIAL_MOD_ASSIGN:
		return '%';
	case SPECIAL_AND_ASSIGN:
		return '&';
	case SPECIAL_OR_ASSIGN:
		return '|';
	case SPECIAL_XOR_ASSIGN:
		return '^';
	case SPECIAL_SHL_ASSIGN:
		return SPECIAL_LEFTSHIFT;
	case SPECIAL_SHR_ASSIGN:
		return SPECIAL_RIGHTSHIFT;
	default:
		return op;
	}
}

int expr_equiv(struct expression *one, struct expression *two)
{
	struct symbol *one_sym = NULL;
	struct symbol *two_sym = NULL;
	char *one_name = NULL;
	char *two_name = NULL;
	int ret = 0;

	if (!one || !two)
		return 0;
	if (one == two)
		return 1;
	if (one->type != two->type)
		return 0;
	if (is_fake_call(one) || is_fake_call(two))
		return 0;

	one_name = expr_to_str_sym(one, &one_sym);
	if (!one_name)
		goto free;
	two_name = expr_to_str_sym(two, &two_sym);
	if (!two_name)
		goto free;
	if (one_sym != two_sym)
		goto free;
	/*
	 * This is a terrible hack because expr_to_str() sometimes gives up in
	 * the middle and just returns what it has.  If you see a () you know
	 * the string is bogus.
	 */
	if (strstr(one_name, "()"))
		goto free;
	if (strcmp(one_name, two_name) == 0)
		ret = 1;
free:
	free_string(one_name);
	free_string(two_name);
	return ret;
}

void push_int(struct int_stack **stack, int num)
{
	int *munged;

	/*
	 * Just put the int on directly instead of a pointer to the int.
	 * Shift it to the left because Sparse uses the last two bits.
	 * This is sort of a dirty hack, yes.
	 */

	munged = INT_PTR(num << 2);

	add_ptr_list(stack, munged);
}

int pop_int(struct int_stack **stack)
{
	int *num;

	num = last_ptr_list((struct ptr_list *)*stack);
	delete_ptr_list_last((struct ptr_list **)stack);

	return PTR_INT(num) >> 2;
}

bool token_to_ul(struct token *token, unsigned long *val)
{
	int cnt = 0;

	/* this function only works for very specific simple defines */
	while (cnt++ < 20 && token) {
		switch (token_type(token)) {
		case TOKEN_IDENT:
			if (macro_to_ul(show_ident(token->ident), val))
				return true;
			break;
		case TOKEN_NUMBER:
			*val = strtoul(token->number, NULL, 0);
			return true;
		case TOKEN_SPECIAL:
			if (token->special == '(' || token->special == ')')
				break;
			return false;
		default:
			return false;
		}
		token = token->next;
	}
	return false;
}

bool macro_to_ul(const char *macro, unsigned long *val)
{
	struct symbol *macro_sym;

	if (!macro)
		return false;

	macro_sym = lookup_macro_symbol(macro);
	if (!macro_sym || !macro_sym->expansion)
		return false;
	return token_to_ul(macro_sym->expansion, val);
}

int success_fail_return(struct range_list *rl)
{
	char *str;
	sval_t sval;

	if (!rl)
		return RET_SUCCESS;

	/* NFSv3 uses negative error codes such as -EIOCBQUEUED for success */
	if (rl_to_sval(rl, &sval) && sval.value == -529)
		return RET_SUCCESS;

	// Negatives are a failure
	if (sval_is_negative(rl_max(rl)))
		return RET_FAIL;

	// NULL and error pointers are a failure
	if (type_is_ptr(rl_type(rl)) && is_err_or_null(rl))
		return RET_FAIL;

	if (rl_to_sval(rl, &sval)) {
		if (sval.value == 0) {
			// Zero is normally success but false is a failure
			if (type_bits(sval.type) == 1)
				return RET_FAIL;
			else
				return RET_SUCCESS;
		}
		// true is success
		if (sval.value == 1 && type_bits(sval.type) == 1)
			return RET_SUCCESS;
	}

	str = show_rl(rl);
	if (strcmp(str, "s32min-(-1),1-s32max") == 0)
		return RET_FAIL;

	if (strcmp(str, "0-s32max") == 0)
		return RET_SUCCESS;

	return RET_UNKNOWN;
}

bool has_cleanup(struct expression *expr)
{
	expr = strip_expr(expr);
	if (!expr || expr->type != EXPR_SYMBOL)
		return false;

	return !!expr->symbol->cleanup;
}
