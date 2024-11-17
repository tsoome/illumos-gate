/*
 * Copyright (C) 2009 Dan Carpenter.
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
 * This is not a check.  It just saves an struct expression pointer
 * whenever something is assigned.  This can be used later on by other scripts.
 */

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

int check_assigned_expr_id;
static int my_id;
static int link_id;

static struct expression *skip_mod;

static void undef(struct sm_state *sm, struct expression *mod_expr)
{
	if (mod_expr == skip_mod)
		return;
	set_state(my_id, sm->name, sm->sym, &undefined);
}

struct expression *get_assigned_expr(struct expression *expr)
{
	struct smatch_state *state;

	state = get_state_expr(my_id, expr);
	if (!state)
		return NULL;
	return (struct expression *)state->data;
}

struct sm_state *get_assigned_sm(struct expression *expr)
{
	return get_sm_state_expr(my_id, expr);
}

struct expression *get_assigned_expr_recurse(struct expression *expr)
{
	struct expression *ret;
	int cnt = 0;

	ret = NULL;
	while ((expr = get_assigned_expr(expr))) {
		ret = expr;
		if (cnt++ > 4)
			break;
	}

	return ret;
}

struct expression *get_assigned_expr_name_sym(const char *name, struct symbol *sym)
{
	struct smatch_state *state;

	state = __get_state(my_id, name, sym);
	if (!state)
		return NULL;
	return (struct expression *)state->data;
}

struct expression *get_assigned_expr_name_sym_recurse(const char *name, struct symbol *sym)
{
	struct expression *expr, *recurse;

	expr = get_assigned_expr_name_sym(name, sym);
	if (!expr)
		return NULL;
	recurse = get_assigned_expr_recurse(expr);
	if (recurse)
		return recurse;
	return expr;
}

static void match_assignment(struct expression *expr)
{
	static struct expression *ignored_expr, *right;
	struct symbol *left_sym, *right_sym;
	struct smatch_state *state;
	char *left_name = NULL;
	char *right_name = NULL;

	if (!cur_func_sym)
		return;

	if (__in_buf_clear)
		return;

	if (expr->op != '=')
		return;
	if (is_fake_call(expr->right))
		return;
	if (is_fake_var_assign(expr))
		return;
	if (__in_fake_struct_assign) {
		struct range_list *rl;

		if (!get_implied_rl(expr->right, &rl))
			return;
		if (is_whole_rl(rl))
			return;
	}

	if (expr->left == ignored_expr)
		return;
	ignored_expr = NULL;
	if (__in_fake_parameter_assign)
		ignored_expr = expr->left;

	left_name = expr_to_var_sym(expr->left, &left_sym);
	if (!left_name || !left_sym)
		goto free;

	right = expr->right;
	if (right->type == EXPR_ASSIGNMENT && right->op == '=')
		right = right->left;

	right = strip__builtin_choose_expr(right);
	right = strip_Generic(right);

	state = alloc_state_expr(strip_expr(right));
	if (!state)
		goto free;

	skip_mod = expr;
	if (get_unfaked_call())
		skip_mod = get_unfaked_call();
	set_state(my_id, left_name, left_sym, state);

	right_name = expr_to_var_sym(right, &right_sym);
	if (!right_name || !right_sym)
		goto free;

	store_link(link_id, right_name, right_sym, left_name, left_sym);

free:
	free_string(left_name);
	free_string(right_name);
}

static void record_param_assignment(struct expression *expr, int param, char *key, char *value)
{
	struct expression *arg, *right;
	struct symbol *sym;
	char *name;
	char *p;
	int right_param;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (!expr || expr->type != EXPR_CALL)
		return;

	p = strstr(value, "[$");
	if (!p)
		return;

	p += 2;
	right_param = strtol(p, &p, 10);
	if (*p != ']')
		return;

	arg = get_argument_from_call_expr(expr->args, param);
	right = get_argument_from_call_expr(expr->args, right_param);
	if (!right || !arg)
		return;
	name = get_variable_from_key(arg, key, &sym);
	if (!name || !sym)
		goto free;

	skip_mod = expr;
	set_state(my_id, name, sym, alloc_state_expr(right));
free:
	free_string(name);
}

void register_assigned_expr(int id)
{
	my_id = check_assigned_expr_id = id;
	add_function_data((unsigned long *)&skip_mod);
	set_dynamic_states(check_assigned_expr_id);
	add_hook(&match_assignment, ASSIGNMENT_HOOK_AFTER);
	add_modification_hook_late(my_id, &undef);
	select_return_states_hook(PARAM_SET, &record_param_assignment);
}

void register_assigned_expr_links(int id)
{
	link_id = id;
	set_dynamic_states(link_id);
	db_ignore_states(link_id);
	set_up_link_functions(my_id, link_id);
}

