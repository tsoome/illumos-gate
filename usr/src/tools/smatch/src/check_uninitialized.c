/*
 * Copyright (C) 2014 Oracle.
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

#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

static int my_id;

STATE(uninitialized);
STATE(initialized);

static bool uncertain_code_path(void)
{
	if (implications_off || parse_error)
		return true;
	if (is_impossible_path())
		return true;

	return false;
}

static void pre_merge_hook(struct sm_state *cur, struct sm_state *other)
{
	if (is_impossible_path())
		set_state(my_id, cur->name, cur->sym, &initialized);
}

static void mark_members_uninitialized(struct symbol *sym)
{
	struct symbol *struct_type, *tmp, *base_type;
	char buf[256];

	struct_type = get_real_base_type(sym);
	FOR_EACH_PTR(struct_type->symbol_list, tmp) {
		if (!tmp->ident)
			continue;
		base_type = get_real_base_type(tmp);
		if (!base_type ||
		    base_type->type == SYM_STRUCT ||
		    base_type->type == SYM_ARRAY ||
		    base_type->type == SYM_UNION)
			continue;
		snprintf(buf, sizeof(buf), "%s.%s", sym->ident->name, tmp->ident->name);
		set_state(my_id, buf, sym, &uninitialized);
	} END_FOR_EACH_PTR(tmp);
}

static void match_declarations(struct symbol *sym)
{
	struct symbol *type;

	if (!cur_func_sym)
		return;

	if (sym->initializer)
		return;

	type = get_real_base_type(sym);
	/* Smatch is crap at tracking arrays */
	if (type->type == SYM_ARRAY)
		return;
	if (type->type == SYM_UNION)
		return;
	if (sym->ctype.modifiers & MOD_STATIC)
		return;

	if (!sym->ident)
		return;

	if (type->type == SYM_STRUCT) {
		mark_members_uninitialized(sym);
		return;
	}

	set_state(my_id, sym->ident->name, sym, &uninitialized);
}

static int is_initialized(struct expression *expr)
{
	struct sm_state *sm;

	expr = strip_expr(expr);
	if (expr->type != EXPR_SYMBOL)
		return 1;
	sm = get_sm_state_expr(my_id, expr);
	if (!sm)
		return 1;
	if (!slist_has_state(sm->possible, &uninitialized))
		return 1;
	return 0;
}

static void warn_about_special_assign(struct expression *expr)
{
	char *name;

	if (!expr || expr->type != EXPR_ASSIGNMENT || expr->op == '=')
		return;

	if (uncertain_code_path())
		return;

	if (is_initialized(expr->left))
		return;

	name = expr_to_str(expr->left);
	sm_warning("uninitialized special assign '%s'", name);
	free_string(name);
}

static void extra_mod_hook(const char *name, struct symbol *sym, struct expression *expr, struct smatch_state *state)
{
	struct expression *parent = expr_get_parent_expr(expr);

	if (!cur_func_sym)
		return;

	if (__in_fake_struct_assign && parent &&
	    parent->type == EXPR_ASSIGNMENT &&
	    is_fake_call(parent->right))
		return;
	if (expr && expr->smatch_flags & Fake)
		return;
	if (!sym || !sym->ident)
		return;
	if (strcmp(name, sym->ident->name) != 0)
		return;
	warn_about_special_assign(expr);
	set_state(my_id, name, sym, &initialized);
}

static void match_assign(struct expression *expr)
{
	struct expression *right;

	if (is_fake_var_assign(expr))
		return;

	right = strip_expr(expr->right);
	if (right->type == EXPR_PREOP && right->op == '&')
		set_state_expr(my_id, right->unop, &initialized);
}

static void match_negative_comparison(struct expression *expr)
{
	struct expression *success;
	struct sm_state *sm;
	sval_t max;

	/*
	 * In the kernel, people don't use "if (ret) {" and "if (ret < 0) {"
	 * consistently.  Ideally Smatch would know the return but often it
	 * doesn't.
	 *
	 */

	if (option_project != PROJ_KERNEL)
		return;

	if (expr->type != EXPR_COMPARE || expr->op != '<')
		return;
	if (!expr_is_zero(expr->right))
		return;
	if (get_implied_max(expr->left, &max) && max.value == 0)
		return;

	success = compare_expression(expr->left, SPECIAL_EQUAL, expr->right);
	if (!assume(success))
		return;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state == &initialized)
			set_true_false_states(my_id, sm->name, sm->sym, NULL, &initialized);
	} END_FOR_EACH_SM(sm);

	end_assume();
}

static struct statement *clear_states;
static void match_enum_switch(struct statement *stmt)
{
	struct expression *expr;
	struct symbol *type;

	if (stmt->type != STMT_COMPOUND)
		return;
	stmt = stmt_get_parent_stmt(stmt);
	if (!stmt || stmt->type != STMT_SWITCH)
		return;

	/* This ended up way uglier than I imagined */
	if (__has_default_case())
		return;

	expr = strip_expr(stmt->switch_expression);
	type = expr->ctype;
	if (!type || type->type != SYM_ENUM)
		return;

	clear_states = stmt;
}

static void match_enum_switch_after(struct statement *stmt)
{
	struct sm_state *sm;

	if (clear_states != stmt)
		return;

	FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
		if (sm->state == &merged)
			set_state(my_id, sm->name, sm->sym, &initialized);
	} END_FOR_EACH_SM(sm);
}

static void match_dereferences(struct expression *expr)
{
	char *name;

	if (uncertain_code_path())
		return;

	if (expr->type != EXPR_PREOP)
		return;
	if (is_initialized(expr->unop))
		return;

	name = expr_to_str(expr->unop);
	sm_error("potentially dereferencing uninitialized '%s'.", name);
	free_string(name);

	set_state_expr(my_id, expr->unop, &initialized);
}

static void match_condition(struct expression *expr)
{
	char *name;

	if (uncertain_code_path())
		return;

	if (is_initialized(expr))
		return;

	name = expr_to_str(expr);
	sm_error("potentially using uninitialized '%s'.", name);
	free_string(name);

	set_state_expr(my_id, expr, &initialized);
}

static void match_function_pointer_call(struct expression *expr)
{
	struct expression *parent, *arg, *tmp;

	/*
	 * If you call a function pointer foo->read(&val) without checking
	 * for errors then you knew what you were doing when you wrote that
	 * code.  I'm not the police to try to prevent intentional bugs.
	 *
	 */
	parent = expr_get_parent_expr(expr);
	if (parent)
		return;
	if (expr->fn->type == EXPR_SYMBOL)
		return;

	FOR_EACH_PTR(expr->args, arg) {
		tmp = strip_expr(arg);
		if (tmp->type != EXPR_PREOP || tmp->op != '&')
			continue;
		set_state_expr(my_id, tmp->unop, &initialized);
	} END_FOR_EACH_PTR(arg);
}

static void match_call(struct expression *expr)
{
	struct expression *arg;
	char *name;

	if (uncertain_code_path())
		return;

	FOR_EACH_PTR(expr->args, arg) {
		if (is_initialized(arg))
			continue;

		name = expr_to_str(arg);
		sm_warning("passing uninitialized '%s'", name);
		free_string(name);

		set_state_expr(my_id, arg, &initialized);
	} END_FOR_EACH_PTR(arg);
}

static int param_used_callback(void *found, int argc, char **argv, char **azColName)
{
	*(int *)found = 1;
	return 0;
}

static int member_is_used(struct expression *call, int param, char *printed_name)
{
	int found;

	/* for function pointers assume everything is used */
	if (call->fn->type != EXPR_SYMBOL)
		return 0;

	found = 0;
	run_sql(&param_used_callback, &found,
		"select * from return_implies where %s and type = %d and parameter = %d and key = '%s';",
		get_static_filter(call->fn->symbol), PARAM_USED, param, printed_name);
	return found;
}

static void match_call_struct_members(struct expression *expr)
{
	struct symbol *type, *sym;
	struct expression *arg;
	struct sm_state *sm;
	char *arg_name;
	char buf[256];
	int param;

	return;

	if (parse_error)
		return;

	param = -1;
	FOR_EACH_PTR(expr->args, arg) {
		param++;
		if (arg->type != EXPR_PREOP || arg->op != '&')
			continue;
		type = get_type(arg->unop);
		if (!type || type->type != SYM_STRUCT)
			continue;
		arg_name = expr_to_var_sym(arg->unop, &sym);
		if (!arg_name || !sym)
			goto free;
		FOR_EACH_MY_SM(my_id, __get_cur_stree(), sm) {
			if (sm->sym != sym)
				continue;
			if (!slist_has_state(sm->possible, &uninitialized))
				continue;
			snprintf(buf, sizeof(buf), "$->%s", sm->name + strlen(arg_name) + 1);
			if (!member_is_used(expr, param, buf))
				goto free;
			sm_warning("struct member %s is uninitialized", sm->name);
		} END_FOR_EACH_SM(sm);

free:
		free_string(arg_name);
	} END_FOR_EACH_PTR(arg);
}

static int is_being_modified(struct expression *expr)
{
	struct expression *parent;
	struct statement *stmt;

	parent = expr_get_parent_expr(expr);
	if (!parent)
		return 0;
	while (parent->type == EXPR_PREOP && parent->op == '(') {
		parent = expr_get_parent_expr(parent);
		if (!parent)
			return 0;
	}
	if (parent->type == EXPR_PREOP && parent->op == '&')
		return 1;
	if (parent->type == EXPR_ASSIGNMENT && expr_equiv(parent->left, expr))
		return 1;

	stmt = last_ptr_list((struct ptr_list *)big_statement_stack);
	if (stmt && stmt->type == STMT_ASM)
		return 1;

	return 0;
}

static bool is_just_silencing_used_variable(struct expression *expr)
{
	struct symbol *type;

	while ((expr = expr_get_parent_expr(expr))) {
		if (expr->type == EXPR_PREOP && expr->op == '(')
			continue;
		if (expr->type == EXPR_CAST) {
			type = expr->cast_type;

			if (!type)
				return false;
			if (type->type == SYM_NODE)
				type = get_real_base_type(type);
			if (type == &void_ctype)
				return true;
		}
	}

	return false;
}

static void match_symbol(struct expression *expr)
{
	char *name;

	if (uncertain_code_path())
		return;

	if (is_initialized(expr))
		return;

	if (is_being_modified(expr))
		return;

	if (is_just_silencing_used_variable(expr))
		return;

	name = expr_to_str(expr);
	sm_error("uninitialized symbol '%s'.", name);
	free_string(name);

	set_state_expr(my_id, expr, &initialized);
}

static void match_untracked(struct expression *call, int param)
{
	struct expression *arg;

	arg = get_argument_from_call_expr(call->args, param);
	arg = strip_expr(arg);
	if (!arg || arg->type != EXPR_PREOP || arg->op != '&')
		return;
	arg = strip_expr(arg->unop);
	set_state_expr(my_id, arg, &initialized);
}

static void match_ignore_param(const char *fn, struct expression *expr, void *_arg_nr)
{
	int arg_nr = PTR_INT(_arg_nr);
	struct expression *arg;

	arg = get_argument_from_call_expr(expr->args, arg_nr);
	arg = strip_expr(arg);
	if (!arg)
		return;
	if (arg->type != EXPR_PREOP || arg->op != '&')
		return;
	arg = strip_expr(arg->unop);
	set_state_expr(my_id, arg, &initialized);
}

static void register_ignored_params_from_file(void)
{
	char name[256];
	struct token *token;
	const char *func;
	char prev_func[256];
	int param;

	memset(prev_func, 0, sizeof(prev_func));
	snprintf(name, 256, "%s.ignore_uninitialized_param", option_project_str);
	name[255] = '\0';
	token = get_tokens_file(name);
	if (!token)
		return;
	if (token_type(token) != TOKEN_STREAMBEGIN)
		return;
	token = token->next;
	while (token_type(token) != TOKEN_STREAMEND) {
		if (token_type(token) != TOKEN_IDENT)
			return;
		func = show_ident(token->ident);

		token = token->next;
		if (token_type(token) != TOKEN_NUMBER)
			return;
		param = atoi(token->number);

		add_function_hook(func, &match_ignore_param, INT_PTR(param));

		token = token->next;
	}
	clear_token_alloc();
}

void check_uninitialized(int id)
{
	my_id = id;

	add_hook(&match_declarations, DECLARATION_HOOK);
	add_extra_mod_hook(&extra_mod_hook);
	add_hook(&match_assign, ASSIGNMENT_HOOK);
	add_hook(&match_negative_comparison, CONDITION_HOOK);
	add_hook(&match_enum_switch, STMT_HOOK_AFTER);
	add_hook(&match_enum_switch_after, STMT_HOOK_AFTER);
	add_untracked_param_hook(&match_untracked);
	add_pre_merge_hook(my_id, &pre_merge_hook);

	add_hook(&match_dereferences, DEREF_HOOK);
	add_hook(&match_condition, CONDITION_HOOK);
	add_hook(&match_call, FUNCTION_CALL_HOOK);
	add_hook(&match_function_pointer_call, FUNCTION_CALL_HOOK);
	add_hook(&match_call_struct_members, FUNCTION_CALL_HOOK);
	add_hook(&match_symbol, SYM_HOOK);

	register_ignored_params_from_file();
}
