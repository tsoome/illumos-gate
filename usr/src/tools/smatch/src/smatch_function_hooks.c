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
 * There are several types of function hooks.
 *
 * The param_key hooks are probably the right things to use going forward.
 * They give you a name/sym pair so it means less code in the checks.
 *
 * The add_function_hook() functions are trigger for every call.  The
 * "return_implies" are triggered for specific return ranges.  The "exact"
 * variants will be triggered if it's *definitely* in the range where the
 * others will be triggered if it's *possibly* in the range.  The "late"
 * variants will be triggered after the others have run.
 *
 * There are a few miscellaneous things like add_function_assign_hook() and
 * add_macro_assign_hook() which are only triggered for assignments.  The
 * add_implied_return_hook() let's you manually adjust the return range.
 *
 * Every call:
 *     add_function_param_key_hook_early()
 *     add_function_param_key_hook()
 *     add_function_param_key_hook_late()
 *     add_param_key_expr_hook()
 *     add_function_hook_early()
 *     add_function_hook()
 *
 * Just for some return ranges:
 *     return_implies_param_key()
 *     return_implies_param_key_expr()
 *     return_implies_param_key_exact()
 *     return_implies_state()
 *     select_return_param_key()  (It's weird that this is not in smatch_db.c)
 *
 * For Assignments:
 *     add_function_assign_hook()
 *
 * For Macro Assignments:
 *     add_macro_assign_hook()
 *
 * Manipulate the return range.
 *     add_implied_return_hook()
 */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"
#include "smatch_function_hashtable.h"
#include "smatch_expression_stacks.h"

struct fcall_back {
	int type;
	struct data_range *range;
	union {
		func_hook *call_back;
		implication_hook *ranged;
		implied_return_hook *implied_return;
	} u;
	void *info;
};

ALLOCATOR(fcall_back, "call backs");
DECLARE_PTR_LIST(call_back_list, struct fcall_back);

DEFINE_FUNCTION_HASHTABLE_STATIC(callback, struct fcall_back, struct call_back_list);
static struct hashtable *func_hash;

int __in_fake_parameter_assign;

enum fn_hook_type {
	REGULAR_CALL_EARLY,
	REGULAR_CALL,
	REGULAR_CALL_LATE,
	RANGED_CALL,
	RANGED_EXACT,
	ASSIGN_CALL,
	IMPLIED_RETURN,
	MACRO_ASSIGN,
	MACRO_ASSIGN_EXTRA,
};

struct param_key_data {
	param_key_hook *call_back;
	expr_func *expr_fn;
	int param;
	const char *key;
	void *info;
};

struct param_data {
	expr_func *call_back;
	int param;
	void *info;
};

struct return_implies_callback {
	int type;
	bool param_key;
	union {
		return_implies_hook *callback;
		param_key_hook *pk_callback;
	};
};
ALLOCATOR(return_implies_callback, "return_implies callbacks");
DECLARE_PTR_LIST(db_implies_list, struct return_implies_callback);
static struct db_implies_list *db_return_states_list;

static struct void_fn_list *return_states_before;
static struct void_fn_list *return_states_after;
static struct string_hook_list *return_string_hooks;

struct db_callback_info {
	int true_side;
	int comparison;
	struct expression *expr;
	struct range_list *rl;
	int left;
	struct stree *stree;
	struct stree *implied;
	struct db_implies_list *callbacks;
	struct db_implies_list *called;
	int prev_return_id;
	int cull;
	int has_states;
	bool states_merged;
	char *ret_str;
	struct smatch_state *ret_state;
	struct expression *var_expr;
	struct expression_list *fake_param_assign_stack;
	int handled;
};

static struct expression_list *fake_calls;

void add_fake_call_after_return(struct expression *call)
{
	add_ptr_list(&fake_calls, call);
}

static void parse_fake_calls(void)
{
	struct expression_list *list;
	struct expression *call;

	list = fake_calls;
	fake_calls = NULL;

	FOR_EACH_PTR(list, call) {
		__split_expr(call);
	} END_FOR_EACH_PTR(call);

	__free_ptr_list((struct ptr_list **)&list);
}

static struct fcall_back *alloc_fcall_back(int type, void *call_back,
					   void *info)
{
	struct fcall_back *cb;

	cb = __alloc_fcall_back(0);
	cb->type = type;
	cb->u.call_back = call_back;
	cb->info = info;
	return cb;
}

static const char *get_fn_name(struct expression *fn)
{
	fn = strip_expr(fn);
	if (!fn)
		return NULL;
	if (fn->type == EXPR_SYMBOL && fn->symbol)
		return fn->symbol->ident->name;
	return get_member_name(fn);
}

static struct call_back_list *get_call_backs(const char *fn_name)
{
	if (!fn_name)
		return NULL;
	return search_callback(func_hash, (char *)fn_name);
}

void add_function_hook(const char *look_for, func_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(REGULAR_CALL, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_function_hook_early(const char *look_for, func_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(REGULAR_CALL_EARLY, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_function_hook_late(const char *look_for, func_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(REGULAR_CALL_LATE, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_function_assign_hook(const char *look_for, func_hook *call_back,
			      void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(ASSIGN_CALL, call_back, info);
	add_callback(func_hash, look_for, cb);
}

static void register_funcs_from_file_helper(const char *file,
					    func_hook *call_back, void *info,
					    bool assign)
{
	struct token *token;
	const char *func;
	char name[64];

	snprintf(name, sizeof(name), "%s.%s", option_project_str, file);
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
		if (assign)
			add_function_assign_hook(func, call_back, info);
		else
			add_function_hook(func, call_back, info);
		token = token->next;
	}
	clear_token_alloc();
}

void register_func_hooks_from_file(const char *file,
				   func_hook *call_back, void *info)
{
	register_funcs_from_file_helper(file, call_back, info, false);
}

void register_assign_hooks_from_file(const char *file,
				     func_hook *call_back, void *info)
{
	register_funcs_from_file_helper(file, call_back, info, true);
}

void add_implied_return_hook(const char *look_for,
			     implied_return_hook *call_back,
			     void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(IMPLIED_RETURN, call_back, info);
	add_callback(func_hash, look_for, cb);
}

static void db_helper(struct expression *expr, param_key_hook *call_back, int param, const char *key, void *info)
{
	char *name;
	struct symbol *sym;

	if (param == -2) {
		call_back(expr, key, NULL, info);
		return;
	}

	name = get_name_sym_from_param_key(expr, param, key, &sym);
	if (!name || !sym)
		goto free;

	call_back(expr, name, sym, info);
free:
	free_string(name);
}

static struct expression *get_parent_assignment(struct expression *expr)
{
	struct expression *parent;
	int cnt = 0;

	if (expr->type == EXPR_ASSIGNMENT)
		return NULL;

	parent = expr_get_fake_parent_expr(expr);
	if (parent && parent->type == EXPR_ASSIGNMENT)
		return parent;

	parent = expr;
	while (true) {
		parent = expr_get_parent_expr(parent);
		if (!parent || ++cnt >= 5)
			break;
		if (parent->type == EXPR_CAST)
			continue;
		if (parent->type == EXPR_PREOP && parent->op == '(')
			continue;
		break;
	}

	if (parent && parent->type == EXPR_ASSIGNMENT)
		return parent;
	return NULL;
}

static void param_key_function(const char *fn, struct expression *expr, void *data)
{
	struct param_key_data *pkd = data;
	struct expression *parent;

	parent = get_parent_assignment(expr);
	if (parent)
		expr = parent;

	db_helper(expr, pkd->call_back, pkd->param, pkd->key, pkd->info);
}

static void param_key_expr_function(const char *fn, struct expression *expr, void *data)
{
	struct param_key_data *pkd = data;
	struct expression *parent, *arg;

	parent = get_parent_assignment(expr);
	if (parent)
		expr = parent;

	arg = gen_expr_from_param_key(expr, pkd->param, pkd->key);
	if (!arg)
		return;
	pkd->expr_fn(arg);
}

static void param_key_implies_function(const char *fn, struct expression *call_expr,
				       struct expression *assign_expr, void *data)
{
	struct param_key_data *pkd = data;

	db_helper(assign_expr ?: call_expr, pkd->call_back, pkd->param, pkd->key, pkd->info);
}

static void param_key_expr_implies_function(const char *fn, struct expression *call_expr,
					    struct expression *assign_expr, void *data)
{
	struct param_key_data *pkd = data;
	struct expression *arg;

	arg = gen_expr_from_param_key(assign_expr ?: call_expr, pkd->param, pkd->key);
	if (!arg)
		return;
	pkd->expr_fn(arg);
}

static struct param_key_data *alloc_pkd(param_key_hook *call_back, int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = malloc(sizeof(*pkd));
	pkd->call_back = call_back;
	pkd->param = param;
	pkd->key = alloc_string(key);
	pkd->info = info;

	return pkd;
}

static struct param_key_data *alloc_pked(expr_func *call_back, int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pkd(NULL, param, key, info);
	pkd->expr_fn = call_back;

	return pkd;
}

void add_function_param_key_hook_early(const char *look_for, param_key_hook *call_back,
				       int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	if (param == -1) {
		printf("pointless early hook for '%s'", look_for);
		return;
	}

	pkd = alloc_pkd(call_back, param, key, info);
	add_function_hook_early(look_for, &param_key_function, pkd);
}

void add_function_param_key_hook(const char *look_for, param_key_hook *call_back,
				 int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pkd(call_back, param, key, info);
	if (param == -1)
		add_function_assign_hook(look_for, &param_key_function, pkd);
	else
		add_function_hook(look_for, &param_key_function, pkd);
}

void add_param_key_expr_hook(const char *look_for, expr_func *call_back,
				  int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pked(call_back, param, key, info);

	if (param == -1)
		add_function_assign_hook(look_for, &param_key_expr_function, pkd);
	else
		add_function_hook(look_for, &param_key_expr_function, pkd);
}

void add_function_param_key_hook_late(const char *look_for, param_key_hook *call_back,
				      int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pkd(call_back, param, key, info);
	add_function_hook_late(look_for, &param_key_function, pkd);
}

void return_implies_param_key(const char *look_for, sval_t start, sval_t end,
			      param_key_hook *call_back,
			      int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pkd(call_back, param, key, info);
	return_implies_state_sval(look_for, start, end, &param_key_implies_function, pkd);
}

void return_implies_param_key_exact(const char *look_for, sval_t start, sval_t end,
				    param_key_hook *call_back,
				    int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pkd(call_back, param, key, info);
	return_implies_exact(look_for, start, end, &param_key_implies_function, pkd);
}

void return_implies_param_key_expr(const char *look_for, sval_t start, sval_t end,
				   expr_func *call_back,
				   int param, const char *key, void *info)
{
	struct param_key_data *pkd;

	pkd = alloc_pked(call_back, param, key, info);
	return_implies_state_sval(look_for, start, end, &param_key_expr_implies_function, pkd);
}

void add_macro_assign_hook(const char *look_for, func_hook *call_back,
			void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(MACRO_ASSIGN, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void add_macro_assign_hook_extra(const char *look_for, func_hook *call_back,
			void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(MACRO_ASSIGN_EXTRA, call_back, info);
	add_callback(func_hash, look_for, cb);
}

void return_implies_state(const char *look_for, long long start, long long end,
			 implication_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(RANGED_CALL, call_back, info);
	cb->range = alloc_range_perm(ll_to_sval(start), ll_to_sval(end));
	add_callback(func_hash, look_for, cb);
}

void return_implies_state_sval(const char *look_for, sval_t start, sval_t end,
			 implication_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(RANGED_CALL, call_back, info);
	cb->range = alloc_range_perm(start, end);
	add_callback(func_hash, look_for, cb);
}

void return_implies_exact(const char *look_for, sval_t start, sval_t end,
			  implication_hook *call_back, void *info)
{
	struct fcall_back *cb;

	cb = alloc_fcall_back(RANGED_EXACT, call_back, info);
	cb->range = alloc_range_perm(start, end);
	add_callback(func_hash, look_for, cb);
}

static struct return_implies_callback *alloc_db_return_callback(int type, bool param_key, void *callback)
{
	struct return_implies_callback *cb;

	cb = __alloc_return_implies_callback(0);
	cb->type = type;
	cb->param_key = param_key;
	cb->callback = callback;

	return cb;
}

void select_return_states_hook(int type, return_implies_hook *callback)
{
	struct return_implies_callback *cb;

	cb = alloc_db_return_callback(type, false, callback);
	add_ptr_list(&db_return_states_list, cb);
}

static void call_db_return_callback(struct db_callback_info *db_info,
				    struct return_implies_callback *cb,
				    int param, char *key, char *value)
{
	if (cb->param_key) {
		db_helper(db_info->expr, cb->pk_callback, param, key, NULL);
		add_ptr_list(&db_info->called, cb);
	} else {
		cb->callback(db_info->expr, param, key, value);
	}
}

void select_return_param_key(int type, param_key_hook *callback)
{
	struct return_implies_callback *cb;

	cb = alloc_db_return_callback(type, true, callback);
	add_ptr_list(&db_return_states_list, cb);
}

void select_return_states_before(void_fn *fn)
{
	add_ptr_list(&return_states_before, fn);
}

void select_return_states_after(void_fn *fn)
{
	add_ptr_list(&return_states_after, fn);
}

void add_return_string_hook(string_hook *fn)
{
	add_ptr_list(&return_string_hooks, fn);
}

static bool call_call_backs(struct call_back_list *list, int type,
			    const char *fn, struct expression *expr)
{
	struct fcall_back *tmp;
	bool handled = false;

	FOR_EACH_PTR(list, tmp) {
		if (tmp->type == type) {
			(tmp->u.call_back)(fn, expr, tmp->info);
			handled = true;
		}
	} END_FOR_EACH_PTR(tmp);

	return handled;
}

static void call_function_hooks(struct expression *expr, enum fn_hook_type type)
{
	struct call_back_list *call_backs;
	const char *fn_name;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	fn_name = get_fn_name(expr->fn);
	call_backs = get_call_backs(fn_name);
	if (!call_backs)
		return;

	call_call_backs(call_backs, type, fn_name, expr);
}

static void call_return_states_after_hooks(struct expression *expr)
{
	call_void_fns(return_states_after);
	__pass_to_client(expr, FUNCTION_CALL_HOOK_AFTER_DB);
	call_function_hooks(expr, REGULAR_CALL_LATE);
}

static void call_ranged_call_backs(struct call_back_list *list,
				const char *fn, struct expression *call_expr,
				struct expression *assign_expr)
{
	struct fcall_back *tmp;

	FOR_EACH_PTR(list, tmp) {
		(tmp->u.ranged)(fn, call_expr, assign_expr, tmp->info);
	} END_FOR_EACH_PTR(tmp);
}

static struct call_back_list *get_same_ranged_call_backs(struct call_back_list *list,
						struct data_range *drange)
{
	struct call_back_list *ret = NULL;
	struct fcall_back *tmp;

	FOR_EACH_PTR(list, tmp) {
		if (tmp->type != RANGED_CALL &&
		    tmp->type != RANGED_EXACT)
			continue;
		if (ranges_equiv(tmp->range, drange))
			add_ptr_list(&ret, tmp);
	} END_FOR_EACH_PTR(tmp);
	return ret;
}

static bool in_list_exact_sval(struct range_list *list, struct data_range *drange)
{
	struct data_range *tmp;

	FOR_EACH_PTR(list, tmp) {
		if (ranges_equiv(tmp, drange))
			return true;
	} END_FOR_EACH_PTR(tmp);
	return false;
}

/*
 * The assign_ranged_funcs() function is called when we have no data from the DB.
 */
static bool assign_ranged_funcs(const char *fn, struct expression *expr,
				 struct call_back_list *call_backs)
{
	struct fcall_back *tmp;
	struct sm_state *sm;
	char *var_name;
	struct symbol *sym;
	struct smatch_state *estate;
	struct stree *tmp_stree;
	struct stree *final_states = NULL;
	struct range_list *handled_ranges = NULL;
	struct range_list *unhandled_rl;
	struct call_back_list *same_range_call_backs = NULL;
	struct expression *call;
	struct range_list *rl;
	int handled = false;

	if (!call_backs)
		return false;

	var_name = expr_to_var_sym(expr->left, &sym);
	if (!var_name || !sym)
		goto free;

	call = strip_expr(expr->right);

	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL &&
		    tmp->type != RANGED_EXACT)
			continue;

		if (in_list_exact_sval(handled_ranges, tmp->range))
			continue;
		__push_fake_cur_stree();
		tack_on(&handled_ranges, tmp->range);

		same_range_call_backs = get_same_ranged_call_backs(call_backs, tmp->range);
		call_ranged_call_backs(same_range_call_backs, fn, expr->right, expr);
		__free_ptr_list((struct ptr_list **)&same_range_call_backs);

		rl = alloc_rl(tmp->range->min, tmp->range->max);
		rl = cast_rl(get_type(expr->left), rl);
		estate = alloc_estate_rl(rl);
		set_extra_mod(var_name, sym, expr->left, estate);

		tmp_stree = __pop_fake_cur_stree();
		merge_fake_stree(&final_states, tmp_stree);
		free_stree(&tmp_stree);
		handled = true;
	} END_FOR_EACH_PTR(tmp);

	unhandled_rl = rl_filter(alloc_whole_rl(get_type(call)), handled_ranges);
	if (unhandled_rl) {
		__push_fake_cur_stree();
		rl = cast_rl(get_type(expr->left), unhandled_rl);
		estate = alloc_estate_rl(rl);
		set_extra_mod(var_name, sym, expr->left, estate);
		tmp_stree = __pop_fake_cur_stree();
		merge_fake_stree(&final_states, tmp_stree);
		free_stree(&tmp_stree);
	}

	FOR_EACH_SM(final_states, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&final_states);
free:
	free_string(var_name);
	return handled;
}

static void call_implies_callbacks(int comparison, struct expression *expr, sval_t sval, int left, struct stree **implied_true, struct stree **implied_false)
{
	struct call_back_list *call_backs;
	struct fcall_back *tmp;
	const char *fn_name;
	struct data_range *value_range;
	struct stree *true_states = NULL;
	struct stree *false_states = NULL;
	struct stree *tmp_stree;

	*implied_true = NULL;
	*implied_false = NULL;
	fn_name = get_fn_name(expr->fn);
	call_backs = get_call_backs(fn_name);
	if (!call_backs)
		return;
	value_range = alloc_range(sval, sval);

	/* set true states */
	__push_fake_cur_stree();
	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL &&
		    tmp->type != RANGED_EXACT)
			continue;
		if (!true_comparison_range_LR(comparison, tmp->range, value_range, left))
			continue;
		(tmp->u.ranged)(fn_name, expr, NULL, tmp->info);
	} END_FOR_EACH_PTR(tmp);
	tmp_stree = __pop_fake_cur_stree();
	merge_fake_stree(&true_states, tmp_stree);
	free_stree(&tmp_stree);

	/* set false states */
	__push_fake_cur_stree();
	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL &&
		    tmp->type != RANGED_EXACT)
			continue;
		if (!false_comparison_range_LR(comparison, tmp->range, value_range, left))
			continue;
		(tmp->u.ranged)(fn_name, expr, NULL, tmp->info);
	} END_FOR_EACH_PTR(tmp);
	tmp_stree = __pop_fake_cur_stree();
	merge_fake_stree(&false_states, tmp_stree);
	free_stree(&tmp_stree);

	*implied_true = true_states;
	*implied_false = false_states;
}

static void set_implied_states(struct db_callback_info *db_info)
{
	struct sm_state *sm;

	FOR_EACH_SM(db_info->implied, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&db_info->implied);
}

static void store_return_state(struct db_callback_info *db_info, const char *ret_str, struct smatch_state *state)
{
	db_info->ret_str = alloc_sname(ret_str),
	db_info->ret_state = state;
}

static struct expression_list *unfaked_calls;

struct expression *get_unfaked_call(void)
{
	return last_ptr_list((struct ptr_list *)unfaked_calls);
}

static void store_unfaked_call(struct expression *expr)
{
	push_expression(&unfaked_calls, expr);
}

static void clear_unfaked_call(void)
{
	delete_ptr_list_last((struct ptr_list **)&unfaked_calls);
}

void fake_param_assign_helper(struct expression *call, struct expression *fake_assign, bool shallow)
{
	store_unfaked_call(call);
	__in_fake_parameter_assign++;
	parse_assignment(fake_assign, true);
	__in_fake_parameter_assign--;
	clear_unfaked_call();
}

static bool fake_a_param_assignment(struct expression *expr, const char *ret_str, struct smatch_state *orig)
{
	struct expression *arg, *left, *right, *tmp, *fake_assign;
	char *p;
	int param;
	char buf[256];
	char *str;

	if (expr->type != EXPR_ASSIGNMENT || expr->op != '=')
		return false;
	left = expr->left;
	right = expr->right;

	while (right->type == EXPR_ASSIGNMENT)
		right = strip_expr(right->right);
	if (!right || right->type != EXPR_CALL)
		return false;

	p = strchr(ret_str, '[');
	if (!p)
		return false;

	p++;
	if (p[0] == '=' && p[1] == '=')
		p += 2;
	if (p[0] != '$')
		return false;

	snprintf(buf, sizeof(buf), "%s", p);

	p = buf;
	p += 1;
	param = strtol(p, &p, 10);

	p = strchr(p, ']');
	if (!p || *p != ']')
		return false;
	*p = '\0';

	arg = get_argument_from_call_expr(right->args, param);
	if (!arg)
		return false;

	/* There should be a get_other_name() function which returns an expr */
	tmp = get_assigned_expr(arg);
	if (tmp)
		arg = tmp;

	/*
	 * This is a sanity check to prevent side effects from evaluating stuff
	 * twice.
	 */
	str = expr_to_chunk_sym_vsl(arg, NULL, NULL);
	if (!str)
		return false;
	free_string(str);

	right = gen_expression_from_key(arg, buf);
	if (!right)  /* Mostly fails for binops like [$0 + 4032] */
		return false;
	fake_assign = assign_expression(left, '=', right);
	fake_param_assign_helper(expr, fake_assign, false);

	/*
	 * If the return is "0-65531[$0->nla_len - 4]" the faked expression
	 * is maybe (-4)-65531 but we know it is in the 0-65531 range so both
	 * parts have to be considered.  We use _nomod() because it's not really
	 * another modification, it's just a clarification.
	 *
	 */
	if (estate_rl(orig)) {
		struct smatch_state *faked;
		struct range_list *rl;

		faked = get_extra_state(left);
		if (estate_rl(faked)) {
			rl = rl_intersection(estate_rl(faked), estate_rl(orig));
			if (rl)
				set_extra_expr_nomod(left, alloc_estate_rl(rl));
		}
	}

	return true;
}

static void fake_return_assignment(struct db_callback_info *db_info, int type, int param, char *key, char *value)
{
	struct expression *call, *left, *right, *assign;
	int right_param;

	if (type != PARAM_COMPARE)
		return;

	call = db_info->expr;
	while (call && call->type == EXPR_ASSIGNMENT)
		call = strip_expr(call->right);
	if (!call || call->type != EXPR_CALL)
		return;

	// TODO: This only handles "$->foo = arg" and not "$->foo = arg->bar".
	if (param != -1)
		return;
	if (!value || strncmp(value, "== $", 4) != 0)
		return;
	if (!isdigit(value[4]) || value[5] != '\0')
		return;
	right_param = atoi(value + 4);

	left = gen_expr_from_param_key(db_info->expr, param, key);
	if (!left)
		return;
	right = get_argument_from_call_expr(call->args, right_param);

	assign = assign_expression(left, '=', right);
	push_expression(&db_info->fake_param_assign_stack, assign);
}

static void set_fresh_mtag_returns(struct db_callback_info *db_info)
{
	struct expression *expr;
	struct smatch_state *state;

	if (!db_info->ret_state)
		return;

	if (!db_info->expr ||
	    db_info->expr->type != EXPR_ASSIGNMENT ||
	    db_info->expr->op != '=')
		return;

	expr = db_info->expr->left;

	state = alloc_estate_rl(cast_rl(get_type(expr), clone_rl(estate_rl(db_info->ret_state))));
	state = get_mtag_return(db_info->expr, state);
	if (!state)
		return;

	set_real_absolute(expr, state);
	set_extra_expr_mod(expr, state);
}

static void set_return_assign_state(struct db_callback_info *db_info)
{
	struct expression *expr = db_info->expr->left;
	struct expression *fake_assign;
	struct smatch_state *state;
	bool was_set = false;

	if (!db_info->ret_state)
		return;

	state = alloc_estate_rl(cast_rl(get_type(expr), clone_rl(estate_rl(db_info->ret_state))));
	if (!fake_a_param_assignment(db_info->expr, db_info->ret_str, state)) {
		set_extra_expr_mod(expr, state);
		was_set = true;
	}

	while ((fake_assign = pop_expression(&db_info->fake_param_assign_stack))) {
		struct range_list *left, *right;

		/*
		 * Originally, I tried to do this as a assignment to record that
		 * a = frob(b) implies that "a->foo == b->foo" etc.  But that
		 * caused a problem because then it was recorded that "a->foo"
		 * was modified and recorded as a PARAM_SET in the database.
		 *
		 * So now, instead of faking an assignment we use
		 * set_extra_expr_nomod() but it's still recorded as an
		 * assignment in the ->fake_param_assign_stack for legacy
		 * reasons and because it's a handy way to store a left/right
		 * pair.
		 */

		get_absolute_rl(fake_assign->left, &left);
		get_absolute_rl(fake_assign->right, &right);
		right = cast_rl(get_type(fake_assign->left), right);
		// FIXME: add some sanity checks
		// FIXME: preserve the sm state if possible
		set_extra_expr_nomod(fake_assign->left, alloc_estate_rl(right));
		was_set = true;
	}

	if (!was_set)
		set_extra_expr_mod(expr, state);
}

static void set_other_side_state(struct db_callback_info *db_info)
{
	struct expression *expr = db_info->var_expr;
	struct smatch_state *state;

	if (!db_info->ret_state)
		return;

	// TODO: faked_assign set ==$ equiv here

	state = alloc_estate_rl(cast_rl(get_type(expr), clone_rl(estate_rl(db_info->ret_state))));
	set_extra_expr_nomod(expr, state);
	db_info->ret_state = NULL;
	db_info->ret_str = NULL;
}

static void handle_ret_equals_param(char *ret_string, struct range_list *rl, struct expression *call)
{
	char *str;
	long long param;
	struct expression *arg;
	struct range_list *orig;

	// TODO: faked_assign This needs to be handled in the assignment code

	str = strstr(ret_string, "==$");
	if (!str)
		return;
	str += 3;
	param = strtoll(str, NULL, 10);
	arg = get_argument_from_call_expr(call->args, param);
	if (!arg)
		return;
	get_absolute_rl(arg, &orig);
	rl = rl_intersection(orig, rl);
	if (!rl)
		return;
	set_extra_expr_nomod(arg, alloc_estate_rl(rl));
}

static bool impossible_limit(struct db_callback_info *db_info, int param, char *key, char *value)
{
	struct expression *expr = db_info->expr;
	struct expression *arg;
	struct smatch_state *state;
	struct range_list *passed;
	struct range_list *limit;
	struct symbol *compare_type;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return false;

	arg = get_argument_from_call_expr(expr->args, param);
	if (!arg)
		return false;

	if (strcmp(key, "$") == 0) {
		if (!get_implied_rl(arg, &passed))
			return false;

		compare_type = get_arg_type(expr->fn, param);
	} else {
		char *name;
		struct symbol *sym;

		name = get_variable_from_key(arg, key, &sym);
		if (!name || !sym)
			return false;

		state = get_state(SMATCH_EXTRA, name, sym);
		if (!state) {
			free_string(name);
			return false;
		}
		passed = estate_rl(state);
		if (!passed || is_whole_rl(passed)) {
			free_string(name);
			return false;
		}

		compare_type = get_member_type_from_key(arg, key);
	}

	passed = cast_rl(compare_type, passed);
	call_results_to_rl(expr, compare_type, value, &limit);
	if (!limit || is_whole_rl(limit))
		return false;
	if (possibly_true_rl(passed, SPECIAL_EQUAL, limit))
		return false;
	if (option_debug || local_debug || debug_db)
		sm_msg("impossible: %d '%s' limit '%s' == '%s' return='%s'", param, key, show_rl(passed), value, db_info->ret_str);
	return true;
}

static bool is_impossible_data(int type, struct db_callback_info *db_info, int param, char *key, char *value)
{
	if (type == PARAM_LIMIT && impossible_limit(db_info, param, key, value))
		return true;
	if (type == COMPARE_LIMIT && param_compare_limit_is_impossible(db_info->expr, param, key, value)) {
		if (local_debug || debug_db)
			sm_msg("param_compare_limit_is_impossible: %d %s %s", param, key, value);
		return true;
	}
	return false;
}

static bool func_type_mismatch(struct expression *expr, const char *value)
{
	struct symbol *type;

	/* This makes faking returns easier */
	if (!value || value[0] == '\0')
		return false;

	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);

	/*
	 * Short cut:  We only care about function pointers that are struct
	 * members.
	 *
	 */
	if (expr->fn->type == EXPR_SYMBOL)
		return false;

	type = get_type(expr->fn);
	if (!type)
		return false;
	if (type->type == SYM_PTR)
		type = get_real_base_type(type);

	if (strcmp(type_to_str(type), value) == 0)
		return false;

	return true;
}

static void process_return_states(struct db_callback_info *db_info)
{
	struct stree *stree;

	set_implied_states(db_info);
	set_fresh_mtag_returns(db_info);
	parse_fake_calls();
	free_ptr_list(&db_info->called);
	stree = __pop_fake_cur_stree();
	if (debug_db) {
		sm_msg("States from DB: %s expr='%s' ret_str='%s' rl='%s' state='%s'",
		       db_info->cull ? "Culling" : "Merging",
		       expr_to_str(db_info->expr),
		       db_info->ret_str, show_rl(db_info->rl),
		       db_info->ret_state ? db_info->ret_state->name : "<none>");
		__print_stree(stree);
	}

	if (!db_info->cull) {
		merge_fake_stree(&db_info->stree, stree);
		db_info->states_merged = true;
	}
	free_stree(&stree);

	db_info->ret_state = NULL;
	db_info->ret_str = NULL;
}

static int db_compare_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_callback_info *db_info = _info;
	struct range_list *var_rl = db_info->rl;
	struct range_list *ret_range;
	int type, param;
	char *ret_str, *key, *value;
	struct return_implies_callback *tmp;
	int return_id;
	int comparison;

	if (argc != 6)
		return 0;

	return_id = atoi(argv[0]);
	ret_str = argv[1];
	type = atoi(argv[2]);
	param = atoi(argv[3]);
	key = argv[4];
	value = argv[5];

	db_info->has_states = 1;
	if (db_info->prev_return_id != -1 && type == INTERNAL) {
		set_other_side_state(db_info);
		process_return_states(db_info);
		__push_fake_cur_stree();
		db_info->cull = 0;
	}
	db_info->prev_return_id = return_id;

	if (type == INTERNAL && func_type_mismatch(db_info->expr, value))
		db_info->cull = 1;
	if (db_info->cull)
		return 0;
	if (type == CULL_PATH) {
		db_info->cull = 1;
		return 0;
	}

	if (is_impossible_data(type, db_info, param, key, value)) {
		db_info->cull = 1;
		return 0;
	}

	call_results_to_rl(db_info->expr, get_type(strip_expr(db_info->expr)), ret_str, &ret_range);
	ret_range = cast_rl(get_type(db_info->expr), ret_range);
	if (!ret_range)
		ret_range = alloc_whole_rl(get_type(db_info->expr));

	comparison = db_info->comparison;
	if (db_info->left)
		comparison = flip_comparison(comparison);

	if (db_info->true_side) {
		if (!possibly_true_rl(var_rl, comparison, ret_range))
			return 0;
		if (type == PARAM_LIMIT)
			param_limit_implications(db_info->expr, param, key, value, &db_info->implied);
		else if (type > PARAM_LIMIT)
			set_implied_states(db_info);
		filter_by_comparison(&var_rl, comparison, ret_range);
		filter_by_comparison(&ret_range, flip_comparison(comparison), var_rl);
	} else {
		if (!possibly_false_rl(var_rl, comparison, ret_range))
			return 0;
		if (type == PARAM_LIMIT)
			param_limit_implications(db_info->expr, param, key, value, &db_info->implied);
		else if (type > PARAM_LIMIT)
			set_implied_states(db_info);
		filter_by_comparison(&var_rl, negate_comparison(comparison), ret_range);
		filter_by_comparison(&ret_range, flip_comparison(negate_comparison(comparison)), var_rl);
	}

	handle_ret_equals_param(ret_str, ret_range, db_info->expr);

	if (type == INTERNAL) {
		set_state(-1, "unnull_path", NULL, &true_state);
		call_string_hooks(return_string_hooks, db_info->expr, ret_str);
		store_return_state(db_info, ret_str, alloc_estate_rl(clone_rl(var_rl)));
	}

	FOR_EACH_PTR(db_info->callbacks, tmp) {
		if (tmp->type == type)
			call_db_return_callback(db_info, tmp, param, key, value);
	} END_FOR_EACH_PTR(tmp);

	fake_return_assignment(db_info, type, param, key, value);

	return 0;
}

static void compare_db_return_states_callbacks(struct expression *left, int comparison, struct expression *right, struct stree *implied_true, struct stree *implied_false)
{
	struct stree *orig_states;
	struct stree *true_states;
	struct stree *false_states;
	struct sm_state *sm;
	struct db_callback_info db_info = {};
	struct expression *var_expr;
	struct expression *call_expr;
	struct range_list *rl;
	int call_on_left;

	orig_states = clone_stree(__get_cur_stree());

	/* legacy cruft.  need to fix call_implies_callbacks(). */
	call_on_left = 1;
	call_expr = left;
	var_expr = right;
	if (left->type != EXPR_CALL) {
		call_on_left = 0;
		call_expr = right;
		var_expr = left;
	}

	get_absolute_rl(var_expr, &rl);

	db_info.comparison = comparison;
	db_info.expr = call_expr;
	db_info.rl = rl;
	db_info.left = call_on_left;
	db_info.callbacks = db_return_states_list;
	db_info.var_expr = var_expr;

	call_void_fns(return_states_before);

	db_info.true_side = 1;
	db_info.stree = NULL;
	db_info.prev_return_id = -1;
	__push_fake_cur_stree();
	sql_select_return_states("return_id, return, type, parameter, key, value",
				 call_expr, db_compare_callback, &db_info);
	set_other_side_state(&db_info);
	process_return_states(&db_info);
	true_states = db_info.stree;
	if (!true_states && db_info.has_states) {
		__push_fake_cur_stree();
		set_path_impossible();
		true_states = __pop_fake_cur_stree();
	}

	nullify_path();
	__unnullify_path();
	FOR_EACH_SM(orig_states, sm) {
		__set_sm_cur_stree(sm);
	} END_FOR_EACH_SM(sm);

	db_info.true_side = 0;
	db_info.stree = NULL;
	db_info.prev_return_id = -1;
	db_info.cull = 0;
	__push_fake_cur_stree();
	sql_select_return_states("return_id, return, type, parameter, key, value", call_expr,
			db_compare_callback, &db_info);
	set_other_side_state(&db_info);
	process_return_states(&db_info);
	false_states = db_info.stree;
	if (!false_states && db_info.has_states) {
		__push_fake_cur_stree();
		set_path_impossible();
		false_states = __pop_fake_cur_stree();
	}

	nullify_path();
	__unnullify_path();
	FOR_EACH_SM(orig_states, sm) {
		__set_sm_cur_stree(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&orig_states);

	FOR_EACH_SM(true_states, sm) {
		__set_true_false_sm(sm, NULL);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(false_states, sm) {
		__set_true_false_sm(NULL, sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&true_states);
	free_stree(&false_states);

	if (!db_info.states_merged)
		mark_call_params_untracked(call_expr);

	call_return_states_after_hooks(call_expr);

	FOR_EACH_SM(implied_true, sm) {
		__set_true_false_sm(sm, NULL);
	} END_FOR_EACH_SM(sm);
	FOR_EACH_SM(implied_false, sm) {
		__set_true_false_sm(NULL, sm);
	} END_FOR_EACH_SM(sm);
}

void function_comparison(struct expression *left, int comparison, struct expression *right)
{
	struct expression *var_expr;
	struct expression *call_expr;
	struct stree *implied_true = NULL;
	struct stree *implied_false = NULL;
	struct range_list *rl;
	sval_t sval;
	int call_on_left;

	// TODO: faked_assign delete this
	// condition calls should be faked and then handled as assignments
	// this code is a lazy work around

	if (unreachable())
		return;

	/* legacy cruft.  need to fix call_implies_callbacks(). */
	call_on_left = 1;
	call_expr = left;
	var_expr = right;
	if (left->type != EXPR_CALL) {
		call_on_left = 0;
		call_expr = right;
		var_expr = left;
	}

	get_absolute_rl(var_expr, &rl);

	if (rl_to_sval(rl, &sval))
		call_implies_callbacks(comparison, call_expr, sval, call_on_left, &implied_true, &implied_false);

	compare_db_return_states_callbacks(left, comparison, right, implied_true, implied_false);
	free_stree(&implied_true);
	free_stree(&implied_false);
}

static void call_ranged_return_hooks(struct db_callback_info *db_info)
{
	struct call_back_list *call_backs;
	struct range_list *range_rl;
	struct expression *expr;
	struct fcall_back *tmp;
	const char *fn_name;

	expr = strip_expr(db_info->expr);
	while (expr->type == EXPR_ASSIGNMENT)
		expr = strip_expr(expr->right);
	if (expr->type != EXPR_CALL)
		return;

	fn_name = get_fn_name(expr->fn);
	call_backs = get_call_backs(fn_name);
	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL)
			continue;
		range_rl = alloc_rl(tmp->range->min, tmp->range->max);
		range_rl = cast_rl(estate_type(db_info->ret_state), range_rl);
		if (possibly_true_rl(range_rl, SPECIAL_EQUAL, estate_rl(db_info->ret_state)))
			(tmp->u.ranged)(fn_name, expr, db_info->expr, tmp->info);
	} END_FOR_EACH_PTR(tmp);

	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_EXACT)
			continue;
		if (!estate_rl(db_info->ret_state))
			continue;

		range_rl = alloc_rl(tmp->range->min, tmp->range->max);
		range_rl = cast_rl(estate_type(db_info->ret_state), range_rl);

		/*
		 * If there is an returned value out of range then this is not
		 * an exact match.  In other words, "0,4096-ptr_max" is not
		 * necessarily a valid match.
		 *
		 */
		if (remove_range(estate_rl(db_info->ret_state),
				 rl_min(range_rl), rl_max(range_rl)))
			continue;
		(tmp->u.ranged)(fn_name, expr, db_info->expr, tmp->info);
	} END_FOR_EACH_PTR(tmp);
}

static int db_assign_return_states_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_callback_info *db_info = _info;
	struct range_list *ret_range;
	int type, param;
	char *ret_str, *key, *value;
	struct return_implies_callback *tmp;
	int return_id;

	if (argc != 6)
		return 0;

	return_id = atoi(argv[0]);
	ret_str = argv[1];
	type = atoi(argv[2]);
	param = atoi(argv[3]);
	key = argv[4];
	value = argv[5];

	if (db_info->prev_return_id != -1 && type == INTERNAL) {
		call_ranged_return_hooks(db_info);
		set_return_assign_state(db_info);
		process_return_states(db_info);
		__push_fake_cur_stree();
		db_info->cull = 0;
	}
	db_info->prev_return_id = return_id;

	if (type == INTERNAL && func_type_mismatch(db_info->expr, value))
		db_info->cull = 1;
	if (db_info->cull)
		return 0;
	if (type == CULL_PATH) {
		db_info->cull = 1;
		return 0;
	}
	if (is_impossible_data(type, db_info, param, key, value)) {
		db_info->cull = 1;
		return 0;
	}

	if (type == PARAM_LIMIT)
		param_limit_implications(db_info->expr, param, key, value, &db_info->implied);
	else if (type > PARAM_LIMIT)
		set_implied_states(db_info);

	db_info->handled = 1;
	call_results_to_rl(db_info->expr->right, get_type(strip_expr(db_info->expr->right)), ret_str, &ret_range);
	if (!ret_range)
		ret_range = alloc_whole_rl(get_type(strip_expr(db_info->expr->right)));
	ret_range = cast_rl(get_type(db_info->expr->right), ret_range);

	if (type == INTERNAL) {
		set_state(-1, "unnull_path", NULL, &true_state);
		__add_comparison_info(db_info->expr->left, strip_expr(db_info->expr->right), ret_str);
		call_string_hooks(return_string_hooks, db_info->expr, ret_str);
		store_return_state(db_info, ret_str, alloc_estate_rl(ret_range));
	}

	FOR_EACH_PTR(db_return_states_list, tmp) {
		if (tmp->type == type)
			call_db_return_callback(db_info, tmp, param, key, value);
	} END_FOR_EACH_PTR(tmp);

	fake_return_assignment(db_info, type, param, key, value);

	return 0;
}

static int db_return_states_assign(struct expression *expr)
{
	struct expression *right;
	struct sm_state *sm;
	struct db_callback_info db_info = {};

	right = strip_expr(expr->right);

	db_info.prev_return_id = -1;
	db_info.expr = expr;
	db_info.stree = NULL;
	db_info.handled = 0;

	call_void_fns(return_states_before);

	__push_fake_cur_stree();
	sql_select_return_states("return_id, return, type, parameter, key, value",
			right, db_assign_return_states_callback, &db_info);
	if (option_debug) {
		sm_msg("%s return_id %d return_ranges %s",
			db_info.cull ? "culled" : "merging",
			db_info.prev_return_id,
			db_info.ret_state ? db_info.ret_state->name : "'<empty>'");
	}
	if (db_info.handled)
		call_ranged_return_hooks(&db_info);
	set_return_assign_state(&db_info);
	process_return_states(&db_info);

	if (!db_info.stree && db_info.cull) { /* this means we culled everything */
		set_extra_expr_mod(expr->left, alloc_estate_whole(get_type(expr->left)));
		set_path_impossible();
	}
	FOR_EACH_SM(db_info.stree, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&db_info.stree);

	if (!db_info.states_merged)
		mark_call_params_untracked(right);

	call_return_states_after_hooks(right);

	return db_info.handled;
}

static bool handle_implied_return(struct expression *expr)
{
	struct range_list *rl;

	if (!get_implied_return(expr->right, &rl))
		return false;
	rl = cast_rl(get_type(expr->left), rl);
	set_extra_expr_mod(expr->left, alloc_estate_rl(rl));
	return true;
}

static void match_assign_call(struct expression *expr)
{
	struct call_back_list *call_backs;
	const char *fn_name;
	struct expression *right;
	int handled = 0;
	struct range_list *rl;

	if (expr->op != '=')
		return;

	right = strip_expr(expr->right);
	if (is_fake_call(right))
		return;

	fn_name = get_fn_name(right->fn);
	call_backs = get_call_backs(fn_name);

	/*
	 * The ordering here is sort of important.
	 * One example, of how this matters is that when we do:
	 *
	 * 	len = strlen(str);
	 *
	 * That is handled by smatch_common_functions.c and smatch_strlen.c.
	 * They use implied_return and function_assign_hook respectively.
	 * We want to get the implied return first before we do the function
	 * assignment hook otherwise we end up writing the wrong thing for len
	 * in smatch_extra.c because we assume that it already holds the
	 * strlen() when we haven't set it yet.
	 */

	if (db_return_states_assign(expr))
		handled = 1;
	else
		handled = assign_ranged_funcs(fn_name, expr, call_backs);
	handled |= handle_implied_return(expr);


	call_call_backs(call_backs, ASSIGN_CALL, fn_name, expr);

	if (handled)
		return;

	/* assignment wasn't handled at all */
	get_absolute_rl(expr->right, &rl);
	rl = cast_rl(get_type(expr->left), rl);
	set_extra_expr_mod(expr->left, alloc_estate_rl(rl));
}

static int db_return_states_callback(void *_info, int argc, char **argv, char **azColName)
{
	struct db_callback_info *db_info = _info;
	struct range_list *ret_range;
	int type, param;
	char *ret_str, *key, *value;
	struct return_implies_callback *tmp;
	int return_id;

	if (argc != 6)
		return 0;

	return_id = atoi(argv[0]);
	ret_str = argv[1];
	type = atoi(argv[2]);
	param = atoi(argv[3]);
	key = argv[4];
	value = argv[5];

	if (db_info->prev_return_id != -1 && type == INTERNAL) {
		call_ranged_return_hooks(db_info);
		process_return_states(db_info);
		__push_fake_cur_stree();
		__unnullify_path();
		db_info->cull = 0;
	}
	db_info->prev_return_id = return_id;

	if (type == INTERNAL && func_type_mismatch(db_info->expr, value))
		db_info->cull = 1;
	if (db_info->cull)
		return 0;
	if (type == CULL_PATH) {
		db_info->cull = 1;
		return 0;
	}
	if (is_impossible_data(type, db_info, param, key, value)) {
		db_info->cull = 1;
		return 0;
	}

	if (type == PARAM_LIMIT)
		param_limit_implications(db_info->expr, param, key, value, &db_info->implied);
	else if (type > PARAM_LIMIT)
		set_implied_states(db_info);

	call_results_to_rl(db_info->expr, get_type(strip_expr(db_info->expr)), ret_str, &ret_range);
	ret_range = cast_rl(get_type(db_info->expr), ret_range);

	if (type == INTERNAL) {
		struct smatch_state *state;

		set_state(-1, "unnull_path", NULL, &true_state);
		call_string_hooks(return_string_hooks, db_info->expr, ret_str);
		state = alloc_estate_rl(ret_range);
		store_return_state(db_info, ret_str, state);
	}

	FOR_EACH_PTR(db_return_states_list, tmp) {
		if (tmp->type == type)
			call_db_return_callback(db_info, tmp, param, key, value);
	} END_FOR_EACH_PTR(tmp);

	fake_return_assignment(db_info, type, param, key, value);

	return 0;
}

static void db_return_states(struct expression *expr)
{
	struct sm_state *sm;
	struct db_callback_info db_info = {};

	if (!__get_cur_stree())  /* no return functions */
		return;

	db_info.prev_return_id = -1;
	db_info.expr = expr;
	db_info.stree = NULL;

	call_void_fns(return_states_before);

	__push_fake_cur_stree();
	__unnullify_path();
	sql_select_return_states("return_id, return, type, parameter, key, value",
			expr, db_return_states_callback, &db_info);
	call_ranged_return_hooks(&db_info);
	process_return_states(&db_info);

	FOR_EACH_SM(db_info.stree, sm) {
		__set_sm(sm);
	} END_FOR_EACH_SM(sm);

	free_stree(&db_info.stree);

	if (!db_info.states_merged)
		mark_call_params_untracked(expr);

	call_return_states_after_hooks(expr);
}

static void db_return_states_call(struct expression *expr)
{
	if (unreachable())
		return;

	if (is_assigned_call(expr) || is_fake_assigned_call(expr))
		return;
	if (is_condition_call(expr))
		return;
	db_return_states(expr);
}

static void match_function_call_early(struct expression *expr)
{
	call_function_hooks(expr, REGULAR_CALL_EARLY);
}

static void match_function_call(struct expression *expr)
{
	call_function_hooks(expr, REGULAR_CALL);
	db_return_states_call(expr);
	/* If we have no database there could be unprocessed fake calls */
	parse_fake_calls();
}

static void match_macro_assign(struct expression *expr)
{
	struct call_back_list *call_backs;
	const char *macro;
	struct expression *right;

	right = strip_expr(expr->right);
	macro = get_macro_name(right->pos);
	call_backs = search_callback(func_hash, (char *)macro);
	if (!call_backs)
		return;
	call_call_backs(call_backs, MACRO_ASSIGN, macro, expr);
	call_call_backs(call_backs, MACRO_ASSIGN_EXTRA, macro, expr);
}

bool get_implied_return(struct expression *expr, struct range_list **rl)
{
	struct call_back_list *call_backs;
	struct fcall_back *tmp;
	bool handled = false;
	char *fn;

	*rl = NULL;

	expr = strip_expr(expr);
	fn = expr_to_var(expr->fn);
	if (!fn)
		goto out;

	call_backs = search_callback(func_hash, fn);

	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type == IMPLIED_RETURN)
			handled |= (tmp->u.implied_return)(expr, tmp->info, rl);
	} END_FOR_EACH_PTR(tmp);

out:
	free_string(fn);
	return handled;
}

struct range_list *get_range_implications(const char *fn)
{
	struct call_back_list *call_backs;
	struct range_list *ret = NULL;
	struct fcall_back *tmp;

	call_backs = search_callback(func_hash, (char *)fn);

	FOR_EACH_PTR(call_backs, tmp) {
		if (tmp->type != RANGED_CALL &&
		    tmp->type != RANGED_EXACT)
			continue;
		add_ptr_list(&ret, tmp->range);
	} END_FOR_EACH_PTR(tmp);

	return ret;
}

void create_function_hook_hash(void)
{
	func_hash = create_function_hashtable(5000);
}

void register_function_hooks_early(int id)
{
	add_hook(&match_function_call_early, FUNCTION_CALL_HOOK_BEFORE);
}

void register_function_hooks(int id)
{
	add_function_data((unsigned long *)&fake_calls);
	add_hook(&match_function_call, CALL_HOOK_AFTER_INLINE);
	add_hook(&match_assign_call, CALL_ASSIGNMENT_HOOK);
	add_hook(&match_macro_assign, MACRO_ASSIGNMENT_HOOK);
}
