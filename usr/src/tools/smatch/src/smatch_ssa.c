/*
 * Copyright (C) 2021 Oracle.
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
 * The truth is I don't know very much about compilers.  I've heard about
 * Single Static Assignment and it seems like a useful feature but it's also
 * possible I have misunderstood the whole thing.
 *
 * Anyway, the point is that say we have code like:
 * ret = alloc();
 * if (ret < 0)
 * 	return ret;
 * p->foo = ret;
 * ret = something else;
 *
 * So the problem here is "p->foo" and "ret" are equivalent at first but then
 * not at the end.  We don't really care if "p->foo" is freed or "ret" is freed,
 * we care if the value which was initially stored in "ret" is freed.  This is
 * different from equiv because "ret" and "p->foo" are not equiv at the end.
 * The SSA module doesn't deal with == only with =.
 *
 * Using this is a bit different and more complicated than I would like.  If
 * there is a new state then call set_ssa_state().  When you're getting the
 * state it's probably easiest to always use get_ssa_sm_state() because
 * afterwards you will need to call update_ssa_state(my_id, sm->name, sm->sym,
 * &state); to change the state.  If you call set_ssa_state() that basically
 * works too but it's slower because it adds a layer of indirection.
 *
 */

#include "smatch.h"
#include "smatch_extra.h"
#include "smatch_slist.h"

static int my_id;

static unsigned long ssa_id = 1;

char *ssa_name(const char *name)
{
	char *ret;
	char *p;

	ret = alloc_sname(name);
	p = strchr(ret, ':');
	if (p)
		*p = '\0';
	return ret;
}

static struct smatch_state *alloc_ssa_new(const char *name)
{
	struct smatch_state *state;
	char buf[64];

	state = __alloc_smatch_state(0);
	snprintf(buf, sizeof(buf), "%s:%ld", name, ssa_id);
	state->name = alloc_sname(buf);

	ssa_id++;

	return state;
}

static struct smatch_state *alloc_ssa_copy(struct sm_state *sm)
{
	struct smatch_state *state;

	if (sm->state == &undefined || sm->state == &merged)
		return sm->state;

	state = __alloc_smatch_state(0);
	state->name = alloc_sname(sm->state->name);
	return state;
}

static bool whatever_close_enough(struct expression *left, struct expression *right)
{
	struct symbol *left_type, *right_type;

	left_type = get_type(left);
	right_type = get_type(right);

	if (type_bits(right_type) == 64) {
		if (type_bits(left_type) == 64)
			return true;
		return false;
	}

	if (type_bits(right_type) == 32) {
		if (type_bits(left_type) == 64 || type_bits(left_type) == 32)
			return true;
		return false;
	}

	return false;
}

static void match_assign(struct expression *expr)
{
	struct smatch_state *left_state;
	struct sm_state *orig, *clone;
	struct symbol *left_sym, *right_sym;
	char *left_name = NULL, *right_name = NULL;

	if (__in_fake_assign)
		return;

	if (expr->op != '=')
		return;

	/* The whatever function is more likely to return true #Faster */
	if (!whatever_close_enough(expr->left, expr->right) &&
	    !values_fit_type(expr->left, expr->right))
		return;

	left_name = expr_to_var_sym(expr->left, &left_sym);
	if (!left_name)
		goto free;

	/*
	 * The ordering of this is really tricky.  The issue here is that we
	 * have: "dev = of_node_get(node);".  The first thing that happens is
	 * the modified hook sets "dev" to undefined.  Then the check for
	 * tracking of_node_get/put() allocates an ssa state for "dev".  So if
	 * it's set here we can just return.  Otherwise track the SSA state.
	 */
	left_state = get_state(my_id, left_name, left_sym);
	if (left_state && left_state != &undefined)
		goto free;

	right_name = expr_to_var_sym(expr->right, &right_sym);
	if (!right_name)
		goto free;

	orig = get_sm_state(my_id, right_name, right_sym);
	if (!orig || orig->state == &undefined)
		orig = set_state(my_id, right_name, right_sym, alloc_ssa_new(right_name));

	/* This can happen in unreachable code or outside of functions I gess */
	if (!orig)
		return;

	/*
	 * Cloning is only really necessary for &merged states but it's better
	 * to only have one code path where possible.
	 *
	 */
	clone        = clone_sm(orig);
	clone->state = alloc_ssa_copy(orig);
	clone->name  = alloc_sname(left_name);
	clone->sym   = left_sym;
	__set_sm(clone);

free:
	free_string(left_name);
	free_string(right_name);
}

void set_ssa_state(int owner, const char *name, struct symbol *sym,
	       struct smatch_state *state)
{
	struct sm_state *sm;

	if (!name)
		return;

	sm = get_sm_state(my_id, name, sym);
	if (!sm || sm->state == &undefined)
		sm = set_state(my_id, name, sym, alloc_ssa_new(name));
	if (!sm)
		return;
	if (sm->state == &merged) {
		sm = clone_sm(sm);
		sm->state = alloc_ssa_new(name);
		add_possible_sm(sm, sm);
		__set_sm(sm);
	}
	if (!sm)
		return;
	set_state(owner, sm->state->name, NULL, state);
}

void update_ssa_state(int owner, const char *name, struct symbol *sym,
		      struct smatch_state *state)
{
	set_state(owner, name, NULL, state);
}

void update_ssa_sm(int owner, struct sm_state *ssa_sm, struct smatch_state *state)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(ssa_sm->possible, tmp) {
		if (tmp->state == &merged ||
		    tmp->state == &undefined)
			continue;
		set_state(owner, tmp->state->name, NULL, state);
	} END_FOR_EACH_PTR(tmp);
}

void set_ssa_state_expr(int owner, struct expression *expr,
		struct smatch_state *state)
{
	struct symbol *sym;
	char *name;

	name = expr_to_var_sym(expr, &sym);
	if (!name)
		return;
	set_ssa_state(owner, name, sym, state);
	free_string(name);
}

struct sm_state *get_ssa_sm_state(int owner, const char *name, struct symbol *sym)
{
	struct sm_state *sm, *tmp, *owner_sm;
	struct sm_state *ret = NULL;

	sm = get_sm_state(my_id, name, sym);
	if (!sm || sm->state == &undefined)
		return NULL;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->state == &merged ||
		    tmp->state == &undefined)
			continue;
		owner_sm = get_sm_state(owner, tmp->state->name, NULL);
		if (owner_sm) {
			if (!ret)
				ret = clone_sm(owner_sm);
			else
				ret = merge_sm_states(ret, owner_sm);
		}
	} END_FOR_EACH_PTR(tmp);

	if (!ret)
		return NULL;

	tmp = ret;
	ret = clone_sm(sm);
	ret->state = tmp->state;

	return ret;
}

struct sm_state *get_ssa_sm_state_expr(int owner, struct expression *expr)
{
	struct sm_state *ret;
	struct symbol *sym;
	char *name;

	name = expr_to_var_sym(expr, &sym);
	if (!name)
		return NULL;
	ret = get_ssa_sm_state(owner, name, sym);
	free_string(name);
	return ret;
}

struct smatch_state *get_ssa_state(int owner, const char *name, struct symbol *sym)
{
	struct sm_state *sm;

	sm = get_ssa_sm_state(my_id, name, sym);
	if (!sm)
		return NULL;
	return sm->state;
}

struct smatch_state *get_ssa_state_expr(int owner, struct expression *expr)
{
	struct sm_state *sm;

	sm = get_ssa_sm_state_expr(my_id, expr);
	if (!sm)
		return NULL;
	return sm->state;
}

void register_ssa(int id)
{
	my_id = id;

	set_dynamic_states(my_id);
	add_hook(&match_assign, ASSIGNMENT_HOOK_AFTER);
	add_modification_hook(my_id, &set_undefined);
}

