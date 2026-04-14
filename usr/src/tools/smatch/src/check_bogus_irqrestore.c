/*
 * Copyright (C) 2011 Oracle.
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

static int my_id;

static bool was_set_in_spinlock_irqsave(struct expression *expr)
{
	struct expression *mod_expr;
	struct smatch_state *state;
	char *macro;

	state = get_modification_state(expr);
	if (!state || !state->data)
		return false;
	mod_expr = state->data;
	/* FIXME: why do we have a fake expression here??? */
	if (mod_expr->pos.line == 0 && mod_expr->pos.pos == 0)
		return true;
	macro = get_macro_name(mod_expr->pos);
	if (!macro)
		return false;
	if (strstr(macro, "save"))
		return true;
	return false;
}

static void match_irqrestore(const char *fn, struct expression *expr, void *_arg_nr)
{
	int arg_nr = PTR_INT(_arg_nr);
	struct expression *arg_expr;
	sval_t tmp;

	arg_expr = get_argument_from_call_expr(expr->args, arg_nr);
	if (!get_implied_value(arg_expr, &tmp))
		return;
	if (was_set_in_spinlock_irqsave(arg_expr))
		return;
	sm_error("calling '%s()' with bogus flags", fn);
}

void check_bogus_irqrestore(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;
	add_function_hook("spin_unlock_irqrestore", &match_irqrestore, INT_PTR(1));
}
