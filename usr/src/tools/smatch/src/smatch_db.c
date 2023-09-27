/*
 * Copyright (C) 2010 Dan Carpenter.
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include "smatch.h"
#include "smatch_slist.h"
#include "smatch_extra.h"

struct sqlite3 *smatch_db;
struct sqlite3 *mem_db;
struct sqlite3 *cache_db;

int debug_db;

STATE(incomplete);
static int my_id;

static int return_id;

static void call_return_state_hooks(struct expression *expr);
static void call_return_states_callbacks(const char *return_ranges, struct expression *expr);

#define SQLITE_CACHE_PAGES 1000

struct def_callback {
	int hook_type;
	void (*callback)(const char *name, struct symbol *sym, char *key, char *value);
};
ALLOCATOR(def_callback, "definition db hook callbacks");
DECLARE_PTR_LIST(callback_list, struct def_callback);
static struct callback_list *select_caller_info_callbacks;

struct def_name_sym_callback {
	int hook_type;
	void (*callback)(const char *name, struct symbol *sym, char *value);
};
ALLOCATOR(def_name_sym_callback, "definition db hook callbacks");
DECLARE_PTR_LIST(name_sym_callback_list, struct def_name_sym_callback);
static struct name_sym_callback_list *select_caller_name_sym_callbacks;

struct member_info_callback {
	int owner;
	void (*callback)(struct expression *call, int param, char *printed_name, struct sm_state *sm);
};
ALLOCATOR(member_info_callback, "caller_info callbacks");
DECLARE_PTR_LIST(member_info_cb_list, struct member_info_callback);
static struct member_info_cb_list *member_callbacks;
static struct member_info_cb_list *member_callbacks_new;

struct return_info_callback {
	int owner;
	void (*callback)(int return_id, char *return_ranges,
			 struct expression *returned_expr,
			 int param,
			 const char *printed_name,
			 struct sm_state *sm);
};
ALLOCATOR(return_info_callback, "return_info callbacks");
DECLARE_PTR_LIST(return_info_cb_list, struct return_info_callback);
static struct return_info_cb_list *return_callbacks;

struct returned_state_callback {
	void (*callback)(int return_id, char *return_ranges, struct expression *return_expr);
};
ALLOCATOR(returned_state_callback, "returned state callbacks");
DECLARE_PTR_LIST(returned_state_cb_list, struct returned_state_callback);
static struct returned_state_cb_list *returned_state_callbacks;

struct returned_member_callback {
	int owner;
	void (*callback)(int return_id, char *return_ranges, struct expression *expr, char *printed_name, struct smatch_state *state);
};
ALLOCATOR(returned_member_callback, "returned member callbacks");
DECLARE_PTR_LIST(returned_member_cb_list, struct returned_member_callback);
static struct returned_member_cb_list *returned_member_callbacks;

struct db_implies_callback {
	int type;
	void (*callback)(struct expression *call, struct expression *arg, char *key, char *value);
};
ALLOCATOR(db_implies_callback, "return_implies callbacks");
DECLARE_PTR_LIST(db_implies_cb_list, struct db_implies_callback);
static struct db_implies_cb_list *return_implies_cb_list_early;
static struct db_implies_cb_list *return_implies_cb_list_late;
static struct db_implies_cb_list *call_implies_cb_list;

DECLARE_PTR_LIST(delete_list, delete_hook);
static struct delete_list *delete_hooks;

struct split_data {
	const char *func, *rl;
};
static struct split_data **forced_splits;
static int split_count;

/* silently truncates if needed. */
char *escape_newlines(const char *str)
{
	char buf[1024] = "";
	bool found = false;
	int i, j;

	for (i = 0, j = 0; str[i] != '\0' && j != sizeof(buf); i++, j++) {
		if (str[i] != '\r' && str[i] != '\n') {
			buf[j] = str[i];
			continue;
		}

		found = true;
		buf[j++] = '\\';
		if (j == sizeof(buf))
			 break;
		buf[j] = 'n';
	}

	if (!found)
		return alloc_sname(str);

	if (j == sizeof(buf))
		buf[j - 1] = '\0';
	return alloc_sname(buf);
}

static int print_sql_output(void *unused, int argc, char **argv, char **azColName)
{
	int i;

	for (i = 0; i < argc; i++) {
		if (i != 0)
			sm_printf(", ");
		sm_printf("%s", argv[i]);
	}
	sm_printf("\n");
	return 0;
}

void sql_exec(struct sqlite3 *db, int (*callback)(void*, int, char**, char**), void *data, const char *sql)
{
	char *err = NULL;
	int rc;

	if (!db)
		return;

	if (option_debug || debug_db) {
		sm_msg("%s", sql);
		if (strncasecmp(sql, "select", strlen("select")) == 0)
			sqlite3_exec(db, sql, print_sql_output, NULL, NULL);
	}

	rc = sqlite3_exec(db, sql, callback, data, &err);
	if (rc != SQLITE_OK && !parse_error) {
		sm_ierror("%s:%d SQL error #2: %s\n", get_filename(), get_lineno(), err);
		sm_ierror("%s:%d SQL: '%s'\n", get_filename(), get_lineno(), sql);
		parse_error = 1;
	}
}

static int replace_count;
static char **replace_table;
static const char *replace_return_ranges(const char *return_ranges)
{
	int i;

	if (!get_function()) {
		/* I have no idea why EXPORT_SYMBOL() is here */
		return return_ranges;
	}
	for (i = 0; i < replace_count; i += 3) {
		if (strcmp(replace_table[i + 0], get_function()) == 0) {
			if (strcmp(replace_table[i + 1], return_ranges) == 0)
				return replace_table[i + 2];
		}
	}
	return return_ranges;
}

static int delete_count;
static char **delete_table;
static bool is_delete_return(const char *return_ranges)
{
	int i;

	if (!get_function())
		return false;

	for (i = 0; i < delete_count; i += 2) {
		if (strcmp(delete_table[i], get_function()) == 0 &&
		    strcmp(delete_table[i + 1], return_ranges) == 0)
			return true;
	}

	return false;
}

void add_delete_return_hook(delete_hook *hook)
{
	add_ptr_list(&delete_hooks, hook);
}

static bool is_project_delete_return(struct expression *expr)
{
	delete_hook *hook;

	FOR_EACH_PTR(delete_hooks, hook) {
		if (hook(expr))
			return true;
	} END_FOR_EACH_PTR(hook);
	return false;
}

static char *use_states;
static int get_db_state_count(void)
{
	struct sm_state *sm;
	int count = 0;

	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (sm->owner == USHRT_MAX)
			continue;
		if (use_states[sm->owner])
			count++;
	} END_FOR_EACH_SM(sm);
	return count;
}

static bool in_base_file(struct symbol *sym)
{
	return sym->pos.stream == base_file_stream;
}

static bool is_local(struct symbol *sym)
{
	if (sym->ctype.modifiers & MOD_STATIC)
		return true;
	if ((sym->ctype.modifiers & MOD_EXTERN) &&
	    (sym->ctype.modifiers & MOD_INLINE) &&
	    !in_base_file(sym))
		return true;

	if (!sym->definition)
		return false;

	if ((sym->definition->ctype.modifiers & MOD_EXTERN) &&
	    (sym->definition->ctype.modifiers & MOD_INLINE) &&
	    !in_base_file(sym->definition))
		return true;

	return false;
}

void db_ignore_states(int id)
{
	use_states[id] = 0;
}

unsigned long long __fn_mtag;
static void set_fn_mtag(struct symbol *sym)
{
	char buf[128];

	if (is_local(cur_func_sym))
		snprintf(buf, sizeof(buf), "%s %s", get_base_file(), get_function());
	else
		snprintf(buf, sizeof(buf), "extern %s", get_function());

	__fn_mtag = str_to_mtag(buf);
}

void sql_insert_return_states(int return_id, const char *return_ranges,
		int type, int param, const char *key, const char *value)
{
	unsigned long long id;


	if (key && strlen(key) >= 80)
		return;
	if (__inline_fn)
		id = (unsigned long)__inline_fn;
	else
		id = __fn_mtag;

	sql_insert(return_states, "0x%llx, '%s', %llu, %d, '%s', %d, %d, %d, '%s', '%s'",
		   get_base_file_id(), get_function(), id, return_id,
		   return_ranges, is_local(cur_func_sym), type, param, key, value);
}

static struct string_list *common_funcs;
static int is_common_function(const char *fn)
{
	char *tmp;

	if (!fn)
		return 0;

	if (strncmp(fn, "__builtin_", 10) == 0)
		return 1;

	FOR_EACH_PTR(common_funcs, tmp) {
		if (strcmp(tmp, fn) == 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static char *function_signature(void)
{
	return type_to_str(get_real_base_type(cur_func_sym));
}

void sql_insert_caller_info(struct expression *call, int type,
		int param, const char *key, const char *value)
{
	FILE *tmp_fd = sm_outfd;
	char *fn;

	if (!option_info && !__inline_call)
		return;
	if (unreachable())
		return;

	if (key && strlen(key) >= 80)
		return;

	fn = get_fnptr_name(call->fn);
	if (!fn)
		return;

	if (__inline_call) {
		mem_sql(NULL, NULL,
			"insert into caller_info values (0x%llx, '%s', '%s', %lu, %d, %d, %d, '%s', '%s');",
			get_base_file_id(), get_function(), fn, (unsigned long)call,
			is_static(call->fn), type, param, key, value);
	}

	if (!option_info)
		return;

	if (strncmp(fn, "__builtin_", 10) == 0)
		return;
	if (type != INTERNAL && is_common_function(fn))
		return;

	sm_outfd = caller_info_fd;
	sm_msg("SQL_caller_info: insert into caller_info values ("
	       "0x%llx, '%s', '%s', %%CALL_ID%%, %d, %d, %d, '%s', '%s');",
	       get_base_file_id(), get_function(), fn, is_static(call->fn),
	       type, param, key, value);
	sm_outfd = tmp_fd;

	free_string(fn);
}

void sql_insert_function_ptr(const char *fn, const char *struct_name)
{
	sql_insert_or_ignore(function_ptr, "0x%llx, '%s', '%s', 0",
			     get_base_file_id(), fn, struct_name);
}

void sql_insert_return_implies(int type, int param, const char *key, const char *value)
{
	unsigned long long id;

	if (__inline_fn)
		id = (unsigned long)__inline_fn;
	else
		id = __fn_mtag;

	sql_insert_or_ignore(return_implies, "0x%llx, '%s', %llu, %d, %d, %d, '%s', '%s'",
		get_base_file_id(), get_function(), id, fn_static(), type,
		param, key, value);
}

void sql_insert_call_implies(int type, int param, const char *key, const char *value)
{
	sql_insert_or_ignore(call_implies, "0x%llx, '%s', %lu, %d, %d, %d, '%s', '%s'",
		get_base_file_id(), get_function(), (unsigned long)__inline_fn,
		fn_static(), type, param, key, value);
}

void sql_insert_function_type_size(const char *member, const char *ranges)
{
	sql_insert(function_type_size, "0x%llx, '%s', '%s', '%s'", get_base_file_id(), get_function(), member, ranges);
}

void sql_insert_function_type_info(int type, const char *struct_type, const char *member, const char *value)
{
	sql_insert(function_type_info, "0x%llx, '%s', %d, '%s', '%s', '%s'", get_base_file_id(), get_function(), type, struct_type, member, value);
}

void sql_insert_type_info(int type, const char *member, const char *value)
{
	sql_insert_cache(type_info, "0x%llx, %d, '%s', '%s'", get_base_file_id(), type, member, value);
}

void sql_insert_local_values(const char *name, const char *value)
{
	sql_insert(local_values, "0x%llx, '%s', '%s'", get_base_file_id(), name, value);
}

void sql_insert_function_type_value(const char *type, const char *value)
{
	sql_insert(function_type_value, "0x%llx, '%s', '%s', '%s'", get_base_file_id(), get_function(), type, value);
}

void sql_insert_function_type(int param, const char *value)
{
	sql_insert(function_type, "0x%llx, '%s', %d, %d, '%s'",
		   get_base_file_id(), get_function(), fn_static(), param, value);
}

void sql_insert_parameter_name(int param, const char *value)
{
	sql_insert(parameter_name, "0x%llx, '%s', %d, %d, '%s'",
		   get_base_file_id(), get_function(), fn_static(), param, value);
}

void sql_insert_data_info(struct expression *data, int type, const char *value)
{
	char *data_name;

	data_name = get_data_info_name(data);
	if (!data_name)
		return;
	sql_insert(data_info, "0x%llx, '%s', %d, '%s'",
		   is_static(data) ? get_base_file_id() : 0,
		   data_name, type, value);
}

void sql_insert_data_info_var_sym(const char *var, struct symbol *sym, int type, const char *value)
{
	sql_insert(data_info, "0x%llx, '%s', %d, '%s'",
		   (sym->ctype.modifiers & MOD_STATIC) ? get_base_file_id() : 0,
		   var, type, value);
}

void sql_save_constraint(const char *con)
{
	if (!option_info)
		return;

        sm_msg("SQL: insert or ignore into constraints (str) values('%s');", escape_newlines(con));
}

void sql_save_constraint_required(const char *data, int op, const char *limit)
{
	sql_insert_or_ignore(constraints_required, "'%s', '%s', '%s'", data, show_special(op), limit);
}

void sql_copy_constraint_required(const char *new_limit, const char *old_limit)
{
	if (!option_info)
		return;

	sm_msg("SQL_late: insert or ignore into constraints_required (data, op, bound) "
		"select constraints_required.data, constraints_required.op, '%s' from "
		"constraints_required where bound = '%s';", new_limit, old_limit);
}

void sql_insert_fn_ptr_data_link(const char *ptr, const char *data)
{
	sql_insert_or_ignore(fn_ptr_data_link, "'%s', '%s'", ptr, data);
}

void sql_insert_fn_data_link(struct expression *fn, int type, int param, const char *key, const char *value)
{
	if (fn->type != EXPR_SYMBOL || !fn->symbol->ident)
		return;

	sql_insert(fn_data_link, "0x%llx, '%s', %d, %d, %d, '%s', '%s'",
		   is_local(fn->symbol) ? get_base_file_id() : 0,
		   fn->symbol->ident->name,
		   is_local(fn->symbol),
		   type, param, key, value);
}

void sql_insert_mtag_about(mtag_t tag, const char *left_name, const char *right_name)
{
	sql_insert_cache(mtag_about, "%lld, '%s', '%s', %d, '%s', '%s'",
			 tag, get_filename(), get_function(), get_lineno(),
			 left_name, right_name);
}

void sql_insert_mtag_info(mtag_t tag, int type, const char *value)
{
	sql_insert_cache(mtag_info, "'%s', %lld, %d, '%s'", get_filename(), tag, type, value);
}

void sql_insert_mtag_map(mtag_t container, int container_offset, mtag_t tag, int tag_offset)
{
	sql_insert(mtag_map, "%lld, %d, %lld, %d", container, container_offset, tag, tag_offset);
}

void sql_insert_mtag_alias(mtag_t orig, mtag_t alias)
{
	sql_insert(mtag_alias, "%lld, %lld", orig, alias);
}

static int save_mtag(void *_tag, int argc, char **argv, char **azColName)
{
	mtag_t *saved_tag = _tag;
	mtag_t new_tag;

	new_tag = strtoll(argv[0], NULL, 10);

	if (!*saved_tag)
		*saved_tag = new_tag;
	else if (*saved_tag != new_tag)
		*saved_tag = -1ULL;

	return 0;
}

int mtag_map_select_container(mtag_t tag, int container_offset, mtag_t *container)
{
	mtag_t tmp = 0;

	run_sql(save_mtag, &tmp,
		"select container from mtag_map where tag = %lld and container_offset = %d and tag_offset = 0;",
		tag, container_offset);

	if (tmp == 0 || tmp == -1ULL)
		return 0;
	*container = tmp;
	return 1;
}

int mtag_map_select_tag(mtag_t container, int offset, mtag_t *tag)
{
	mtag_t tmp = 0;

	run_sql(save_mtag, &tmp,
		"select tag from mtag_map where container = %lld and container_offset = %d;",
		container, offset);

	if (tmp == 0 || tmp == -1ULL)
		return 0;
	*tag = tmp;
	return 1;
}

char *get_static_filter(struct symbol *sym)
{
	static char sql_filter[1024];

	/* This can only happen on buggy code.  Return invalid SQL. */
	if (!sym) {
		sql_filter[0] = '\0';
		return sql_filter;
	}

	if (is_local(sym)) {
		snprintf(sql_filter, sizeof(sql_filter),
			 "file = 0x%llx and function = '%s' and static = '1'",
			 get_base_file_id(), sym->ident->name);
	} else {
		snprintf(sql_filter, sizeof(sql_filter),
			 "function = '%s' and static = '0'", sym->ident->name);
	}

	return sql_filter;
}

static int get_row_count(void *_row_count, int argc, char **argv, char **azColName)
{
	int *row_count = _row_count;

	*row_count = 0;
	if (argc != 1)
		return 0;
	*row_count = atoi(argv[0]);
	return 0;
}

static void sql_select_return_states_pointer(const char *cols,
	struct expression *call, int (*callback)(void*, int, char**, char**), void *info)
{
	char *ptr;
	int return_count = 0;

	ptr = get_fnptr_name(call->fn);
	if (!ptr)
		return;

	run_sql(get_row_count, &return_count,
		"select count(*) from return_states join function_ptr "
		"where return_states.function == function_ptr.function and "
		"ptr = '%s' and searchable = 1 and type = %d;", ptr, INTERNAL);
	/* The magic number 100 is just from testing on the kernel. */
	if (return_count == 0 || return_count > 100) {
		run_sql(callback, info,
			"select distinct %s from return_states join function_ptr where "
			"return_states.function == function_ptr.function and ptr = '%s' "
			"and searchable = 1 and type = %d "
			"order by function_ptr.file, return_states.file, return_id, type;",
			cols, ptr, INTERNAL);
		mark_call_params_untracked(call);
		return;
	}

	run_sql(callback, info,
		"select %s from return_states join function_ptr where "
		"return_states.function == function_ptr.function and ptr = '%s' "
		"and searchable = 1 "
		"order by function_ptr.file, return_states.file, return_id, type;",
		cols, ptr);
}

static int is_local_symbol(struct expression *expr)
{
	if (expr->type != EXPR_SYMBOL)
		return 0;
	if (expr->symbol->ctype.modifiers & (MOD_NONLOCAL | MOD_STATIC | MOD_ADDRESSABLE))
		return 0;
	return 1;
}

bool is_fn_ptr(struct expression *fn)
{
	fn = strip_expr(fn);
	if (fn->type != EXPR_SYMBOL)
		return true;
	if (!fn->symbol)
		return true;
	if (is_local_symbol(fn))
		return true;
	return false;
}

void sql_select_return_states(const char *cols, struct expression *call,
	int (*callback)(void*, int, char**, char**), void *info)
{
	struct expression *fn;
	int row_count = 0;

	if (is_fake_call(call))
		return;

	fn = strip_expr(call->fn);
	if (is_fn_ptr(fn)) {
		sql_select_return_states_pointer(cols, call, callback, info);
		return;
	}

	if (inlinable(fn)) {
		mem_sql(callback, info,
			"select %s from return_states where call_id = '%lu' order by return_id, type;",
			cols, (unsigned long)call);
		return;
	}

	run_sql(get_row_count, &row_count, "select count(*) from return_states where %s;",
		get_static_filter(fn->symbol));
	if (row_count == 0 && fn->symbol && fn->symbol->definition)
		set_state(my_id, "db_incomplete", NULL, &incomplete);
	if (row_count == 0 || row_count > 3000) {
		mark_call_params_untracked(call);
		return;
	}

	run_sql(callback, info, "select %s from return_states where %s order by file, return_id, type;",
		cols, get_static_filter(fn->symbol));
}

bool db_incomplete(void)
{
	return !!get_state(my_id, "db_incomplete", NULL);
}

#define CALL_IMPLIES 0
#define RETURN_IMPLIES 1

struct implies_info {
	int type;
	struct db_implies_cb_list *cb_list;
	struct expression *expr;
	struct symbol *sym;
};

void sql_select_implies(const char *cols, struct implies_info *info,
	int (*callback)(void*, int, char**, char**))
{
	if (info->type == RETURN_IMPLIES && inlinable(info->expr->fn)) {
		mem_sql(callback, info,
			"select %s from return_implies where call_id = '%lu';",
			cols, (unsigned long)info->expr);
		return;
	}

	run_sql(callback, info, "select %s from %s_implies where %s;",
		cols,
		info->type == CALL_IMPLIES ? "call" : "return",
		get_static_filter(info->sym));
}

struct select_caller_info_data {
	struct stree *final_states;
	struct timeval start_time;
	int prev_func_id;
	int ignore;
	int results;
};

static int caller_info_callback(void *_data, int argc, char **argv, char **azColName);

static void sql_select_caller_info(struct select_caller_info_data *data,
	const char *cols, struct symbol *sym)
{
	if (__inline_fn) {
		mem_sql(caller_info_callback, data,
			"select %s from caller_info where call_id = %lu;",
			cols, (unsigned long)__inline_fn);
		return;
	}

	if (is_common_function(sym->ident->name))
		return;
	run_sql(caller_info_callback, data,
		"select %s from common_caller_info where %s order by call_id;",
		cols, get_static_filter(sym));
	if (data->results)
		return;

	run_sql(caller_info_callback, data,
		"select %s from caller_info where %s order by call_id;",
		cols, get_static_filter(sym));
}

void select_caller_info_hook(void (*callback)(const char *name, struct symbol *sym, char *key, char *value), int type)
{
	struct def_callback *def_callback = __alloc_def_callback(0);

	def_callback->hook_type = type;
	def_callback->callback = callback;
	add_ptr_list(&select_caller_info_callbacks, def_callback);
}

void select_caller_name_sym(void (*fn)(const char *name, struct symbol *sym, char *value), int type)
{
	struct def_name_sym_callback *callback = __alloc_def_name_sym_callback(0);

	callback->hook_type = type;
	callback->callback = fn;
	add_ptr_list(&select_caller_name_sym_callbacks, callback);
}

/*
 * These call backs are used when the --info option is turned on to print struct
 * member information.  For example foo->bar could have a state in
 * smatch_extra.c and also check_user.c.
 */
void add_member_info_callback(int owner, void (*callback)(struct expression *call, int param, char *printed_name, struct sm_state *sm))
{
	struct member_info_callback *member_callback = __alloc_member_info_callback(0);

	member_callback->owner = owner;
	member_callback->callback = callback;
	add_ptr_list(&member_callbacks, member_callback);
}

void add_caller_info_callback(int owner, void (*callback)(struct expression *call, int param, char *printed_name, struct sm_state *sm))
{
	struct member_info_callback *member_callback = __alloc_member_info_callback(0);

	member_callback->owner = owner;
	member_callback->callback = callback;
	add_ptr_list(&member_callbacks_new, member_callback);
}

void add_return_info_callback(int owner,
			      void (*callback)(int return_id, char *return_ranges,
					       struct expression *returned_expr,
					       int param,
					       const char *printed_name,
					       struct sm_state *sm))
{
	struct return_info_callback *return_callback = __alloc_return_info_callback(0);

	return_callback->owner = owner;
	return_callback->callback = callback;
	add_ptr_list(&return_callbacks, return_callback);
}

void add_split_return_callback(void (*fn)(int return_id, char *return_ranges, struct expression *returned_expr))
{
	struct returned_state_callback *callback = __alloc_returned_state_callback(0);

	callback->callback = fn;
	add_ptr_list(&returned_state_callbacks, callback);
}

void add_returned_member_callback(int owner, void (*callback)(int return_id, char *return_ranges, struct expression *expr, char *printed_name, struct smatch_state *state))
{
	struct returned_member_callback *member_callback = __alloc_returned_member_callback(0);

	member_callback->owner = owner;
	member_callback->callback = callback;
	add_ptr_list(&returned_member_callbacks, member_callback);
}

void select_call_implies_hook(int type, void (*callback)(struct expression *call, struct expression *arg, char *key, char *value))
{
	struct db_implies_callback *cb = __alloc_db_implies_callback(0);

	cb->type = type;
	cb->callback = callback;
	add_ptr_list(&call_implies_cb_list, cb);
}

void select_return_implies_hook_early(int type, void (*callback)(struct expression *call, struct expression *arg, char *key, char *value))
{
	struct db_implies_callback *cb = __alloc_db_implies_callback(0);

	cb->type = type;
	cb->callback = callback;
	add_ptr_list(&return_implies_cb_list_early, cb);
}

void select_return_implies_hook(int type, void (*callback)(struct expression *call, struct expression *arg, char *key, char *value))
{
	struct db_implies_callback *cb = __alloc_db_implies_callback(0);

	cb->type = type;
	cb->callback = callback;
	add_ptr_list(&return_implies_cb_list_late, cb);
}

struct return_info {
	struct expression *static_returns_call;
	struct symbol *return_type;
	struct range_list *return_range_list;
};

static int db_return_callback(void *_ret_info, int argc, char **argv, char **azColName)
{
	struct return_info *ret_info = _ret_info;
	struct range_list *rl;
	struct expression *call_expr = ret_info->static_returns_call;

	if (argc != 1)
		return 0;
	call_results_to_rl(call_expr, ret_info->return_type, argv[0], &rl);
	ret_info->return_range_list = rl_union(ret_info->return_range_list, rl);
	return 0;
}

static struct expression *cached_expr, *cached_no_args;
static const char *cached_str;
static struct range_list *cached_rl, *cached_str_rl, *cached_no_args_rl;

static void clear_cached_return_vals(void)
{
	cached_expr = NULL;
	cached_rl = NULL;
	cached_str = NULL;
	cached_str_rl = NULL;
	cached_no_args = NULL;
	cached_no_args_rl = NULL;
}

struct range_list *db_return_vals(struct expression *expr)
{
	struct return_info ret_info = {};
	struct sm_state *sm;

	if (!expr)
		return NULL;

	if (is_fake_call(expr))
		return NULL;

	if (expr == cached_expr)
		return clone_rl(cached_rl);

	cached_expr = expr;
	cached_rl = NULL;

	sm = get_extra_sm_state(expr);
	if (sm) {
		cached_rl = clone_rl(estate_rl(sm->state));
		return clone_rl(estate_rl(sm->state));
	}
	ret_info.static_returns_call = expr;
	ret_info.return_type = get_type(expr);
	if (!ret_info.return_type)
		return NULL;

	if (expr->fn->type != EXPR_SYMBOL || !expr->fn->symbol)
		return NULL;

	ret_info.return_range_list = NULL;
	if (inlinable(expr->fn)) {
		mem_sql(db_return_callback, &ret_info,
			"select distinct return from return_states where call_id = '%lu';",
			(unsigned long)expr);
	} else {
		run_sql(db_return_callback, &ret_info,
			"select distinct return from return_states where %s;",
			get_static_filter(expr->fn->symbol));
	}
	cached_rl = clone_rl(ret_info.return_range_list);
	return ret_info.return_range_list;
}

struct range_list *db_return_vals_from_str(const char *fn_name)
{
	struct return_info ret_info;

	if (!fn_name)
		return NULL;
	if (fn_name == cached_str)
		return clone_rl(cached_str_rl);
	cached_str = fn_name;
	cached_str_rl = NULL;

	ret_info.static_returns_call = NULL;
	ret_info.return_type = &llong_ctype;
	ret_info.return_range_list = NULL;

	run_sql(db_return_callback, &ret_info,
		"select distinct return from return_states where function = '%s';",
		fn_name);
	cached_str_rl = clone_rl(ret_info.return_range_list);
	return ret_info.return_range_list;
}

/*
 * This is used when we have a function that takes a function pointer as a
 * parameter.  "frob(blah, blah, my_function);"  We know that the return values
 * from frob() come from my_funcion() so we want to find the possible returns
 * of my_function(), but we don't know which arguments are passed to it.
 *
 */
struct range_list *db_return_vals_no_args(struct expression *expr)
{
	struct return_info ret_info = {};

	if (!expr || expr->type != EXPR_SYMBOL)
		return NULL;

	if (expr == cached_no_args)
		return clone_rl(cached_no_args_rl);
	cached_no_args = expr;
	cached_no_args_rl = NULL;

	ret_info.static_returns_call = expr;
	ret_info.return_type = get_type(expr);
	ret_info.return_type = get_real_base_type(ret_info.return_type);
	if (!ret_info.return_type)
		return NULL;

	run_sql(db_return_callback, &ret_info,
		"select distinct return from return_states where %s;",
		get_static_filter(expr->symbol));

	cached_no_args_rl = clone_rl(ret_info.return_range_list);
	return ret_info.return_range_list;
}

static void match_call_marker(struct expression *expr)
{
	struct symbol *type;

	type = get_type(expr->fn);
	if (type && type->type == SYM_PTR)
		type = get_real_base_type(type);

	/*
	 * we just want to record something in the database so that if we have
	 * two calls like:  frob(4); frob(some_unkown); then on the receiving
	 * side we know that sometimes frob is called with unknown parameters.
	 */

	sql_insert_caller_info(expr, INTERNAL, -1, "%call_marker%", type_to_str(type));
}

int is_recursive_member(const char *name)
{
	char buf[256];
	const char *p, *next;
	int size;

	p = strchr(name, '>');
	if (!p)
		return 0;
	p++;
	while (true) {
		next = strchr(p, '>');
		if (!next)
			return 0;
		next++;

		size = next - p;
		if (size >= sizeof(buf))
			return 0;
		memcpy(buf, p, size);
		buf[size] = '\0';
		if (strstr(next, buf))
			return 1;
		p = next;
	}
}

char *sm_to_arg_name(struct expression *expr, struct sm_state *sm)
{
	struct symbol *sym;
	const char *sm_name;
	char *name;
	bool is_address = false;
	bool add_star = false;
	char buf[256];
	char *ret = NULL;
	int len;

	expr = strip_expr(expr);
	if (!expr)
		return NULL;

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		is_address = true;
	}

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	if (sym != sm->sym)
		goto free;

	sm_name = sm->name;
	add_star = false;
	if (sm_name[0] == '*') {
		add_star = true;
		sm_name++;
	}

	len = strlen(name);
	if (strncmp(name, sm_name, len) != 0)
		goto free;
	if (sm_name[len] == '\0') {
		snprintf(buf, sizeof(buf), "%s%s$",
			 add_star ? "*" : "", is_address ? "*" : "");
	} else {
		if (sm_name[len] != '.' && sm_name[len] != '-')
			goto free;
		if (sm_name[len] == '-')
			len++;
		// FIXME does is_address really imply that sm_name[len] == '-'
		snprintf(buf, sizeof(buf), "%s$->%s", add_star ? "*" : "",
			 sm_name + len);
	}

	ret = alloc_sname(buf);
free:
	free_string(name);
	return ret;
}

static void print_struct_members(struct expression *call, struct expression *expr, int param,
	int owner,
	void (*callback)(struct expression *call, int param, char *printed_name, struct sm_state *sm),
	bool new)
{
	struct sm_state *sm;
	const char *sm_name;
	char *name;
	struct symbol *sym;
	int len;
	char printed_name[256];
	int is_address = 0;
	bool add_star;
	struct symbol *type;

	expr = strip_expr(expr);
	if (!expr)
		return;
	type = get_type(expr);
	if (!new && type && type_bits(type) < type_bits(&ulong_ctype))
		return;

	if (expr->type == EXPR_PREOP && expr->op == '&') {
		expr = strip_expr(expr->unop);
		is_address = 1;
	}

	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;

	len = strlen(name);
	FOR_EACH_SM(__get_cur_stree(), sm) {
		if (sm->owner != owner || sm->sym != sym)
			continue;

		sm_name = sm->name;
		add_star = false;
		if (sm_name[0] == '*') {
			add_star = true;
			sm_name++;
		}
		// FIXME: simplify?
		if (!add_star && strcmp(name, sm_name) == 0) {
			if (is_address) {
				snprintf(printed_name, sizeof(printed_name), "*$");
			} else {
				if (new)
					snprintf(printed_name, sizeof(printed_name), "$");
				else
					continue;
			}
		} else if (add_star && strcmp(name, sm_name) == 0) {
			snprintf(printed_name, sizeof(printed_name), "%s*$",
				 is_address ? "*" : "");
		} else if (strncmp(name, sm_name, len) == 0) {
			if (sm_name[len] != '.' && sm_name[len] != '-')
				continue;
			if (is_address && sm_name[len] == '.') {
				snprintf(printed_name, sizeof(printed_name),
					 "%s$->%s", add_star ? "*" : "",
					 sm_name + len + 1);
			} else if (is_address && sm_name[len] == '-') {
				snprintf(printed_name, sizeof(printed_name),
					 "%s(*$)%s", add_star ? "*" : "",
					 sm_name + len);
			} else {
				snprintf(printed_name, sizeof(printed_name),
					 "%s$%s", add_star ? "*" : "",
					 sm_name + len);
			}
		} else if (sm_name[0] == '&' && strncmp(name, sm_name + 1, len) == 0) {
			if (sm_name[len + 1] != '.' && sm_name[len + 1] != '-')
				continue;
			if (is_address && sm_name[len + 1] == '.') {
				snprintf(printed_name, sizeof(printed_name),
					 "&%s$->%s", add_star ? "*" : "",
					 sm_name + len + 2);
			} else if (is_address && sm_name[len] == '-') {
				snprintf(printed_name, sizeof(printed_name),
					 "&%s(*$)%s", add_star ? "*" : "",
					 sm_name + len + 1);
			} else {
				snprintf(printed_name, sizeof(printed_name),
					 "&%s$%s", add_star ? "*" : "",
					 sm_name + len + 1);
			}
		} else {
			continue;
		}
		if (is_recursive_member(printed_name))
			continue;
		callback(call, param, printed_name, sm);
	} END_FOR_EACH_SM(sm);
free:
	free_string(name);
}

static void match_call_info(struct expression *call)
{
	struct member_info_callback *cb;
	struct expression *arg;
	int i;

	FOR_EACH_PTR(member_callbacks, cb) {
		i = -1;
		FOR_EACH_PTR(call->args, arg) {
			i++;
			print_struct_members(call, arg, i, cb->owner, cb->callback, 0);
		} END_FOR_EACH_PTR(arg);
	} END_FOR_EACH_PTR(cb);
}

static struct expression *get_fake_variable(struct expression *expr)
{
	struct expression *tmp;

	tmp = expr_get_fake_parent_expr(expr);
	if (!tmp || tmp->type != EXPR_ASSIGNMENT)
		return NULL;

	return tmp->left;
}

static struct sm_state *get_returned_sm(struct expression *expr)
{
	struct expression *fake;

	fake = get_fake_variable(expr);
	if (fake)
		expr = fake;

	return get_sm_state_expr(SMATCH_EXTRA, expr);
}

static void match_call_info_new(struct expression *call)
{
	struct member_info_callback *cb;
	struct expression *arg, *tmp;
	int i;

	if (!option_info && !__inline_call && !local_debug)
		return;

	FOR_EACH_PTR(member_callbacks_new, cb) {
		i = -1;
		FOR_EACH_PTR(call->args, arg) {
			i++;
			tmp = get_fake_variable(arg);
			if (!tmp)
				tmp = arg;
			__ignore_param_used++;
			print_struct_members(call, tmp, i, cb->owner, cb->callback, 1);
			__ignore_param_used--;
		} END_FOR_EACH_PTR(arg);
	} END_FOR_EACH_PTR(cb);
}

static int get_param(int param, char **name, struct symbol **sym)
{
	struct symbol *arg;
	int i;

	i = 0;
	FOR_EACH_PTR(cur_func_sym->ctype.base_type->arguments, arg) {
		if (i == param) {
			*name = arg->ident->name;
			*sym = arg;
			return TRUE;
		}
		i++;
	} END_FOR_EACH_PTR(arg);

	return FALSE;
}

static int function_signature_matches(const char *sig)
{
	char *my_sig;

	my_sig = function_signature();
	if (!sig || !my_sig)
		return 1;  /* default to matching */
	if (strcmp(my_sig, sig) == 0)
		  return 1;
	return 0;
}

static int caller_info_callback(void *_data, int argc, char **argv, char **azColName)
{
	struct select_caller_info_data *data = _data;
	int func_id;
	long type;
	long param;
	char *key;
	char *value;
	char *name = NULL;
	struct symbol *sym = NULL;
	struct def_callback *def_callback;
	struct def_name_sym_callback *ns_callback;
	struct stree *stree;
	struct timeval cur_time;
	char fullname[256];
	char *p;

	data->results = 1;

	if (argc != 5)
		return 0;

	gettimeofday(&cur_time, NULL);
	if (cur_time.tv_sec - data->start_time.tv_sec > 10)
		return 0;

	func_id = atoi(argv[0]);
	errno = 0;
	type = strtol(argv[1], NULL, 10);
	param = strtol(argv[2], NULL, 10);
	if (errno)
		return 0;
	key = argv[3];
	value = argv[4];

	if (data->prev_func_id == -1)
		data->prev_func_id = func_id;
	if (func_id != data->prev_func_id) {
		stree = __pop_fake_cur_stree();
		if (!data->ignore)
			merge_stree(&data->final_states, stree);
		free_stree(&stree);
		__push_fake_cur_stree();
		__unnullify_path();
		data->prev_func_id = func_id;
		data->ignore = 0;
	}

	if (data->ignore)
		return 0;
	if (type == INTERNAL &&
	    !function_signature_matches(value)) {
		data->ignore = 1;
		return 0;
	}

	if (param >= 0 && !get_param(param, &name, &sym))
		return 0;

	FOR_EACH_PTR(select_caller_info_callbacks, def_callback) {
		if (def_callback->hook_type == type)
			def_callback->callback(name, sym, key, value);
	} END_FOR_EACH_PTR(def_callback);

	p = strchr(key, '$');
	if (name && p)
		snprintf(fullname, sizeof(fullname), "%.*s%s%s", (int)(p - key), key, name, p + 1);
	else
		snprintf(fullname, sizeof(fullname), "%s", key);

	FOR_EACH_PTR(select_caller_name_sym_callbacks, ns_callback) {
		if (ns_callback->hook_type == type)
			ns_callback->callback(fullname, sym, value);
	} END_FOR_EACH_PTR(ns_callback);

	return 0;
}

static struct string_list *ptr_names_done;
static struct string_list *ptr_names;

static int get_ptr_name(void *unused, int argc, char **argv, char **azColName)
{
	insert_string(&ptr_names, alloc_string(argv[0]));
	return 0;
}

static char *get_next_ptr_name(void)
{
	char *ptr;

	FOR_EACH_PTR(ptr_names, ptr) {
		if (!insert_string(&ptr_names_done, ptr))
			continue;
		return ptr;
	} END_FOR_EACH_PTR(ptr);
	return NULL;
}

static void get_ptr_names(unsigned long long file, const char *name)
{
	char sql_filter[1024];
	int before, after;

	if (file) {
		snprintf(sql_filter, 1024, "file = 0x%llx and function = '%s';",
			 file, name);
	} else {
		snprintf(sql_filter, 1024, "function = '%s';", name);
	}

	before = ptr_list_size((struct ptr_list *)ptr_names);

	run_sql(get_ptr_name, NULL,
		"select distinct ptr from function_ptr where %s",
		sql_filter);

	after = ptr_list_size((struct ptr_list *)ptr_names);
	if (before == after)
		return;

	while ((name = get_next_ptr_name()))
		get_ptr_names(0, name);
}

static void match_data_from_db(struct symbol *sym)
{
	struct select_caller_info_data data = { .prev_func_id = -1 };
	struct sm_state *sm;
	struct stree *stree;
	struct timeval end_time;

	if (!sym || !sym->ident)
		return;

	set_fn_mtag(sym);
	gettimeofday(&data.start_time, NULL);

	__push_fake_cur_stree();
	__unnullify_path();

	if (!__inline_fn) {
		char *ptr;

		if (sym->ctype.modifiers & MOD_STATIC)
			get_ptr_names(get_base_file_id(), sym->ident->name);
		else
			get_ptr_names(0, sym->ident->name);

		if (ptr_list_size((struct ptr_list *)ptr_names) > 20) {
			__free_ptr_list((struct ptr_list **)&ptr_names);
			__free_ptr_list((struct ptr_list **)&ptr_names_done);
			__free_fake_cur_stree();
			return;
		}

		sql_select_caller_info(&data,
				       "call_id, type, parameter, key, value",
				       sym);


		stree = __pop_fake_cur_stree();
		if (!data.ignore)
			merge_stree(&data.final_states, stree);
		free_stree(&stree);
		__push_fake_cur_stree();
		__unnullify_path();
		data.prev_func_id = -1;
		data.ignore = 0;
		data.results = 0;

		FOR_EACH_PTR(ptr_names, ptr) {
			run_sql(caller_info_callback, &data,
				"select call_id, type, parameter, key, value"
				" from common_caller_info where function = '%s' order by call_id",
				ptr);
		} END_FOR_EACH_PTR(ptr);

		if (data.results) {
			FOR_EACH_PTR(ptr_names, ptr) {
				free_string(ptr);
			} END_FOR_EACH_PTR(ptr);
			goto free_ptr_names;
		}

		FOR_EACH_PTR(ptr_names, ptr) {
			run_sql(caller_info_callback, &data,
				"select call_id, type, parameter, key, value"
				" from caller_info where function = '%s' order by call_id",
				ptr);
			free_string(ptr);
		} END_FOR_EACH_PTR(ptr);

free_ptr_names:
		__free_ptr_list((struct ptr_list **)&ptr_names);
		__free_ptr_list((struct ptr_list **)&ptr_names_done);
	} else {
		sql_select_caller_info(&data,
				       "call_id, type, parameter, key, value",
				       sym);
	}

	stree = __pop_fake_cur_stree();
	if (!data.ignore)
		merge_stree(&data.final_states, stree);
	free_stree(&stree);

	gettimeofday(&end_time, NULL);
	if (end_time.tv_sec - data.start_time.tv_sec <= 10) {
		FOR_EACH_SM(data.final_states, sm) {
			__set_sm(sm);
		} END_FOR_EACH_SM(sm);
	}

	free_stree(&data.final_states);
}

static int return_implies_callbacks(void *_info, int argc, char **argv, char **azColName)
{
	struct implies_info *info = _info;
	struct db_implies_callback *cb;
	struct expression *arg = NULL;
	int type;
	int param;

	if (argc != 5)
		return 0;

	type = atoi(argv[1]);
	param = atoi(argv[2]);

	/* The caller doesn't pass the assignment so -1 can't be useful */
	if (param == -1)
		return 0;
	if (param >= 0) {
		arg = get_argument_from_call_expr(info->expr->args, param);
		if (!arg)
			return 0;
	}

	FOR_EACH_PTR(info->cb_list, cb) {
		if (cb->type != type)
			continue;
		cb->callback(info->expr, arg, argv[3], argv[4]);
	} END_FOR_EACH_PTR(cb);

	return 0;
}

static int call_implies_callbacks(void *_info, int argc, char **argv, char **azColName)
{
	struct implies_info *info = _info;
	struct db_implies_callback *cb;
	struct expression *arg;
	struct symbol *sym;
	char *name;
	int type;
	int param;

	if (argc != 5)
		return 0;

	type = atoi(argv[1]);
	param = atoi(argv[2]);

	if (!get_param(param, &name, &sym))
		return 0;
	arg = symbol_expression(sym);
	if (!arg)
		return 0;

	FOR_EACH_PTR(info->cb_list, cb) {
		if (cb->type != type)
			continue;
		cb->callback(info->expr, arg, argv[3], argv[4]);
	} END_FOR_EACH_PTR(cb);

	return 0;
}

static void match_return_implies_helper(struct expression *expr, struct db_implies_cb_list *cb_list)
{
	struct implies_info info = {
		.type = RETURN_IMPLIES,
		.cb_list = cb_list,
	};

	if (expr->fn->type != EXPR_SYMBOL ||
	    !expr->fn->symbol)
		return;
	info.expr = expr;
	info.sym = expr->fn->symbol;
	sql_select_implies("function, type, parameter, key, value", &info,
			   return_implies_callbacks);
}

static void match_return_implies_early(struct expression *expr)
{
	match_return_implies_helper(expr, return_implies_cb_list_early);
}

static void match_return_implies_late(struct expression *expr)
{
	match_return_implies_helper(expr, return_implies_cb_list_late);
}

static void match_call_implies(struct symbol *sym)
{
	struct implies_info info = {
		.type = CALL_IMPLIES,
		.cb_list = call_implies_cb_list,
	};

	if (!sym || !sym->ident)
		return;

	info.sym = sym;
	sql_select_implies("function, type, parameter, key, value", &info,
			   call_implies_callbacks);
}

static char *get_fn_param_str(struct expression *expr)
{
	struct expression *tmp;
	int param;
	char buf[32];

	tmp = get_assigned_expr(expr);
	if (tmp)
		expr = tmp;
	expr = strip_expr(expr);
	if (!expr || expr->type != EXPR_CALL)
		return NULL;
	expr = strip_expr(expr->fn);
	if (!expr || expr->type != EXPR_SYMBOL)
		return NULL;
	param = get_param_num(expr);
	if (param < 0)
		return NULL;

	snprintf(buf, sizeof(buf), "[r $%d]", param);
	return alloc_sname(buf);
}

static char *get_return_compare_is_param(struct expression *expr)
{
	char *var;
	char buf[256];
	int comparison;
	int param;

	param = get_param_num(expr);
	if (param < 0)
		return NULL;

	var = expr_to_var(expr);
	if (!var)
		return NULL;
	snprintf(buf, sizeof(buf), "%s orig", var);
	comparison = get_comparison_strings(var, buf);
	free_string(var);

	if (!comparison)
		return NULL;

	snprintf(buf, sizeof(buf), "[%s$%d]", show_special(comparison), param);
	return alloc_sname(buf);
}

static char *get_return_compare_str(struct expression *expr)
{
	char *compare_str;

	compare_str = get_return_compare_is_param(expr);
	if (compare_str)
		return compare_str;

	compare_str = expr_lte_to_param(expr, -1);
	if (compare_str)
		return compare_str;

	return expr_param_comparison(expr, -1);
}

static const char *get_return_ranges_str(struct expression *expr, struct range_list **rl_p)
{
	struct expression *fake;
	struct range_list *rl;
	const char *return_ranges;
	sval_t sval;
	const char *container_of_str;
	const char *math_str;
	char *fn_param_str;
	char *compare_str;
	char buf[128];

	*rl_p = NULL;

	if (!expr)
		return alloc_sname("");

	fake = get_fake_variable(expr);
	if (fake)
		expr = fake;

	container_of_str = get_container_of_str(expr);

	if (get_implied_value(expr, &sval)) {
		sval = sval_cast(cur_func_return_type(), sval);
		*rl_p = alloc_rl(sval, sval);
		return_ranges = sval_to_str_or_err_ptr(sval);
		if (container_of_str) {
			snprintf(buf, sizeof(buf), "%s[%s]", return_ranges, container_of_str);
			return alloc_sname(buf);
		}
		return return_ranges;
	}

	fn_param_str = get_fn_param_str(expr);
	math_str = get_param_key_swap_dollar(expr);
	compare_str = expr_equal_to_param(expr, -1);
	if (!math_str)
		math_str = get_value_in_terms_of_parameter_math(expr);

	if (get_implied_rl(expr, &rl) && !is_whole_rl(rl)) {
		rl = cast_rl(cur_func_return_type(), rl);
		return_ranges = show_rl(rl);
	} else if (get_imaginary_absolute(expr, &rl)){
		rl = cast_rl(cur_func_return_type(), rl);
		return alloc_sname(show_rl(rl));
	} else {
		get_absolute_rl(expr, &rl);
		rl = cast_rl(cur_func_return_type(), rl);
		return_ranges = show_rl(rl);
	}
	*rl_p = rl;

	if (container_of_str) {
		snprintf(buf, sizeof(buf), "%s[%s]", return_ranges, container_of_str);
		return alloc_sname(buf);
	}
	if (fn_param_str) {
		snprintf(buf, sizeof(buf), "%s%s", return_ranges, fn_param_str);
		return alloc_sname(buf);
	}
	if (compare_str) {
		snprintf(buf, sizeof(buf), "%s%s", return_ranges, compare_str);
		return alloc_sname(buf);
	}
	if (math_str) {
		snprintf(buf, sizeof(buf), "%s[%s]", return_ranges, math_str);
		return alloc_sname(buf);
	}
	compare_str = get_return_compare_str(expr);
	if (compare_str) {
		snprintf(buf, sizeof(buf), "%s%s", return_ranges, compare_str);
		return alloc_sname(buf);
	}

	return return_ranges;
}

static void match_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	sql_insert_return_states(return_id, return_ranges, INTERNAL, -1, "", function_signature());
}

static bool call_return_state_hooks_conditional(struct expression *expr)
{
	int final_pass_orig = final_pass;
	static int recurse;

	if (recurse >= 2)
		return false;
	if (!expr ||
	    (expr->type != EXPR_CONDITIONAL && expr->type != EXPR_SELECT))
		return false;

	recurse++;

	__push_fake_cur_stree();

	final_pass = 0;
	__split_whole_condition(expr->conditional);
	final_pass = final_pass_orig;

	call_return_state_hooks(expr->cond_true ?: expr->conditional);

	__push_true_states();
	__use_false_states();

	call_return_state_hooks(expr->cond_false);

	__merge_true_states();
	__free_fake_cur_stree();

	recurse--;
	return true;
}

static bool handle_forced_split(const char *return_ranges, struct expression *expr)
{
	struct split_data *data = NULL;
	struct expression *compare;
	struct range_list *rl;
	char buf[64];
	char *math;
	sval_t sval;
	bool undo;
	int i;

	for (i = 0; i < split_count; i++) {
		if (get_function() &&
		    strcmp(get_function(), forced_splits[i]->func) == 0) {
			data = forced_splits[i];
			break;
		}
	}
	if (!data)
		return false;

	// FIXME: this works for copy_to/from_user() because the only thing we
	// care about is zero/non-zero
	if (strcmp(data->rl, "0") != 0)
		return false;

	compare = compare_expression(expr, SPECIAL_EQUAL, zero_expr());
	if (!compare)
		return false;
	if (get_implied_value(compare, &sval))
		return false;

	undo = assume(compare_expression(expr, SPECIAL_EQUAL, zero_expr()));
	call_return_states_callbacks("0", expr);
	if (undo)
		end_assume();

	undo = assume(compare_expression(expr, SPECIAL_NOTEQUAL, zero_expr()));
	if (get_implied_rl(expr, &rl)) {
		math = strchr(return_ranges, '[');
		snprintf(buf, sizeof(buf), "%s%s", show_rl(rl), math ?: "");
	} else {
		snprintf(buf, sizeof(buf), "%s", return_ranges);
	}
	call_return_states_callbacks(buf, expr);
	if (undo)
		end_assume();

	return true;
}

static void call_return_states_callbacks(const char *return_ranges, struct expression *expr)
{
	struct returned_state_callback *cb;

	return_ranges = replace_return_ranges(return_ranges);
	if (is_delete_return(return_ranges))
		return;
	if (is_project_delete_return(expr))
		return;
	if (handle_forced_split(return_ranges, expr))
		return;

	return_id++;
	FOR_EACH_PTR(returned_state_callbacks, cb) {
		cb->callback(return_id, (char *)return_ranges, expr);
	} END_FOR_EACH_PTR(cb);
}

static void call_return_state_hooks_compare(struct expression *expr)
{
	char *return_ranges;
	int final_pass_orig = final_pass;
	sval_t sval = { .type = &int_ctype };
	sval_t ret;

	if (!get_implied_value(expr, &ret))
		ret.value = -1;

	__push_fake_cur_stree();

	final_pass = 0;
	__split_whole_condition(expr);
	final_pass = final_pass_orig;

	if (ret.value != 0) {
		return_ranges = alloc_sname("1");
		sval.value = 1;
		set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_sval(sval));

		call_return_states_callbacks(return_ranges, expr);
	}

	__push_true_states();
	__use_false_states();

	if (ret.value != 1) {
		return_ranges = alloc_sname("0");
		sval.value = 0;
		set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_sval(sval));

		call_return_states_callbacks(return_ranges, expr);
	}

	__merge_true_states();
	__free_fake_cur_stree();
}

static bool is_implies_function(struct expression *expr)
{
	struct range_list *rl;

	if (!expr)
		return false;

	rl = get_range_implications(get_function());
	if (!rl)
		return false;

	sm_msg("%s: is implied", __func__);
	return true;
}

static int ptr_in_list(struct sm_state *sm, struct state_list *slist)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(slist, tmp) {
		if (strcmp(tmp->state->name, sm->state->name) == 0)
			return 1;
	} END_FOR_EACH_PTR(tmp);

	return 0;
}

static int split_possible_helper(struct sm_state *sm, struct expression *expr)
{
	struct range_list *rl;
	char *return_ranges;
	struct sm_state *tmp;
	int ret = 0;
	int nr_possible, nr_states;
	char *compare_str;
	char buf[128];
	struct state_list *already_handled = NULL;
	sval_t sval;

	if (!sm || !sm->merged)
		return 0;

	if (too_many_possible(sm) && !is_implies_function(expr))
		return 0;

	/* bail if it gets too complicated */
	nr_possible = 0;
	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->merged)
			continue;
		if (ptr_in_list(tmp, already_handled))
			continue;
		add_ptr_list(&already_handled, tmp);
		nr_possible++;
	} END_FOR_EACH_PTR(tmp);
	free_slist(&already_handled);
	nr_states = get_db_state_count();
	if (nr_states * nr_possible >= 2000 && !is_implies_function(expr))
		return 0;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (!is_leaf(tmp))
			continue;
		if (ptr_in_list(tmp, already_handled))
			continue;
		add_ptr_list(&already_handled, tmp);

		ret = 1;
		__push_fake_cur_stree();

		overwrite_states_using_pool(sm, tmp);

		rl = cast_rl(cur_func_return_type(), estate_rl(tmp->state));
		return_ranges = show_rl(rl);
		set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(clone_rl(rl)));
		compare_str = get_return_compare_str(expr);
		/* ignore obvious stuff like 0 <= param */
		/* Is this worthile when we have PARAM_COMPARE? */
		if (compare_str &&
		    strncmp(compare_str, "[=", 2) != 0 &&
		    rl_to_sval(rl, &sval))
			compare_str = NULL;
		if (compare_str) {
			snprintf(buf, sizeof(buf), "%s%s", return_ranges, compare_str);
			return_ranges = alloc_sname(buf);
		}

		call_return_states_callbacks(return_ranges, expr);

		__free_fake_cur_stree();
	} END_FOR_EACH_PTR(tmp);

	free_slist(&already_handled);

	return ret;
}

static int call_return_state_hooks_split_possible(struct expression *expr)
{
	struct sm_state *sm;

	if (!expr)
		return 0;

	sm = get_returned_sm(expr);
	return split_possible_helper(sm, expr);
}

static bool has_empty_state(struct sm_state *sm)
{
	struct sm_state *tmp;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (!estate_rl(tmp->state))
			return true;
	} END_FOR_EACH_PTR(tmp);

	return false;
}

static bool has_possible_negative(struct sm_state *sm)
{
	struct sm_state *tmp;

	if (!type_signed(estate_type(sm->state)))
		return false;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (!estate_rl(tmp->state))
			continue;
		if (sval_is_negative(estate_min(tmp->state)) &&
		    sval_is_negative(estate_max(tmp->state)))
			return true;
	} END_FOR_EACH_PTR(tmp);

	return false;
}

static bool has_separate_zero_null(struct sm_state *sm)
{
	struct sm_state *tmp;
	sval_t sval;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (!estate_get_single_value(tmp->state, &sval))
			continue;
		if (sval.value == 0)
			return true;
	} END_FOR_EACH_PTR(tmp);

	return false;
}

static int split_positive_from_negative(struct expression *expr)
{
	struct sm_state *sm;
	struct range_list *rl;
	const char *return_ranges;
	struct range_list *ret_rl;
	bool separate_zero;
	int undo;

	/* We're going to print the states 3 times */
	if (get_db_state_count() > 10000 / 3)
		return 0;

	if (!get_implied_rl(expr, &rl) || !rl)
		return 0;
	/* Forget about INT_MAX and larger */
	if (rl_max(rl).value <= 0)
		return 0;
	if (!sval_is_negative(rl_min(rl)))
		return 0;

	sm = get_returned_sm(expr);
	if (!sm)
		return 0;
	if (has_empty_state(sm))
		return 0;
	if (!has_possible_negative(sm))
		return 0;
	separate_zero = has_separate_zero_null(sm);

	if (!assume(compare_expression(expr, separate_zero ? '>' : SPECIAL_GTE, zero_expr())))
		return 0;

	return_ranges = get_return_ranges_str(expr, &ret_rl);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(ret_rl));
	call_return_states_callbacks(return_ranges, expr);

	end_assume();

	if (separate_zero) {
		undo = assume(compare_expression(expr, SPECIAL_EQUAL, zero_expr()));

		return_ranges = get_return_ranges_str(expr, &ret_rl);
		set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(ret_rl));
		call_return_states_callbacks(return_ranges, expr);

		if (undo)
			end_assume();
	}

	undo = assume(compare_expression(expr, '<', zero_expr()));

	return_ranges = get_return_ranges_str(expr, &ret_rl);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(ret_rl));
	call_return_states_callbacks(return_ranges, expr);

	if (undo)
		end_assume();

	return 1;
}

static int call_return_state_hooks_split_null_non_null_zero(struct expression *expr)
{
	struct range_list *rl;
	struct range_list *nonnull_rl;
	sval_t null_sval;
	struct range_list *null_rl = NULL;
	char *return_ranges;
	struct sm_state *sm;
	struct smatch_state *state;
	int nr_states;
	int final_pass_orig = final_pass;

	if (!expr || expr_equal_to_param(expr, -1))
		return 0;
	if (expr->type == EXPR_CALL)
		return 0;

	sm = get_returned_sm(expr);
	if (!sm)
		return 0;
	if (ptr_list_size((struct ptr_list *)sm->possible) == 1)
		return 0;
	state = sm->state;
	if (!estate_rl(state))
		return 0;
	if (estate_min(state).value == 0 && estate_max(state).value == 0)
		return 0;
	if (has_possible_negative(sm))
		return 0;
	if (!has_separate_zero_null(sm))
		return 0;

	nr_states = get_db_state_count();
	if (option_info && nr_states >= 1500)
		return 0;

	rl = estate_rl(state);

	__push_fake_cur_stree();

	final_pass = 0;
	__split_whole_condition(expr);
	final_pass = final_pass_orig;

	nonnull_rl = rl_filter(rl, rl_zero());
	return_ranges = show_rl(nonnull_rl);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(nonnull_rl));

	call_return_states_callbacks(return_ranges, expr);

	__push_true_states();
	__use_false_states();

	return_ranges = alloc_sname("0");
	null_sval = sval_type_val(rl_type(rl), 0);
	add_range(&null_rl, null_sval, null_sval);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(null_rl));
	call_return_states_callbacks(return_ranges, expr);

	__merge_true_states();
	__free_fake_cur_stree();

	return 1;
}

static bool is_neg_and_pos_err_code(struct range_list *rl)
{
	struct data_range *tmp, *last;

	if (option_project != PROJ_KERNEL)
		return false;
	if (!rl)
		return false;

	/* Assume s32min-(14),(-12)-(-1),1-s32max is an error code. */
	last = last_ptr_list((struct ptr_list *)rl);
	if (last->max.value >= 0 &&
	    (last->min.value != 1 ||
	     last->max.value != INT_MAX))
		return false;


	FOR_EACH_PTR(rl, tmp) {
		if (tmp == last)
			break;
		if (tmp->min.value != INT_MIN && tmp->min.value < -4095)
			return false;
		if (tmp->max.value < -4095 || tmp->max.value >= 0)
			return false;
	} END_FOR_EACH_PTR(tmp);

	return true;
}

static bool is_kernel_success_fail(struct sm_state *sm)
{
	struct sm_state *tmp;
	struct range_list *rl;
	bool has_zero = false;
	bool has_neg = false;

	if (!sm)
		return false;

	if (!type_signed(estate_type(sm->state)))
		return false;

	FOR_EACH_PTR(sm->possible, tmp) {
		rl = estate_rl(tmp->state);
		if (!rl)
			return false;
		if (!is_leaf(tmp))
			continue;
		if (rl_min(rl).value == 0 && rl_max(rl).value == 0) {
			has_zero = true;
			continue;
		}
		has_neg = true;
		if (is_neg_and_pos_err_code(estate_rl(tmp->state)))
			continue;
		return false;
	} END_FOR_EACH_PTR(tmp);

	return has_zero && has_neg;
}

static int call_return_state_hooks_split_success_fail(struct expression *expr)
{
	struct expression *tmp_ret;
	struct sm_state *sm;
	struct range_list *rl;
	struct range_list *nonzero_rl;
	sval_t zero_sval;
	struct range_list *zero_rl = NULL;
	int nr_states;
	char *return_ranges;
	int final_pass_orig = final_pass;

	if (option_project != PROJ_KERNEL)
		return 0;

	nr_states = get_db_state_count();
	if (nr_states > 2000)
		return 0;

	tmp_ret = get_fake_variable(expr);
	if (!tmp_ret)
		tmp_ret = expr;
	sm = get_returned_sm(tmp_ret);
	if (!sm)
		return 0;
	if (ptr_list_size((struct ptr_list *)sm->possible) == 1)
		return 0;
	if (!is_kernel_success_fail(sm))
		return 0;

	rl = estate_rl(sm->state);
	if (!rl)
		return 0;

	__push_fake_cur_stree();

	final_pass = 0;
	__split_whole_condition(tmp_ret);
	final_pass = final_pass_orig;

	nonzero_rl = rl_filter(rl, rl_zero());
	nonzero_rl = cast_rl(cur_func_return_type(), nonzero_rl);
	return_ranges = show_rl(nonzero_rl);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(nonzero_rl));

	call_return_states_callbacks(return_ranges, expr);

	__push_true_states();
	__use_false_states();

	return_ranges = alloc_sname("0");
	zero_sval = sval_type_val(rl_type(rl), 0);
	add_range(&zero_rl, zero_sval, zero_sval);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(zero_rl));
	call_return_states_callbacks(return_ranges, expr);

	__merge_true_states();
	__free_fake_cur_stree();

	return 1;
}

static int is_boolean(struct expression *expr)
{
	struct range_list *rl;

	if (!get_implied_rl(expr, &rl))
		return 0;
	if (rl_min(rl).value == 0 && rl_max(rl).value == 1)
		return 1;
	return 0;
}

static int splitable_function_call(struct expression *expr)
{
	struct sm_state *sm;

	if (!expr || expr->type != EXPR_CALL)
		return 0;
	sm = get_extra_sm_state(expr);
	return split_possible_helper(sm, expr);
}

static struct sm_state *find_bool_param(void)
{
	struct stree *start_states;
	struct symbol *arg;
	struct sm_state *sm, *tmp;
	sval_t sval;

	start_states = get_start_states();

	FOR_EACH_PTR_REVERSE(cur_func_sym->ctype.base_type->arguments, arg) {
		if (!arg->ident)
			continue;
		sm = get_sm_state_stree(start_states, SMATCH_EXTRA, arg->ident->name, arg);
		if (!sm)
			continue;
		if (rl_min(estate_rl(sm->state)).value != 0 ||
		    rl_max(estate_rl(sm->state)).value != 1)
			continue;
		goto found;
	} END_FOR_EACH_PTR_REVERSE(arg);

	return NULL;

found:
	/*
	 * Check if it's splitable.  If not, then splitting it up is likely not
	 * useful for the callers.
	 */
	FOR_EACH_PTR(sm->possible, tmp) {
		if (is_merged(tmp))
			continue;
		if (!estate_get_single_value(tmp->state, &sval))
			return NULL;
	} END_FOR_EACH_PTR(tmp);

	return sm;
}

static int split_on_bool_sm(struct sm_state *sm, struct expression *expr)
{
	struct range_list *ret_rl;
	const char *return_ranges;
	struct sm_state *tmp;
	int ret = 0;
	struct state_list *already_handled = NULL;

	if (!sm || !sm->merged)
		return 0;

	if (too_many_possible(sm))
		return 0;

	FOR_EACH_PTR(sm->possible, tmp) {
		if (tmp->merged)
			continue;
		if (ptr_in_list(tmp, already_handled))
			continue;
		add_ptr_list(&already_handled, tmp);

		ret = 1;
		__push_fake_cur_stree();

		overwrite_states_using_pool(sm, tmp);

		return_ranges = get_return_ranges_str(expr, &ret_rl);
		set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(ret_rl));
		call_return_states_callbacks(return_ranges, expr);

		__free_fake_cur_stree();
	} END_FOR_EACH_PTR(tmp);

	free_slist(&already_handled);

	return ret;
}

static int split_by_bool_param(struct expression *expr)
{
	struct sm_state *start_sm, *sm;
	sval_t sval;

	start_sm = find_bool_param();
	if (!start_sm)
		return 0;
	sm = get_sm_state(SMATCH_EXTRA, start_sm->name, start_sm->sym);
	if (!sm || estate_get_single_value(sm->state, &sval))
		return 0;

	if (get_db_state_count() * 2 >= 2000)
		return 0;

	return split_on_bool_sm(sm, expr);
}

static int split_by_null_nonnull_param(struct expression *expr)
{
	struct symbol *arg;
	struct sm_state *sm;
	int nr_possible;

	arg = first_ptr_list((struct ptr_list *)cur_func_sym->ctype.base_type->arguments);
	if (!arg || !arg->ident)
		return 0;
	if (get_real_base_type(arg)->type != SYM_PTR)
		return 0;

	if (param_was_set_var_sym(arg->ident->name, arg))
		return 0;
	sm = get_sm_state(SMATCH_EXTRA, arg->ident->name, arg);
	if (!sm)
		return 0;

	if (!has_separate_zero_null(sm))
		return 0;

	nr_possible = ptr_list_size((struct ptr_list *)sm->possible);
	if (get_db_state_count() * nr_possible >= 2000)
		return 0;

	return split_on_bool_sm(sm, expr);
}

static void call_hooks_based_on_pool(struct expression *expr, struct sm_state *gate_sm, struct sm_state *pool_sm)
{
	struct range_list *ret_rl;
	const char *return_ranges;

	__push_fake_cur_stree();

	overwrite_states_using_pool(gate_sm, pool_sm);

	return_ranges = get_return_ranges_str(expr, &ret_rl);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(ret_rl));
	call_return_states_callbacks(return_ranges, expr);

	__free_fake_cur_stree();
}

static bool split_by_impossible(struct expression *expr)
{
	static int impossible_id;
	struct sm_state *sm, *tmp;
	int nr_states;

	if (!impossible_id)
		impossible_id = id_from_name("register_impossible_return");
	if (!impossible_id)
		return false;

	/*
	 * The only states for register_impossible_return are &impossible,
	 * &undefined and &merged.  This function will break otherwise.
	 */

	sm = get_sm_state(impossible_id, "impossible", NULL);
	if (!sm || sm->state != &merged)
		return false;

	nr_states = get_db_state_count();
	if (nr_states >= 1000)
		return false;

	/* handle possible */
	FOR_EACH_PTR(sm->possible, tmp) {
		if (!is_leaf(tmp))
			continue;
		if (tmp->state != &undefined)
			continue;
		call_hooks_based_on_pool(expr, sm, tmp);
		goto impossible;
	} END_FOR_EACH_PTR(tmp);

impossible:
	/* handle impossible */
	FOR_EACH_PTR(sm->possible, tmp) {
		if (!is_leaf(tmp))
			continue;
		if (strcmp(tmp->state->name, "impossible") != 0)
			continue;
		call_hooks_based_on_pool(expr, sm, tmp);
		return true;
	} END_FOR_EACH_PTR(tmp);

	return false;
}

struct expression *strip_expr_statement(struct expression *expr)
{
	struct expression *orig = expr;
	struct statement *stmt, *last_stmt;

	if (!expr)
		return NULL;
	if (expr->type == EXPR_PREOP && expr->op == '(')
		expr = expr->unop;
	if (expr->type != EXPR_STATEMENT)
		return orig;
	stmt = expr->statement;
	if (!stmt || stmt->type != STMT_COMPOUND)
		return orig;

	last_stmt = last_ptr_list((struct ptr_list *)stmt->stmts);
	if (!last_stmt || last_stmt->type == STMT_LABEL)
		last_stmt = last_stmt->label_statement;
	if (!last_stmt || last_stmt->type != STMT_EXPRESSION)
		return orig;
	return strip_expr(last_stmt->expression);
}

static bool is_kernel_error_path(struct expression *expr)
{
	struct range_list *rl;

	if (option_project != PROJ_KERNEL)
		return false;

	if (!get_implied_rl(expr, &rl))
		return false;
	if (rl_type(rl) != &int_ctype)
		return false;
	if (!is_neg_and_pos_err_code(rl))
		return false;
	return true;
}

static void call_return_state_hooks(struct expression *expr)
{
	struct range_list *ret_rl;
	const char *return_ranges;
	int nr_states;
	sval_t sval;

	if (debug_db) {
		struct range_list *rl = NULL;

		get_absolute_rl(expr, &rl);
		sm_msg("RETURN: expr='%s' rl='%s' %lu states%s", expr_to_str(expr),
		       show_rl(rl), stree_count(__get_cur_stree()),
		       is_impossible_path() ? " (impossible path)" : "");
	}

	if (__path_is_null())
		return;

	if (is_impossible_path())
		goto vanilla;

	if (expr && (expr->type == EXPR_COMPARE ||
		     !get_implied_value(expr, &sval)) &&
	    (is_condition(expr) || is_boolean(expr))) {
		call_return_state_hooks_compare(expr);
		if (debug_db)
			sm_msg("%s: bool", __func__);
		return;
	} else if (call_return_state_hooks_conditional(expr)) {
		if (debug_db)
			sm_msg("%s: condition", __func__);
		return;
	} else if (is_kernel_error_path(expr)) {
		if (debug_db)
			sm_msg("%s: kernel error path", __func__);
		goto vanilla;
	} else if (call_return_state_hooks_split_success_fail(expr)) {
		if (debug_db)
			sm_msg("%s: success_fail", __func__);
		return;
	} else if (call_return_state_hooks_split_possible(expr)) {
		if (debug_db)
			sm_msg("%s: split_possible", __func__);
		return;
	} else if (split_positive_from_negative(expr)) {
		if (debug_db)
			sm_msg("%s: positive negative", __func__);
		return;
	} else if (call_return_state_hooks_split_null_non_null_zero(expr)) {
		if (debug_db)
			sm_msg("%s: split zero non-zero", __func__);
		return;
	} else if (splitable_function_call(expr)) {
		if (debug_db)
			sm_msg("%s: split_function_call", __func__);
		return;
	} else if (split_by_bool_param(expr)) {
		if (debug_db)
			sm_msg("%s: bool param", __func__);
		return;
	} else if (split_by_null_nonnull_param(expr)) {
		if (debug_db)
			sm_msg("%s: null non-null param", __func__);
		return;
	} else if (split_by_impossible(expr)) {
		if (debug_db)
			sm_msg("%s: split by impossible", __func__);
		return;
	}

vanilla:
	return_ranges = get_return_ranges_str(expr, &ret_rl);
	set_state(RETURN_ID, "return_ranges", NULL, alloc_estate_rl(ret_rl));

	nr_states = get_db_state_count();
	if (nr_states >= 10000) {
		return_id++;
		match_return_info(return_id, (char *)return_ranges, expr);
		print_limited_param_set(return_id, (char *)return_ranges, expr);
		mark_all_params_untracked(return_id, (char *)return_ranges, expr);
		return;
	}
	call_return_states_callbacks(return_ranges, expr);
	if (debug_db)
		sm_msg("%s: vanilla", __func__);
}

static void print_returned_struct_members(int return_id, char *return_ranges, struct expression *expr)
{
	struct returned_member_callback *cb;
	struct sm_state *sm;
	struct symbol *type;
	char *name;
	char member_name[256];
	int len;

	type = get_type(expr);
	if (!type || type->type != SYM_PTR)
		return;
	name = expr_to_var(expr);
	if (!name)
		return;

	len = strlen(name);
	FOR_EACH_PTR(returned_member_callbacks, cb) {
		FOR_EACH_MY_SM(cb->owner, __get_cur_stree(), sm) {
			if (sm->name[0] == '*' && strcmp(sm->name + 1, name) == 0) {
				strcpy(member_name, "*$");
				cb->callback(return_id, return_ranges, expr, member_name, sm->state);
				continue;
			}
			if (strncmp(sm->name, name, len) != 0)
				continue;
			if (strncmp(sm->name + len, "->", 2) != 0)
				continue;
			snprintf(member_name, sizeof(member_name), "$%s", sm->name + len);
			cb->callback(return_id, return_ranges, expr, member_name, sm->state);
		} END_FOR_EACH_SM(sm);
	} END_FOR_EACH_PTR(cb);

	free_string(name);
}

static void print_return_struct_info(int return_id, char *return_ranges,
				     struct expression *expr,
				     struct symbol *sym,
				     struct return_info_callback *cb)
{
	struct sm_state *sm;
	const char *printed_name;
	int param;

	FOR_EACH_MY_SM(cb->owner, __get_cur_stree(), sm) {
		param = get_param_key_from_var_sym(sm->name, sm->sym, expr, &printed_name);
		if (!printed_name)
			continue;
		if (param < 0)
			continue;
		cb->callback(return_id, return_ranges, expr, param, printed_name, sm);
	} END_FOR_EACH_SM(sm);

	/* always print returned states after processing param states */
	FOR_EACH_MY_SM(cb->owner, __get_cur_stree(), sm) {
		param = get_return_param_key_from_var_sym(sm->name, sm->sym, expr, &printed_name);
		if (param != -1 || !printed_name)
			continue;
		cb->callback(return_id, return_ranges, expr, -1, printed_name, sm);
	} END_FOR_EACH_SM(sm);
}

static void print_return_info(int return_id, char *return_ranges, struct expression *expr)
{
	struct return_info_callback *cb;
	struct expression *tmp;
	struct symbol *sym;

	if (!option_info && !__inline_fn &&
	    !local_debug && !option_debug)
		return;

	tmp = get_fake_variable(expr);
	if (tmp)
		expr = tmp;
	sym = expr_to_sym(expr);

	FOR_EACH_PTR(return_callbacks, cb) {
		__ignore_param_used++;
		print_return_struct_info(return_id, return_ranges, expr, sym, cb);
		__ignore_param_used--;
	} END_FOR_EACH_PTR(cb);
}

static void reset_memdb(struct symbol *sym)
{
	mem_sql(NULL, NULL, "delete from caller_info;");
	mem_sql(NULL, NULL, "delete from return_states;");
	mem_sql(NULL, NULL, "delete from call_implies;");
	mem_sql(NULL, NULL, "delete from return_implies;");
}

static void match_end_func_info(struct symbol *sym)
{
	if (__path_is_null())
		return;
	call_return_state_hooks(NULL);
}

static void match_after_func(struct symbol *sym)
{
	clear_cached_return_vals();
	if (!__inline_fn)
		reset_memdb(sym);
}

static void init_memdb(void)
{
	char *err = NULL;
	int rc;
	const char *schema_files[] = {
		"db/db.schema",
		"db/caller_info.schema",
		"db/common_caller_info.schema",
		"db/return_states.schema",
		"db/function_type_size.schema",
		"db/type_size.schema",
		"db/function_type_info.schema",
		"db/type_info.schema",
		"db/call_implies.schema",
		"db/return_implies.schema",
		"db/function_ptr.schema",
		"db/local_values.schema",
		"db/function_type_value.schema",
		"db/type_value.schema",
		"db/function_type.schema",
		"db/data_info.schema",
		"db/parameter_name.schema",
		"db/constraints.schema",
		"db/constraints_required.schema",
		"db/fn_ptr_data_link.schema",
		"db/fn_data_link.schema",
		"db/mtag_about.schema",
		"db/mtag_info.schema",
		"db/mtag_map.schema",
		"db/mtag_data.schema",
		"db/mtag_alias.schema",
	};
	static char buf[4096];
	int fd;
	int ret;
	int i;

	rc = sqlite3_open(":memory:", &mem_db);
	if (rc != SQLITE_OK) {
		sm_ierror("starting In-Memory database.");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(schema_files); i++) {
		fd = open_schema_file(schema_files[i]);
		if (fd < 0)
			continue;
		ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			sm_ierror("failed to read: %s", schema_files[i]);
			continue;
		}
		close(fd);
		if (ret == sizeof(buf)) {
			sm_ierror("Schema file too large:  %s (limit %zd bytes)",
			       schema_files[i], sizeof(buf));
			continue;
		}
		buf[ret] = '\0';
		rc = sqlite3_exec(mem_db, buf, NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			sm_ierror("SQL error #2: %s", err);
			sm_ierror("%s", buf);
		}
	}
}

static void init_cachedb(void)
{
	char *err = NULL;
	int rc;
	const char *schema_files[] = {
		"db/call_implies.schema",
		"db/return_implies.schema",
		"db/type_info.schema",
		"db/mtag_about.schema",
		"db/mtag_data.schema",
		"db/mtag_info.schema",
		"db/sink_info.schema",
		"db/hash_string.schema",
	};
	static char buf[4096];
	int fd;
	int ret;
	int i;

	rc = sqlite3_open(":memory:", &cache_db);
	if (rc != SQLITE_OK) {
		sm_ierror("starting In-Memory database.");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(schema_files); i++) {
		fd = open_schema_file(schema_files[i]);
		if (fd < 0)
			continue;
		ret = read(fd, buf, sizeof(buf));
		if (ret < 0) {
			sm_ierror("failed to read: %s", schema_files[i]);
			continue;
		}
		close(fd);
		if (ret == sizeof(buf)) {
			sm_ierror("Schema file too large:  %s (limit %zd bytes)",
			       schema_files[i], sizeof(buf));
			continue;
		}
		buf[ret] = '\0';
		rc = sqlite3_exec(cache_db, buf, NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			sm_ierror("SQL error #2: %s", err);
			sm_ierror("%s", buf);
		}
	}
}

static int save_cache_data(void *_table, int argc, char **argv, char **azColName)
{
	static char buf[4096];
	char tmp[256];
	char *p = buf;
	char *table = _table;
	int i;


	p += snprintf(p, 4096 - (p - buf), "insert or ignore into %s values (", table);
	for (i = 0; i < argc; i++) {
		if (i)
			p += snprintf(p, 4096 - (p - buf), ", ");
		sqlite3_snprintf(sizeof(tmp), tmp, "%q", escape_newlines(argv[i]));
		p += snprintf(p, 4096 - (p - buf), "'%s'", tmp);

	}
	p += snprintf(p, 4096 - (p - buf), ");");
	if (p - buf > 4096)
		return 0;

	sm_msg("SQL: %s", buf);
	return 0;
}

static void dump_cache(struct symbol_list *sym_list)
{
	const char *cache_tables[] = {
		"type_info", "return_implies", "call_implies", "mtag_data",
		"mtag_info", "mtag_about", "sink_info", "hash_string",
	};
	char buf[64];
	int i;

	if (!option_info)
		return;

	for (i = 0; i < ARRAY_SIZE(cache_tables); i++) {
		snprintf(buf, sizeof(buf), "select * from %s;", cache_tables[i]);
		cache_sql(&save_cache_data, (char *)cache_tables[i], buf);
	}
}

void open_smatch_db(char *db_file)
{
	int rc;

	if (option_no_db)
		return;

	use_states = malloc(num_checks);
	memset(use_states, 0xff, num_checks);

	init_memdb();
	init_cachedb();

	rc = sqlite3_open_v2(db_file, &smatch_db, SQLITE_OPEN_READONLY, NULL);
	if (rc != SQLITE_OK) {
		option_no_db = 1;
		return;
	}
	run_sql(NULL, NULL,
		"PRAGMA cache_size = %d;", SQLITE_CACHE_PAGES);
	return;
}

static char *get_next_string(char **str)
{
	static char string[256];
	char *start;
	char *p = *str;
	int len, i, j;

	if (*p == '\0')
		return NULL;
	start = p;

	while (*p != '\0' && *p != '\n') {
		if (*p == '\\' && *(p + 1) == ' ') {
			p += 2;
			continue;
		}
		if (*p == ' ')
			break;
		p++;
	}

	len = p - start;
	if (len >= sizeof(string)) {
		memcpy(string, start, sizeof(string));
		string[sizeof(string) - 1] = '\0';
		sm_ierror("return_fix: '%s' too long", string);
		**str = '\0';
		return NULL;
	}
	memcpy(string, start, len);
	string[len] = '\0';
	for (i = 0; i < sizeof(string) - 1; i++) {
		if (string[i] == '\\' && string[i + 1] == ' ') {
			for (j = i; string[j] != '\0'; j++)
				string[j] = string[j + 1];
		}
	}
	if (*p != '\0')
		p++;
	*str = p;
	return string;
}

static void register_return_deletes(void)
{
	char *func, *ret_str;
	char filename[256];
	char buf[4096];
	int fd, ret, i;
	char *p;

	snprintf(filename, 256, "db/%s.delete.return_states", option_project_str);
	fd = open_schema_file(filename);
	if (fd < 0)
		return;
	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret < 0)
		return;
	if (ret == sizeof(buf)) {
		sm_ierror("file too large:  %s (limit %zd bytes)",
		       filename, sizeof(buf));
		return;
	}
	buf[ret] = '\0';

	p = buf;
	while (*p) {
		get_next_string(&p);
		delete_count++;
	}
	if (delete_count == 0)
		return;
	if (delete_count % 2 != 0) {
		printf("error parsing '%s' delete_count=%d\n", filename, delete_count);
		delete_count = 0;
		return;
	}
	delete_table = malloc(delete_count * sizeof(char *));

	p = buf;
	i = 0;
	while (*p) {
		func = alloc_string(get_next_string(&p));
		ret_str = alloc_string(get_next_string(&p));

		delete_table[i++] = func;
		delete_table[i++] = ret_str;
	}
}

#define RETURN_FIX_SIZE 8196
static void register_return_replacements(void)
{
	char *func, *orig, *new;
	char filename[256];
	int fd, ret, i;
	char *buf;
	char *p;

	snprintf(filename, 256, "db/%s.return_fixes", option_project_str);
	fd = open_schema_file(filename);
	if (fd < 0)
		return;
	buf = malloc(RETURN_FIX_SIZE);
	ret = read(fd, buf, RETURN_FIX_SIZE);
	close(fd);
	if (ret < 0) {
		free(buf);
		return;
	}
	if (ret == RETURN_FIX_SIZE) {
		sm_ierror("file too large:  %s (limit %d bytes)",
		       filename, RETURN_FIX_SIZE);
		free(buf);
		return;
	}
	buf[ret] = '\0';

	p = buf;
	while (*p) {
		get_next_string(&p);
		replace_count++;
	}
	if (replace_count == 0) {
		free(buf);
		return;
	}
	if (replace_count % 3 != 0) {
		printf("error parsing '%s' replace_count=%d\n", filename, replace_count);
		replace_count = 0;
		free(buf);
		return;
	}
	replace_table = malloc(replace_count * sizeof(char *));

	p = buf;
	i = 0;
	while (*p) {
		func = alloc_string(get_next_string(&p));
		orig = alloc_string(get_next_string(&p));
		new  = alloc_string(get_next_string(&p));

		replace_table[i++] = func;
		replace_table[i++] = orig;
		replace_table[i++] = new;
	}
	free(buf);
}

static void register_forced_return_splits(void)
{
	int struct_members = sizeof(struct split_data) / sizeof(char *);
	char filename[256];
	char buf[4096];
	int fd, ret, i;
	char *p;

	snprintf(filename, 256, "db/%s.forced_return_splits", option_project_str);
	fd = open_schema_file(filename);
	if (fd < 0)
		return;
	ret = read(fd, buf, sizeof(buf));
	close(fd);
	if (ret < 0)
		return;
	if (ret == sizeof(buf)) {
		sm_ierror("file too large:  %s (limit %zd bytes)",
		       filename, sizeof(buf));
		return;
	}
	buf[ret] = '\0';

	p = buf;
	while (*p) {
		get_next_string(&p);
		split_count++;
	}
	if (split_count == 0)
		return;
	if (split_count % struct_members != 0) {
		printf("error parsing '%s' split_count=%d\n", filename, split_count);
		split_count = 0;
		return;
	}
	split_count /= struct_members;
	forced_splits = malloc(split_count * sizeof(void *));

	p = buf;
	i = 0;
	while (*p) {
		struct split_data *split = malloc(sizeof(*split));

		split->func = alloc_string(get_next_string(&p));
		split->rl = alloc_string(get_next_string(&p));
		forced_splits[i++] = split;
	}
}

void register_definition_db_callbacks(int id)
{
	my_id = id;

	add_hook(&match_call_info, FUNCTION_CALL_HOOK_BEFORE);
	add_hook(&match_call_info_new, FUNCTION_CALL_HOOK_BEFORE);
	add_split_return_callback(match_return_info);
	add_split_return_callback(print_returned_struct_members);
	add_split_return_callback(print_return_info);
	add_hook(&call_return_state_hooks, RETURN_HOOK);
	add_hook(&match_end_func_info, END_FUNC_HOOK);
	add_hook(&match_after_func, AFTER_FUNC_HOOK);

	add_hook(&match_data_from_db, FUNC_DEF_HOOK);
	add_hook(&match_call_implies, FUNC_DEF_HOOK);
	add_hook(&match_return_implies_early, CALL_HOOK_AFTER_INLINE);

	common_funcs = load_strings_from_file(option_project_str, "common_functions");
	register_return_deletes();
	register_return_replacements();
	register_forced_return_splits();

	add_hook(&dump_cache, END_FILE_HOOK);
}

void register_definition_db_callbacks_late(int id)
{
	add_hook(&match_return_implies_late, CALL_HOOK_AFTER_INLINE);
}

void register_db_call_marker(int id)
{
	add_hook(&match_call_marker, FUNCTION_CALL_HOOK_BEFORE);
}

char *get_data_info_name(struct expression *expr)
{
	struct symbol *sym;
	char *name;
	char buf[256];
	char *ret = NULL;

	expr = strip_expr(expr);
	name = get_member_name(expr);
	if (name)
		return name;
	name = expr_to_var_sym(expr, &sym);
	if (!name || !sym)
		goto free;
	if (!(sym->ctype.modifiers & MOD_TOPLEVEL))
		goto free;
	if (sym->ctype.modifiers & MOD_STATIC)
		snprintf(buf, sizeof(buf), "static %s", name);
	else
		snprintf(buf, sizeof(buf), "global %s", name);
	ret = alloc_sname(buf);
free:
	free_string(name);
	return ret;
}
