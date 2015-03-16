/*
 * header for process handling
 *
 * Copyright (C) 2014 Stefani Seibold <stefani@seibold.net>
 *
 * sponsored by Rohde & Schwarz GmbH & Co. KG
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "base.h"
#include "bfdinc.h"
#include "memtrace.h"
#include "rbtree.h"

/* forward declaration */
typedef struct _mt_process mt_process;

typedef enum {
	MT_PROCESS_RUNNING,	/* Child is running */
	MT_PROCESS_EXIT,	/* _exit() has been called in child */
	MT_PROCESS_IGNORE,	/* ignored */
} mt_processStatus;

typedef void (*mt_processBlockForeachFunc) (struct alloc_block *block, void *data);

struct _mt_process {
	mt_processStatus status;
	pid_t pid;
	unsigned long bytes_used;
	unsigned long n_allocations;
	unsigned long total_allocations;
	unsigned long leaks;
	unsigned long long leaked_bytes;
	unsigned long stack_trees;
	struct rb_root block_table;
	struct rb_root stack_table;
	struct list_head map_list;
	unsigned long long tsc;
	int swap_endian;
	int is_64bit;
	unsigned long (*get_ulong)(void *);
	void (*put_ulong)(void *, unsigned long);
	uint16_t (*val16)(uint16_t val);
	uint32_t (*val32)(uint32_t val);
	uint64_t (*val64)(uint64_t val);
	uint8_t ptr_size;
};

extern void block_unref(struct alloc_block *block);

extern mt_process *process_new(pid_t pid, int swap_endian, int is_64bit);
extern void process_reset_allocations(mt_process *process);
extern void process_reinit(mt_process *process, int swap_endian, int is_64bit);
extern void process_delete(mt_process *process);
extern void process_exit(mt_process *process);
extern void process_duplicate(mt_process *process, mt_process *copy);
extern void process_set_status(mt_process *process, mt_processStatus status);
extern void process_read_map(mt_process *process, void *data, uint32_t n);
extern void process_release_map(mt_process *process);
extern void process_status(mt_process *process);
extern void *process_scan(mt_process *curr, void *leaks, uint32_t n);
extern void process_alloc(mt_process *process, mt_msg *msg, void *payload);
extern void process_free(mt_process *process, mt_msg *mt_msg, void *payload);
extern void process_munmap(mt_process *process, mt_msg *mt_msg, void *payload);
extern void process_leaks_scan(mt_server *server, mt_process *process, int mode);

extern void process_dump_sort_average(mt_process *process, const char *outfile);
extern void process_dump_sort_usage(mt_process *process, const char *outfile);
extern void process_dump_sort_leaks(mt_process *process, const char *outfile);
extern void process_dump_sort_bytes_leaked(mt_process *process, const char *outfile);
extern void process_dump_sort_allocations(mt_process *process, const char *outfile);
extern void process_dump_sort_total(mt_process *process, const char *outfile);
extern void process_dump_sort_tsc(mt_process *process, const char *outfile);
extern void process_dump_stacks(mt_process *process, const char *outfile);

#endif
