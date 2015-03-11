/*
 * process handling
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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base.h"
#include "binfile.h"
#include "dump.h"
#include "client.h"
#include "common.h"
#include "job.h"
#include "process.h"
#include "rbtree.h"

#define	PAGE_SIZE 4096

struct rb_block {
	struct rb_node node;
	unsigned long flags;
	unsigned long addr;
	unsigned long size;
	struct rb_stack *stack_node;
};

struct stack {
	unsigned long refcnt;
	void *addrs;
	uint32_t size;
	uint32_t entries;
	char **syms;
	mt_operation operation;
};

struct rb_stack {
	struct rb_node node;
	struct stack *stack;
	unsigned long leaks;
	unsigned long long n_allocations;
	unsigned long long total_allocations;
	unsigned long long bytes_used;
	unsigned long long bytes_leaked;
	unsigned long long tsc;
};

struct map {
	struct list_head list;
	unsigned long offset;
	unsigned long addr;
	unsigned long size;
	char *filename;
	char *realpath;
	struct bin_file *binfile;
	int ignore;
	unsigned char perm;
};

static unsigned long get_uint64(void *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));

	return v;
}

static unsigned long get_uint64_swap(void *p)
{
	uint64_t v;

	memcpy(&v, p, sizeof(v));

	return bswap_64(v);
}

static unsigned long get_uint32(void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));

	return v;
}

static unsigned long get_uint32_swap(void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));

	return bswap_32(v);
}

static void put_uint64(void *p, unsigned long v)
{
	uint64_t _v = v;

	memcpy(p, &_v, sizeof(_v));
}

static void put_uint64_swap(void *p, unsigned long v)
{
	uint64_t _v = bswap_64(v);

	memcpy(p, &_v, sizeof(_v));
}

static void put_uint32(void *p, unsigned long v)
{
	uint32_t _v = v;

	memcpy(p, &_v, sizeof(_v));
}

static void put_uint32_swap(void *p, unsigned long v)
{
	uint32_t _v = bswap_32(v);

	memcpy(p, &_v, sizeof(_v));
}

static uint16_t val16(uint16_t v)
{
	return v;
}

static uint16_t val16_swap(uint16_t v)
{
	return bswap_16(v);
}

static uint32_t val32(uint32_t v)
{
	return v;
}

static uint32_t val32_swap(uint32_t v)
{
	return bswap_32(v);
}

static uint64_t val64(uint64_t v)
{
	return v;
}

static uint64_t val64_swap(uint64_t v)
{
	return bswap_64(v);
}

static inline int memncmp(void *p1, uint32_t l1, void *p2, uint32_t l2)
{
	int ret = memcmp(p1, p2, (l1 < l2) ? l1 : l2);
	if (ret)
		return ret;
	if (l1 < l2)
		return -1;
	if (l1 > l2)
		return 1;
	return 0;
}

static void process_walk_map(mt_process *process, unsigned char perm, void (*func)(struct map *, void *), void *user)
{
	struct list_head *pos;

	for(pos = process->map_list.next; !list_is_last(pos, &process->map_list); pos = pos->next) {
		struct map *map = (struct map *)pos;

		if (map->perm & perm)
			func(map, user);
	}
}

static struct map *locate_map(mt_process *process, bfd_vma addr)
{
	struct list_head *it;
	bfd_vma a = (bfd_vma)addr;

	list_for_each(it, &process->map_list) {
		struct map *map = container_of(it, struct map, list);

		if ((a >= map->addr) && (a < map->addr + map->size))
			return map;
	}
	return NULL;
}

static struct map *open_map(mt_process *process, bfd_vma addr)
{
	struct map *map = locate_map(process, addr);
	char *filename;
	char *realpath;
	char **p;

	if (!map)
		return NULL;

	if (!map)
		return NULL;

	if (map->binfile)
		return map;

	if (map->ignore)
		return map;

	p = get_search_list();

	do {
		int len = strlen(*p);

		while(len && (*p)[len - 1] == '/')
			--len;

		for(filename = map->filename; *filename == '/'; ++filename)
			;

		do {
			if (asprintf(&realpath, "%.*s/%s", len, *p, filename) == -1)
				return map;

			if (!access(realpath, R_OK)) {
				map->binfile = bin_file_new(realpath);

				if (map->binfile) {
					map->realpath = realpath;
					return map;
				}
			}

			free(realpath);

			filename = strchr(filename + 1, '/');
		} while(filename++);
	} while(*++p);

	map->ignore = 1;
	return map;
}

static char *resolv_address(mt_process *process, bfd_vma addr)
{
	char *sym;
	struct map *map = open_map(process, addr);

	if (!map)
		return NULL;

	if (map->binfile) {
		sym = bin_file_lookup(map->binfile, addr, map->addr);
		if (sym)
			return sym;
	}

	if (asprintf(&sym, "%s", map->filename) == -1)
		return NULL;

	return sym;
}

static void stack_resolv(mt_process *process, struct stack *stack)
{
	uint32_t i;
	void *addrs;

	stack->syms = malloc(sizeof(*stack->syms) * stack->entries);
	if (!stack->syms)
		return;

	addrs = stack->addrs;

	for(i = 0; i < stack->entries; ++i) {
		unsigned long addr = process->get_ulong(addrs);

		if (!addr) {
			stack->syms[i] = NULL;

			continue;
		}

		stack->syms[i] = resolv_address(process, addr);

		addrs += process->ptr_size;
	}
}

static void stack_unref(struct stack *stack)
{
	if (--stack->refcnt == 0) {
		if (stack->syms) {
			unsigned int i;

			for(i = 0; i < stack->entries; ++i)
				free(stack->syms[i]);

			free(stack->syms);
		}
		free(stack);
	}
}

static struct rb_stack *stack_clone(mt_process *process, struct rb_stack *stack_node)
{
	struct rb_root *root = &process->stack_table;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_stack *this;
	int ret;

	/* Figure out where to put new node */
	while (*new) {
		this = container_of(*new, struct rb_stack, node);

		parent = *new;
		ret = memncmp(stack_node->stack->addrs, stack_node->stack->size, this->stack->addrs, this->stack->size);

		if (ret < 0)
			new = &((*new)->rb_left);
		else
		if (ret > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}

	this = malloc(sizeof(*this));
	if (!this)
		return NULL;

	this->leaks = stack_node->leaks;
	this->n_allocations = stack_node->n_allocations;
	this->total_allocations = stack_node->total_allocations;
	this->bytes_used = stack_node->bytes_used;
	this->bytes_leaked = stack_node->bytes_leaked;
	this->tsc = stack_node->tsc;
	this->stack = stack_node->stack;
	this->stack->refcnt++;

	/* Add new node and rebalance tree. */
	rb_link_node(&this->node, parent, new);
	rb_insert_color(&this->node, root);

	process->stack_trees++;

	return this;
}

static struct rb_stack *stack_add(mt_process *process, pid_t pid, void *addrs, uint32_t stack_size, mt_operation operation)
{
	struct rb_root *root = &process->stack_table;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_stack *this;
	struct stack *stack;
	int ret;

	/* Figure out where to put new node */
	while (*new) {
		this = container_of(*new, struct rb_stack, node);

		parent = *new;
		ret = memncmp(addrs, stack_size, this->stack->addrs, this->stack->size);

		if (ret < 0)
			new = &((*new)->rb_left);
		else
		if (ret > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}

	this = malloc(sizeof(*this));
	if (!this)
		return NULL;

	stack = malloc(sizeof(*stack));
	if (!stack) {
		free(this);
		return NULL;
	}

	stack->refcnt = 1;
	stack->addrs = malloc(stack_size);
	stack->size = stack_size;
	stack->entries = stack_size / process->ptr_size;
	stack->syms = NULL;
	stack->operation = operation;

	memcpy(stack->addrs, addrs, stack_size);

	this->n_allocations = 0;
	this->total_allocations = 0;
	this->bytes_used = 0;
	this->leaks = 0;
	this->bytes_leaked = 0;
	this->stack = stack;

	/* Add new node and rebalance tree. */
	rb_link_node(&this->node, parent, new);
	rb_insert_color(&this->node, root);

	process->stack_trees++;

	return this;
}

static void process_dump_stack(mt_process *process, struct rb_stack *this)
{
	uint32_t i;
	void *addrs;
	struct stack *stack = this->stack;

	if (!stack->syms) {
		stack_resolv(process, stack);

		if (!stack->syms)
			return;
	}

	for(addrs = stack->addrs, i = 0; i < stack->entries; ++i) {
		if (dump_printf("  [0x%lx] %s\n", process->get_ulong(addrs), stack->syms[i] ? stack->syms[i] : "?") == -1)
			return;

		addrs += process->ptr_size;
	}
}

static struct rb_block *process_rb_search_range(struct rb_root *root, unsigned long addr, unsigned long size)
{
	struct rb_node *node = root->rb_node;

	if (!size)
		size = 1;

	while (node) {
		struct rb_block *this = container_of(node, struct rb_block, node);

		if (addr <= this->addr && addr + size > this->addr)
			return this;

		if (addr < this->addr)
			node = node->rb_left;
		else
			node = node->rb_right;
	}
	return NULL;
}

static struct rb_block *process_rb_search(struct rb_root *root, unsigned long addr)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_block *this = container_of(node, struct rb_block, node);

		if (addr < this->addr)
			node = node->rb_left;
		else if (addr > this->addr)
			node = node->rb_right;
		else
			return this;
	}
	return NULL;
}

static void process_release_mem(mt_process *process, struct rb_block *block, unsigned int size)
{
	if (block->flags & BLOCK_LEAKED) {
		block->flags &= ~BLOCK_LEAKED;

		block->stack_node->leaks--;
		block->stack_node->bytes_leaked -= block->size;

		process->leaks--;
		process->leaked_bytes -= block->size;
	}

	block->stack_node->bytes_used -= size;

	process->bytes_used -= size;
}

static void process_rb_delete_block(mt_process *process, struct rb_block *block)
{
	rb_erase(&block->node, &process->block_table);

	process_release_mem(process, block, block->size);
	process->n_allocations--;

	block->stack_node->n_allocations--;

	free(block);
}

static int process_rb_insert_block(mt_process *process, unsigned long addr, unsigned long size, struct rb_stack *stack, unsigned long flags)
{
	struct rb_node **new = &process->block_table.rb_node, *parent = NULL;
	struct rb_block *block;
	unsigned long n;

	n = size;
	if (!n)
		n = 1;

	/* Figure out where to put the new node */
	while (*new) {
		struct rb_block *this = container_of(*new, struct rb_block, node);

		parent = *new;

		if (addr <= this->addr && addr + n > this->addr)
			return -1;

		if (addr < this->addr)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	block = malloc(sizeof(*block));
	if (!block)
		return -1;

	block->addr = addr;
	block->size = size;
	block->flags = flags;
	block->stack_node = stack;
	block->stack_node->n_allocations++;
	block->stack_node->total_allocations++;
	block->stack_node->bytes_used += size;
	block->stack_node->stack->refcnt++;

	/* Add new node and rebalance tree. */
	rb_link_node(&block->node, parent, new);
	rb_insert_color(&block->node, &process->block_table);

	process->n_allocations++;

	return 0;
}

static struct map *_process_add_map(mt_process *process, unsigned long start, unsigned long end, unsigned long offset, const char *filename, unsigned char perm)
{
	struct map *map = malloc(sizeof(*map));

	map->addr = start;
	map->offset = offset;
	map->size = end - start;
	map->filename = strdup(filename);
	map->realpath = NULL;
	map->binfile = NULL;
	map->ignore = 0;
	map->perm = perm;

	if (map->perm & PERM_W)
		++process->write_maps;

	list_add_tail(&map->list, &process->map_list);

	return map;
}

static void _process_del_map(mt_process *process, struct map *map)
{
	if (map->perm & PERM_W)
		--process->write_maps;

	bin_file_free(map->binfile);

	list_del(&map->list);

	free(map->filename);
	free(map->realpath);
	free(map->binfile);
	free(map);
}


void process_release_map(mt_process *process)
{
	struct list_head *pos;
	struct list_head *n;

	list_for_each_safe(pos, n, &process->map_list) {
		struct map *map = (struct map *)pos;

		_process_del_map(process, map);
	}
}

void process_read_map(mt_process *process, void *data, uint32_t n)
{
	struct xmap *xmap;

	if(!n)
		return;

	process_release_map(process);

	for(xmap = data; (void *)xmap - data < n; xmap = XMAP_NEXT(xmap, process->val16(xmap->flen) + 1)) {
		struct map *map = _process_add_map(process, process->val64(xmap->start), process->val64(xmap->end), process->val64(xmap->offset), xmap->fname, xmap->perm);

		if (!map)
			break;
#if 0
fprintf(stderr, "start: 0x%08llx len: 0x%08llx offset: 0x%08llx perm: %02x fname: %s\n",
		map->start,
		map->len,
		map->offset,
		map->perm,
		map->fname);
#endif
	}
}

static void process_init(mt_process *process, int swap_endian, int is_64bit)
{
	if (is_64bit) {
		process->ptr_size = sizeof(uint64_t);
		process->get_ulong = swap_endian ? get_uint64_swap : get_uint64;
		process->put_ulong = swap_endian ? put_uint64_swap : put_uint64;
	}
	else {
		process->ptr_size = sizeof(uint32_t);
		process->get_ulong = swap_endian ? get_uint32_swap : get_uint32;
		process->put_ulong = swap_endian ? put_uint32_swap : put_uint32;
	}

	process->val16 = swap_endian ? val16_swap : val16;
	process->val32 = swap_endian ? val32_swap : val32;
	process->val64 = swap_endian ? val64_swap : val64;

	process->is_64bit = is_64bit;
	process->swap_endian = swap_endian;
	process->status = MT_PROCESS_RUNNING;
}

void process_reset_allocations(mt_process *process)
{
	struct rb_block *rbb, *rbb_next;
	struct rb_stack *rbs, *rbs_next;

	rbtree_postorder_for_each_entry_safe(rbb, rbb_next, &process->block_table, node) {
		process->n_allocations--;
		free(rbb);
	}
	process->block_table = RB_ROOT;

	rbtree_postorder_for_each_entry_safe(rbs, rbs_next, &process->stack_table, node) {
		stack_unref(rbs->stack);
		free(rbs);
	}
	process->stack_table = RB_ROOT;

	process->total_allocations = 0;
	process->bytes_used = 0;
	process->stack_trees = 0;
	process->leaks = 0;
	process->leaked_bytes = 0;
	process->tsc = 0;
}

static void process_reset(mt_process *process)
{
	process_reset_allocations(process);
	process_release_map(process);
}

static int process_rb_duplicate_block(struct rb_node *node, void *user)
{
	struct rb_block *block = container_of(node, struct rb_block, node);
	mt_process *process = user;
	struct rb_stack *stack = stack_clone(process, block->stack_node);

	if (process_rb_insert_block(process, block->addr, block->size, stack, block->flags))
		abort();

	process->bytes_used += block->size;

	return 0;
}

void process_duplicate(mt_process *process, mt_process *copy)
{
	process_reset(process);
	process_init(process, copy->swap_endian, copy->is_64bit);

	if (!copy)
		return;

	rb_iterate(&copy->block_table, process_rb_duplicate_block, process);

	process->total_allocations = copy->total_allocations;
	process->tsc = copy->tsc;
}

static int sort_tsc(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->tsc > (*q)->tsc)
		return -1;
	if ((*p)->tsc < (*q)->tsc)
		return 1;
	return 0;
}

static int sort_average(const struct rb_stack **p, const struct rb_stack **q)
{
	double pv, qv;

	if ((*p)->n_allocations)
		pv = (double)(*p)->bytes_used / (*p)->n_allocations;
	else
		pv = 0.0;

	if ((*q)->n_allocations)
		qv = (double)(*q)->bytes_used / (*q)->n_allocations;
	else
		qv = 0.0;

	if (pv > qv)
		return -1;
	if (pv < qv)
		return 1;
	return 0;
}

static int sort_usage(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->bytes_used > (*q)->bytes_used)
		return -1;
	if ((*p)->bytes_used < (*q)->bytes_used)
		return 1;
	return 0;
}

static int sort_leaks(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->leaks > (*q)->leaks)
		return -1;
	if ((*p)->leaks < (*q)->leaks)
		return 1;
	return 0;
}

static int sort_bytes_leaked(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->bytes_leaked > (*q)->bytes_leaked)
		return -1;
	if ((*p)->bytes_leaked < (*q)->bytes_leaked)
		return 1;
	return 0;
}

static int sort_allocations(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->n_allocations > (*q)->n_allocations)
		return -1;
	if ((*p)->n_allocations < (*q)->n_allocations)
		return 1;
	return 0;
}

static int sort_total(const struct rb_stack **p, const struct rb_stack **q)
{
	if ((*p)->total_allocations > (*q)->total_allocations)
		return -1;
	if ((*p)->total_allocations < (*q)->total_allocations)
		return 1;
	return 0;
}

static const char *str_operation(uint16_t operation)
{
	switch(operation) {
	case MT_MALLOC:
		return "malloc";
	case MT_REALLOC:
		return "realloc";
	case MT_MEMALIGN:
		return "memalign";
	case MT_POSIX_MEMALIGN:
		return "posix_memalign";
	case MT_ALIGNED_ALLOC:
		return "aligned_alloc";
	case MT_VALLOC:
		return "valloc";
	case MT_PVALLOC:
		return "pvalloc";
	case MT_MMAP:
		return "mmap";
	case MT_MMAP64:
		return "mmap64";
	case MT_FREE:
		return "free";
	case MT_MUNMAP:
		return "munmap";
	default:
		break;
	}
	return "unknow operation";
}

static void _process_dump(mt_process *process, int (*sortby)(const struct rb_stack **, const struct rb_stack **), int (*skipfunc)(struct rb_stack *), FILE *file)
{
	struct rb_stack **arr;
	unsigned long i;
	void *data;

	arr = malloc(sizeof(struct rb_stack *) * process->stack_trees);
	if (!arr)
		return;

	for(i = 0, data = rb_first(&process->stack_table); data; data = rb_next(data))
		arr[i++] = container_of(data, struct rb_stack, node);

	if (dump_init(file) == -1)
		return;

	dump_printf("Process dump %d\n", process->pid);

	qsort(arr, process->stack_trees, sizeof(struct stack *), (void *)sortby);

	for(i = 0; i < process->stack_trees; ++i) {
		struct rb_stack *stack = arr[i];

		if (!skipfunc(stack)) {
			if (dump_printf(
				"Stack (%s):\n"
				" bytes used: %llu\n"
				" number of open allocations: %llu\n"
				" total number of allocations: %llu\n"
				" leaked allocations: %lu (%llu bytes)\n"
				" tsc: %llu\n",
					str_operation(stack->stack->operation),
					stack->bytes_used,
					stack->n_allocations,
					stack->total_allocations,
					stack->leaks,
					stack->bytes_leaked,
					stack->tsc
			) == -1)
				break;

			process_dump_stack(process, stack);
		}
	}
	free(arr);
	dump_flush();
	return;
}

static void process_dump(mt_process *process, int (*sortby)(const struct rb_stack **, const struct rb_stack **), int (*skipfunc)(struct rb_stack *), const char *outfile)
{
	if (!outfile)
		_process_dump(process, sortby, skipfunc, NULL);
	else {
		FILE *file = fopen(outfile, "w");

		if (!file) {
			fprintf(stderr, "could not open `%s' for output!\n", outfile);
			return;
		}
		_process_dump(process, sortby, skipfunc, file);

		fclose(file);
	}
}

static int skip_none(struct rb_stack *stack)
{
	return 0;
}

static int skip_zero_allocations(struct rb_stack *stack)
{
	return !stack->n_allocations;
}

static int skip_zero_leaks(struct rb_stack *stack)
{
	return !stack->leaks;
}

void process_dump_sort_average(mt_process *process,  const char *outfile)
{
	process_dump(process, sort_average, skip_zero_allocations, outfile);
}

void process_dump_sort_usage(mt_process *process, const char *outfile)
{
	process_dump(process, sort_usage, skip_zero_allocations, outfile);
}

void process_dump_sort_leaks(mt_process *process, const char *outfile)
{
	process_dump(process, sort_leaks, skip_zero_leaks, outfile);
}

void process_dump_sort_bytes_leaked(mt_process *process, const char *outfile)
{
	process_dump(process, sort_bytes_leaked, skip_zero_leaks, outfile);
}

void process_dump_sort_allocations(mt_process *process, const char *outfile)
{
	process_dump(process, sort_allocations, skip_zero_allocations, outfile);
}

void process_dump_sort_total(mt_process *process, const char *outfile)
{
	process_dump(process, sort_total, skip_zero_allocations, outfile);
}

void process_dump_sort_tsc(mt_process *process, const char *outfile)
{
	process_dump(process, sort_tsc, skip_zero_allocations, outfile);
}

void process_dump_stacks(mt_process *process, const char *outfile)
{
	process_dump(process, sort_allocations, skip_none, outfile);
}

void *process_scan(mt_process *process, void *leaks, uint32_t payload_size)
{
	unsigned int new = 0;
	unsigned long n = payload_size / process->ptr_size;
	unsigned long i;
	void *new_leaks = leaks;

	for(i = 0; i < n; ++i) {
		struct rb_block *block = process_rb_search(&process->block_table, process->get_ulong(leaks));

		if (!(block->flags & BLOCK_LEAKED)) {
			block->flags |= BLOCK_LEAKED;

			block->stack_node->leaks++;
			block->stack_node->bytes_leaked += block->size;

			process->leaks++;
			process->leaked_bytes += block->size;

			memcpy(new_leaks + new * process->ptr_size, leaks, process->ptr_size);
			new++;
		}
		leaks += process->ptr_size;
	}

	dump_init(NULL);
	dump_printf("process %d\n", process->pid);
	dump_printf(" leaks reported: %lu\n", n);
	dump_printf(" new leaks found: %u\n", new);
	dump_printf(" leaked bytes: %llu\n", process->leaked_bytes);

	for(i = 0; i < new; ++i) {
		struct rb_block *block = process_rb_search(&process->block_table, process->get_ulong(new_leaks));

		if (dump_printf(" leaked at 0x%08lx (%lu bytes)\n", (unsigned long)block->addr, (unsigned long)block->size) == -1)
			break;

		new_leaks += process->ptr_size;
	}

	dump_printf("leaks total: %lu\n", process->leaks);
	dump_flush();


	return leaks;
}

static int is_mmap(mt_operation operation)
{
	return operation == MT_MMAP || operation == MT_MMAP64;
}

void process_munmap(mt_process *process, mt_msg *mt_msg, void *payload)
{
	struct rb_block *block = NULL;
	unsigned long ptr;
	unsigned long size;

	if (process->is_64bit) {
		struct _mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);
	}
	else {
		struct _mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);
	}

	do {
		block = process_rb_search_range(&process->block_table, ptr, size);
		if (!block)
			break;

		if (!is_mmap(block->stack_node->stack->operation)) {
			fprintf(stderr, ">>> block missmatch MAP<>MALLOC %#lx found\n", ptr);
			break;
		}

		if (block->addr >= ptr) {
			unsigned off = block->addr - ptr;

			size -= off;
			ptr += off;

			if (size < block->size) {
				process_release_mem(process, block, size);

				block->addr += size;
				block->size -= size;

				break;
			}

			size -= block->size;
			ptr += block->size;

			process_rb_delete_block(process, block);
		}
		else {
			unsigned off = ptr - block->addr;

			if (off + size < block->size) {
				unsigned long new_addr = block->addr + (off + size);
				unsigned long new_size = block->size - (off + size);

				process_release_mem(process, block, block->size - off - new_size);

				block->size = off;

				if (process_rb_insert_block(process, new_addr, new_size, block->stack_node, 0))
					abort();

				process->n_allocations++;
				process->total_allocations++;
				process->bytes_used += new_size;

				break;
			}

			process_release_mem(process, block, off);

			block->addr += off;
			block->size -= off;

			size -= block->size;
			ptr += block->size;
		}
	} while(size);
}

void process_free(mt_process *process, mt_msg *mt_msg, void *payload)
{
	struct rb_block *block = NULL;
	unsigned long ptr;

	if (process->is_64bit) {
		struct _mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
	}
	else {
		struct _mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
	}

	block = process_rb_search(&process->block_table, ptr);
	if (block) {
		if (is_mmap(block->stack_node->stack->operation))
			fprintf(stderr, ">>> block missmatch MAP<>MALLOC %#lx found\n", ptr);

		process_rb_delete_block(process, block);
	}
	else
		fprintf(stderr, ">>> block %#lx not found (pid=%d, tid=%d)\n", ptr, process->pid, mt_msg->tid);
}

void process_alloc(mt_process *process, mt_msg *mt_msg, void *payload)
{
	struct rb_block *block = NULL;
	uint32_t payload_len = mt_msg->payload_len;
	unsigned long *stack_data;
	uint32_t stack_size;
	unsigned long ptr;
	unsigned long size;

	if (process->is_64bit) {
		struct _mt_alloc_payload_64 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);

		stack_data = payload + sizeof(*mt_alloc);
		stack_size = (payload_len - sizeof(*mt_alloc));
	}
	else {
		struct _mt_alloc_payload_32 *mt_alloc = payload;

		ptr = process->get_ulong(&mt_alloc->ptr);
		size = process->get_ulong(&mt_alloc->size);

		stack_data = payload + sizeof(*mt_alloc);
		stack_size = (payload_len - sizeof(*mt_alloc));
	}

	block = process_rb_search(&process->block_table, ptr);
	if (block) {
		fprintf(stderr, ">>> block collison %s ptr %#lx size %lu pid %d tid %d\n", str_operation(mt_msg->operation), ptr, size, process->pid, mt_msg->tid);

		process_rb_delete_block(process, block);
	}

	struct rb_stack *stack = stack_add(process, process->pid, stack_data, stack_size, mt_msg->operation);

	if (process_rb_insert_block(process, ptr, size, stack, 0))
		abort();

	process->total_allocations++;
	process->bytes_used += size;

	stack->tsc = process->tsc++;
}

void process_reinit(mt_process *process, int swap_endian, int is_64bit)
{
	process_reset(process);
	process_init(process, swap_endian, is_64bit);
}

mt_process *process_new(pid_t pid, int swap_endian, int is_64bit)
{
	mt_process *process = malloc(sizeof(*process));

	memset(process, 0, sizeof(*process));

	process->pid = pid;
	process->write_maps = 0;
	process->block_table = RB_ROOT;
	process->stack_table = RB_ROOT;
	INIT_LIST_HEAD(&process->map_list);

	process_init(process, swap_endian, is_64bit);

	return process;
}

void process_exit(mt_process *process)
{
	process_reinit(process, process->swap_endian, process->is_64bit);
	process_set_status(process, MT_PROCESS_EXIT);
}

void process_set_status(mt_process *process, mt_processStatus status)
{
	process->status = status;
}

void process_delete(mt_process *process)
{
	process_reset(process);
	free(process);
}

static void process_block_foreach(mt_process *process, void (*func)(struct rb_block *, void *), void *user)
{
	struct rb_node *data;

	for(data = rb_first(&process->block_table); data; data = rb_next(data))
		func(container_of(data, struct rb_block, node), user);
}

static const char *process_get_status(mt_process *process)
{
	const char *str;

	switch(process->status) {
	case MT_PROCESS_RUNNING:
		str = "running";
		break;
	case MT_PROCESS_EXIT:
		str = "exited";
		break;
	case MT_PROCESS_IGNORE:
		str = "ignored";
		break;
	default:
		str = "unknown";
		break;
	}
	return str;
}

void process_status(mt_process *process)
{
	printf(
		"process %d status\n"
		" bytes used: %lu\n"
		" number of open allocations: %lu\n"
		" total number of allocations: %lu\n"
		" average allocation: %f bytes\n"
		" number of allocators: %lu\n"
		" number of leaks: %lu\n"
		" number of leaked bytes: %llu\n"
		" status: %s\n",
		process->pid,
		process->bytes_used,
		process->n_allocations,
		process->total_allocations,
		process->n_allocations ? (double)process->bytes_used / process->n_allocations : 0.0,
		process->stack_trees,
		process->leaks,
		process->leaked_bytes,
		process_get_status(process)
	);
}

struct block_helper {
	mt_process *process;
	unsigned int	len;
	unsigned long	mask;
	unsigned long	fmask;
	unsigned long	fmode;
	void * 		data;
};

struct map_helper {
	mt_process *process;
	void *data;
};

static void set_map(struct map *map, void *data)
{
	struct map_helper *mh = data;

	mh->process->put_ulong(mh->data, map->addr);
	mh->data += mh->process->ptr_size;
	
	mh->process->put_ulong(mh->data, map->size);
	mh->data += mh->process->ptr_size;
}

static void *prepare_maps(mt_process *process, void *data)
{
	struct map_helper mh = { .process = process, .data = data };

	process_walk_map(process, PERM_W, set_map, &mh);

	return mh.data;
}

static void set_block(struct rb_block *block, void *data)
{
	struct block_helper *bh = data;
	unsigned long addr;

	if ((block->flags & bh->fmask) != 0)
		return;

	if ((block->flags & bh->fmode) != bh->fmode)
		return;

	block->flags |= BLOCK_SCANNED;

	for (addr = (unsigned long) block->addr; addr & bh->mask; bh->mask >>= 1)
		;

	bh->process->put_ulong(bh->data, block->addr);
	bh->data += bh->process->ptr_size;

	bh->len++;
}

static void *prepare_blocks(mt_process *process, void *addr, unsigned long *n, unsigned long *mask, unsigned long fmask, unsigned long fmode)
{
	struct block_helper bh = { .process = process, .len = 0, .mask = ~0, .data = addr, .fmask = fmask | BLOCK_IGNORE, .fmode = fmode };

	process_block_foreach(process, set_block, &bh);

	*n = bh.len;
	*mask = bh.mask;

	return bh.data;
}

void process_leaks_scan(mt_server *server, mt_process *process, int mode)
{
	mt_scan_payload *payload;
	unsigned int payload_len;
	void *addr;
	unsigned long n;
	unsigned long mask;
	unsigned long fmask;
	unsigned long fmode;

	if (!process->n_allocations)
		return;

	switch(mode) {
	case SCAN_ALL:
		fmask = 0;
		fmode = 0;
		break;
	case SCAN_NEW:
		fmask = BLOCK_SCANNED;
		fmode = 0;
		break;
	case SCAN_LEAK:
		fmask = 0;
		fmode = BLOCK_LEAKED;
		break;
	default:
		return;
	}

	if (MT_SEND_MSG(server, process, MT_XMAP, 0, 0, NULL) <= 0)
		return;

	if (server_wait_op(server, MT_XMAP) == FALSE)
		return;

	payload_len = sizeof(*payload) + (process->n_allocations + process->write_maps * 2) * process->ptr_size;

	payload = malloc(payload_len);
	if (!payload) {
		fprintf(stderr, "leak scan: out of memory!\n");
		return;
	}
	memset(payload, 0, payload_len);

	addr = payload->data;
	addr = prepare_maps(process, addr);
	addr = prepare_blocks(process, addr, &n, &mask, fmask, fmode);

	printf("scanning %lu allocations\n", n);
	if (n) {
		payload_len = sizeof(*payload) + (n + process->write_maps * 2) * process->ptr_size;

		payload->maps = process->val32(process->write_maps);
		payload->ptr_size = process->val32(process->ptr_size);
		payload->mask = process->val64(mask);

		if (MT_SEND_MSG(server, process, MT_SCAN, 0, payload_len, payload, 0, NULL) > 0)
			server_wait_op(server, MT_SCAN);

		free(payload);
	}

	if (MT_SEND_MSG(server, process, MT_CONT, 0, 0, NULL) <= 0)
		return;
}

