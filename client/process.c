/*
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
	struct alloc_block *block;
};

struct rb_stack {
	struct rb_node node;
	struct list_head block_list;
	void *addrs;
	uint32_t size;
	unsigned long leaks;
	unsigned long long n_allocations;
	unsigned long long total_allocations;
	unsigned long long bytes_used;
	unsigned long long bytes_leaked;
	unsigned long long tsc;
	uint16_t operation;
	char **syms;
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

static struct rb_stack *stack_add(mt_process *process, void *stack, uint32_t stack_size)
{
	struct rb_root *root = &process->stack_table;
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_stack *data;
	int ret;

	/* Figure out where to put new node */
	while (*new) {
		struct rb_stack *this = container_of(*new, struct rb_stack, node);

		parent = *new;
		ret = memncmp(stack, stack_size, this->addrs, this->size);

		if (ret < 0)
			new = &((*new)->rb_left);
		else
		if (ret > 0)
			new = &((*new)->rb_right);
		else
			return this;
	}

	data = malloc(sizeof(*data));
	if (!data)
		return NULL;

	data->addrs = malloc(stack_size * sizeof(*stack));
	data->size = stack_size;
	data->n_allocations = 0;
	data->total_allocations = 0;
	data->bytes_used = 0;
	data->leaks = 0;
	data->bytes_leaked = 0;
	data->syms = NULL;

	memcpy(data->addrs, stack, stack_size);

	INIT_LIST_HEAD(&data->block_list);

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	process->stack_trees++;

	return data;
}

void block_unref(struct alloc_block *block)
{
	if (--block->refcnt == 0)
		free(block);
}

mt_process *process_clone_of(mt_process *process)
{
	while (process->clone_of)
		process = process->clone_of;
	return process;
}

void process_walk_map(mt_process *process, unsigned char perm, mt_processMapForeachFunc func, void *user)
{
	struct list_head *pos;

	for(pos = process->map_list.next; !list_is_last(pos, &process->map_list); pos = pos->next) {
		struct file_map *map = (struct file_map *)pos;

		if (map->perm & perm)
			func(map, user);
	}
}

void process_release_map(mt_process *process)
{
	struct list_head *pos;
	struct list_head *n;

	list_for_each_safe(pos, n, &process->map_list) {
		struct file_map *map = (struct file_map *)pos;

		list_del(pos);

		if (map->binfile)
			bin_file_free(map->binfile);
		if (map->real_path)
			free(map->real_path);
		free(map->fname);
		free(map);
	}

	process->write_maps = 0;
}

void process_read_map(mt_process *process, void *data, uint32_t n)
{
	struct file_map *map;
	struct xmap *xmap;

	if(!n)
		return;

	process_release_map(process);

	for(xmap = data; (void *)xmap - data < n; xmap = XMAP_NEXT(xmap, process->val16(xmap->flen) + 1)) {
		map = malloc(sizeof(*map));

		map->binfile = NULL;

		map->start = process->val64(xmap->start);
		map->len = process->val64(xmap->end) - map->start;
		map->offset = process->val64(xmap->offset);

		map->perm = xmap->perm;

		map->fname = strdup(xmap->fname);
		map->real_path = NULL;

		if (map->perm & PERM_W)
			++process->write_maps;
#if 0
fprintf(stderr, "start: 0x%08llx len: 0x%08llx offset: 0x%08llx perm: %02x fname: %s\n",
		map->start,
		map->len,
		map->offset,
		map->perm,
		map->fname);
#endif

		list_add_tail(&map->list, &process->map_list);
	}

	map = malloc(sizeof(*map));
	map->binfile = NULL;
	map->start = ~0;
	map->len = 0;
	map->fname = NULL;
	map->real_path = NULL;

	list_add_tail(&map->list, &process->map_list);
}

static struct file_map *locate_map(mt_process *process, bfd_vma addr)
{
	struct list_head *pos;
	bfd_vma a = (bfd_vma) addr;

	for(pos = process->map_list.next; !list_is_last(pos, &process->map_list); pos = pos->next) {
		struct file_map *map = (struct file_map *)pos;

		if (*map->fname && (map->perm & PERM_X)) {
			if ((a >= map->start) && (a < map->start + map->len))
				return map;
		}
	}

	return NULL;
}

static struct file_map *open_map(mt_process *process, bfd_vma addr)
{
	struct file_map *map = locate_map(process, addr);
	char *fname;
	char *real_path;

	if (!map)
		return NULL;

	if (!map->real_path) {
		char **p = get_search_list();

		do {
			int len = strlen(*p);

			while(len && (*p)[len - 1] == '/')
				--len;

			for(fname = map->fname; *fname == '/'; ++fname)
				;

			do {
				if (asprintf(&real_path, "%.*s/%s", len, *p, fname) == -1)
					return map;

				if (!access(real_path, R_OK)) {
					map->binfile = bin_file_new(real_path);

					if (map->binfile) {
						map->real_path = real_path;
						return map;
					}
				}

				free(real_path);

				fname = strchr(fname + 1, '/');
			} while(fname++);
		} while(*++p);
	}
	return map;
}

static char *process_dump_address(mt_process *process, bfd_vma addr)
{
	struct file_map *map = open_map(process, addr);
	char *sym = NULL;

	if (!map) {
		if (asprintf(&sym, "[0x%llx] <unknown map>", (unsigned long long)addr) == -1)
			sym = NULL;
	}
	else {
		sym = bin_file_lookup(map->binfile, addr, map->start);
		if (!sym) {
			if (asprintf(&sym, "[0x%llx] %s", (unsigned long long)addr, map->fname) == -1)
				sym = NULL;
		}
	}
	return sym;
}

static void process_dump_stack(mt_process *process, struct rb_stack *stack)
{
	uint32_t i;
	void *addrs;
	uint32_t stack_size = stack->size / process->ptr_size;

	if (!stack->syms) {
		stack->syms = malloc(sizeof(*stack->syms) * stack_size);
		if (!stack->syms)
			return;

		for(addrs = stack->addrs, i = 0; i < stack_size; ++i) {
			unsigned long addr = process->get_ulong(addrs);

			if (!addr) {
				stack->syms[i] = NULL;

				continue;
			}

			stack->syms[i] = process_dump_address(process, addr);

			addrs += process->ptr_size;
		}
	}

	for(addrs = stack->addrs, i = 0; i < stack_size; ++i) {
		if (dump_printf("  %s\n", stack->syms[i]) == -1)
			return;

		addrs += process->ptr_size;
	}
}

static struct rb_block *process_rb_search_range(struct rb_root *root, unsigned long addr, unsigned long size)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_block *data = container_of(node, struct rb_block, node);

		if (addr < data->block->addr) {
			if (addr + size < data->block->addr)
				node = node->rb_left;
			else
				return data;
		}
		else
		if (data->block->addr < addr) {
			if (data->block->addr + data->block->size < addr)
				node = node->rb_right;
			else
				return data;
		}
		else
			return data;
	}
	return NULL;
}

static struct rb_block *process_rb_search(struct rb_root *root, unsigned long addr)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_block *data = container_of(node, struct rb_block, node);

		if (addr < data->block->addr)
			node = node->rb_left;
		else
		if (data->block->addr < addr)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static void process_release_mem(mt_process *process, struct alloc_block *block, unsigned int size)
{
	if (block->flags & BLOCK_LEAKED) {
		struct rb_stack *stack;

		stack = block->stack;
		if (stack) {
			stack->leaks--;
			stack->bytes_leaked -= block->size;
		}
		process->leaks--;
		process->leaked_bytes -= block->size;
	}

	if (block->stack)
		block->stack->bytes_used -= size;

	process->bytes_used -= size;
}

static void process_rb_delete_block(mt_process *process, struct rb_block *data)
{
	struct alloc_block *block;

	block = data->block;
		
	rb_erase(&data->node, &process->block_table);
	free(data);

	process_release_mem(process, block, block->size);

	process->n_allocations--;

	if (block->stack)
		block->stack->n_allocations--;

	block_unref(block);
}

static int process_rb_insert_block(struct rb_root *root, struct alloc_block *block)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_block *data;
	struct rb_stack *stack;

	/* Figure out where to put the new node */
	while (*new) {
		struct rb_block *this = container_of(*new, struct rb_block, node);

		parent = *new;
		if (block->addr < this->block->addr) {
#if 0
			if (block->addr + block->size > this->block->addr)
				return FALSE;
#endif
			new = &((*new)->rb_left);
		}
		else if (block->addr > this->block->addr)
			new = &((*new)->rb_right);
		else
			return FALSE;
	}

	data = malloc(sizeof(*data));
	data->block = block;

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	stack = block->stack;
	if (stack) {
		stack->n_allocations++;
		stack->total_allocations++;
		stack->bytes_used += block->size;
	}

	return TRUE;
}

static int process_rb_duplicate_block(struct rb_node *node, void *user)
{
	struct rb_block *data = container_of(node, struct rb_block, node);
	struct alloc_block *block = data->block;

	if (process_rb_insert_block((struct rb_root *)user, block)) {
		block->refcnt++;
		return 0;
	}
	return 1;
}

void process_duplicate(mt_process *process, mt_process *copy)
{
	process_reinit(process, process->swap_endian, process->is_64bit);

	if (!copy)
		return;

	if (rb_iterate(&copy->block_table, process_rb_duplicate_block, &process->block_table))
		fatal("rb_iterate");

	process->n_allocations = copy->n_allocations;
	process->total_allocations = copy->total_allocations;
	process->bytes_used = copy->bytes_used;
	process->stack_trees = copy->stack_trees;
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
	case MT_ALLOC:
		return "alloc";
	case MT_REALLOC:
		return "realloc";
	case MT_FREE:
		return "free";
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
	case MT_MUNMAP:
		return "munmap";
	default:
		break;
	}
	return "unknow operation";
}

static void process_dump(mt_process *process, void *sortby, int (*skipfunc)(struct rb_stack *), const char *outfile)
{
	struct rb_stack **arr;
	unsigned long i;
	void *data;
	unsigned long stack_trees = process->stack_trees; 

	arr = malloc(sizeof(struct rb_stack *) * stack_trees);
	if (!arr)
		return;

	for(i = 0, data = rb_first(&process->stack_table); data; data = rb_next(data)) {
		if (i >= stack_trees)
			goto err;

		arr[i++] = container_of(data, struct rb_stack, node);
	}

	if (i != stack_trees)
		goto err;

	qsort(arr, stack_trees, sizeof(struct rb_stack *), sortby);

	if (dump_open(outfile) == -1)
		return;

	for(i = 0; i < process->stack_trees; ++i) {
		struct rb_stack *stack = arr[i];

		if (!skipfunc(stack)) {
			if (dump_printf(
				"Stack (%s):\n"
				" bytes used: %lu\n"
				" number of open allocations: %lu\n"
				" total number of allocations: %lu\n"
				" leaked allocations: %lu (%lu bytes)\n"
				" tsc: %llu\n",
					str_operation(stack->operation),
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
	dump_close();
	return;
err:
	free(arr);
	return;
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

void *process_scan(mt_process *curr, void *leaks, uint32_t payload_size)
{
	mt_process *process = process_clone_of(curr);
	unsigned int new = 0;
	unsigned long n = payload_size / process->ptr_size;
	unsigned long i;
	void *new_leaks = leaks;

	for(i = 0; i < n; ++i) {
		struct rb_block *data = process_rb_search(&process->block_table, process->get_ulong(leaks));
		if (data) {
			struct alloc_block *block = data->block;
			struct rb_stack *stack;

			if (!(block->flags & BLOCK_LEAKED)) {
				block->flags |= BLOCK_LEAKED;

				stack = block->stack;
				if (stack) {
					stack->leaks++;
					stack->bytes_leaked += block->size;
				}
				process->leaks++;
				process->leaked_bytes += block->size;

				memcpy(new_leaks + new * process->ptr_size, leaks, process->ptr_size);
				new++;
			}
		}
		leaks += process->ptr_size;
	}

	dump_open(NULL);
	dump_printf("leaks reported: %lu\n", n);
	dump_printf("new leaks found: %u\n", new);
	dump_printf("leaked bytes: %lu\n", process->leaked_bytes);

	for(i = 0; i < new; ++i) {
		struct rb_block *data = process_rb_search(&process->block_table, process->get_ulong(new_leaks));
		if (data) {
			struct alloc_block *block = data->block;

			if (dump_printf(" leaked at 0x%08lx (%lu bytes)\n", (unsigned long)block->addr, (unsigned long)block->size) == -1)
				break;
		}
		new_leaks += process->ptr_size;
	}

	dump_printf("leaks total: %lu\n", process->leaks);

	dump_close();

	return leaks;
}

static inline unsigned long roundup_mask(unsigned long val, unsigned long mask)
{
	return (val + mask) & ~mask;
}

void process_alloc(mt_server *server, mt_process *process, mt_msg *mt_msg, void *payload)
{
	struct alloc_block *block = NULL;
	uint32_t payload_len = mt_msg->payload_len;
	unsigned long *stack;
	uint32_t stack_size;
	unsigned long old_ptr;
	unsigned long new_ptr;
	unsigned long size;
	struct rb_block *data;
	unsigned long page_mask = server->info.page_size - 1;

	if (process->is_64bit) {
		struct _mt_alloc_payload_64 *mt_alloc = payload;

		old_ptr = process->get_ulong(&mt_alloc->old_ptr);
		new_ptr = process->get_ulong(&mt_alloc->new_ptr);
		size = process->get_ulong(&mt_alloc->size);

		stack = payload + sizeof(*mt_alloc);
		stack_size = payload_len - sizeof(*mt_alloc);
	}
	else {
		struct _mt_alloc_payload_32 *mt_alloc = payload;

		old_ptr = process->get_ulong(&mt_alloc->old_ptr);
		new_ptr = process->get_ulong(&mt_alloc->new_ptr);
		size = process->get_ulong(&mt_alloc->size);

		stack = payload + sizeof(*mt_alloc);
		stack_size = payload_len - sizeof(*mt_alloc);
	}

	process = process_clone_of(process);

#if 0
	fprintf(stderr, "%s operation %s(%d) (%#lx, %#lx) size:%lu\n", __FUNCTION__, str_operation(mt_msg->operation), mt_msg->operation, old_ptr, new_ptr, size);
#endif
	if (old_ptr) {
		if (mt_msg->operation == MT_MUNMAP) {
			if (old_ptr & page_mask)
				return;

			size = roundup_mask(size, page_mask);

			do {
				data = process_rb_search_range(&process->block_table, old_ptr, size);
				if (!data)
					break;

				block = data->block;

				if (block->addr > old_ptr) {
					size -= block->addr - old_ptr;
					old_ptr = block->addr;
				}
				
				if (block->stack->operation != MT_MMAP) {
					unsigned addr = roundup_mask(block->addr + block->size, page_mask);

					if (addr - old_ptr > size)
						size = 0;
					else {
						size -= addr - old_ptr;
						old_ptr = addr;
					}
					continue;
				}

				if (block->addr == old_ptr) {
					if (size >= block->size) {
						size -= block->size;
						old_ptr += block->size;

						process_rb_delete_block(process, data);
					}
					else {
						process_release_mem(process, block, size);

						block->addr += size;
						block->size -= size;
						size = 0;
					}
				}
				else {
					unsigned off = old_ptr - block->addr;

					if (off + size < block->size) {
						struct alloc_block *new_block;

						new_block = malloc(sizeof(*block));
						new_block->refcnt = 1;

						new_block->flags = 0;
						new_block->addr = block->addr + (off + size);
						new_block->size = block->size - (off + size);
						new_block->stack = block->stack;
						new_block->tid = block->tid;

						process_release_mem(process, block, size + new_block->size);

						block->size = off;
						size = 0;

						if (!process_rb_insert_block(&process->block_table, new_block)) {
							fprintf(stderr, "split block 0x%08lx collison (pid=%d, tid=%d) %s\n", block->addr, process->pid, mt_msg->tid, str_operation(mt_msg->operation));
							free(new_block);
							return;
						}

						process->n_allocations++;
						process->total_allocations++;
						process->bytes_used += new_block->size;
					}
					else {
						process_release_mem(process, block, off);

						block->addr += off;
						block->size -= off;
						size -= block->size;

						old_ptr += block->size;
					}
				}
			} while(size);
		}
		else {
			data = process_rb_search(&process->block_table, old_ptr);

			if (data && data->block->stack->operation != MT_MMAP)
				process_rb_delete_block(process, data);
		}
	}

	if (new_ptr) {
		if (mt_msg->operation == MT_MMAP) {
			if (new_ptr  & page_mask)
				return;

			size = roundup_mask(size, page_mask);
		}

		if (!size)
			return;

		block = malloc(sizeof(*block));
		block->refcnt = 1;

		block->flags = 0;
		block->addr = new_ptr;
		block->size = size;

		block->stack = stack_add(process, stack, stack_size);
		block->tid = mt_msg->tid;
		block->stack->tsc = process->tsc++;
		block->stack->operation = mt_msg->operation;

		if (process_rb_insert_block(&process->block_table, block)) {
			process->n_allocations++;
			process->total_allocations++;
			process->bytes_used += block->size;

			return;
		}

		fprintf(stderr, "block 0x%08lx collison (pid=%d, tid=%d) %s\n", block->addr, process->pid, mt_msg->tid, str_operation(mt_msg->operation));
		free(block);
	}
}

void process_reset(mt_process *process)
{
	struct rb_block *rbb, *rbb_next;
	struct rb_block *rbs, *rbs_next;

	process_release_map(process);

	rbtree_postorder_for_each_entry_safe(rbb, rbb_next, &process->block_table, node) {
		block_unref(rbb->block);
		free(rbb);
	}

	rbtree_postorder_for_each_entry_safe(rbs, rbs_next, &process->stack_table, node)
		free(rbs);

	process->block_table = RB_ROOT;
	process->stack_table = RB_ROOT;

	process->n_allocations = 0;
	process->total_allocations = 0;
	process->bytes_used = 0;
	process->stack_trees = 0;
	process->leaks = 0;
	process->leaked_bytes = 0;
	process->tsc = 0;
}

void process_reinit(mt_process *process, int swap_endian, int is_64bit)
{
	process_reset(process);

	process->status = MT_PROCESS_INIT;
	process->program_name = NULL;
	process->write_maps = 0;
	process->is_64bit = is_64bit;
	
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
}

mt_process *process_new(pid_t pid, int swap_endian, int is_64bit)
{
	mt_process *process = malloc(sizeof(*process));

	memset(process, 0, sizeof(*process));

	process->pid = pid;
	process->clone_of = NULL;
	INIT_LIST_HEAD(&process->map_list);
	process->swap_endian = swap_endian;

	process_reinit(process, swap_endian, is_64bit);

	return process;
}

void process_set_clone(mt_process *process, mt_process *clone)
{
	process->clone_of = clone;
}

void process_finalize(mt_process *process)
{
	process_reinit(process, process->swap_endian, process->is_64bit);

	free(process->program_name);
}

void process_set_status(mt_process *process, mt_processStatus status)
{
	process->status = status;
}

void process_block_foreach(mt_process *process, mt_processBlockForeachFunc func, void *user)
{
	struct rb_node *data;

	for(data = rb_first(&process->block_table); data; data = rb_next(data))
		func(container_of(data, struct rb_block, node)->block, user);
}

void process_status(mt_process *process)
{
	printf(
		"bytes used: %lu\n"
		"number of open allocations: %lu\n"
		"total number of allocations: %lu\n"
		"average allocation: %f bytes\n"
		"number of allocators: %lu\n"
		"number of leaks: %lu\n"
		"number of leaked bytes: %llu\n",
		process->bytes_used,
		process->n_allocations,
		process->total_allocations,
		process->n_allocations ? (double)process->bytes_used / process->n_allocations : 0.0,
		process->stack_trees,
		process->leaks,
		process->leaked_bytes);
}

