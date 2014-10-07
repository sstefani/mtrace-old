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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base.h"
#include "client.h"
#include "common.h"
#include "job.h"
#include "process.h"

struct block_helper {
	mt_process *	process;
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

static void set_ignore(struct alloc_block *block, void *data)
{
	block->flags |= BLOCK_IGNORE;
}

void mark_ignore(mt_process *process)
{
	process = process_clone_of(process);

	process_block_foreach(process, set_ignore, NULL);
}

static void set_map(struct file_map *map, void *data)
{
	struct map_helper *mh = data;

	mh->process->put_ulong(mh->data, map->start);
	mh->data += mh->process->ptr_size;
	
	mh->process->put_ulong(mh->data, map->len);
	mh->data += mh->process->ptr_size;
}

static void *prepare_maps(mt_process *process, void *data)
{
	struct map_helper mh = { .process = process, .data = data };

	process_walk_map(process, PERM_W, set_map, &mh);

	return mh.data;
}

static void set_block(struct alloc_block *block, void *data)
{
	struct block_helper *bh = data;
	unsigned long addr;

	if ((block->flags & bh->fmask) != 0)
		return;

	if ((block->flags & bh->fmode) != bh->fmode)
		return;

	block->flags |= BLOCK_SCANNED;

	assert(bh->len < bh->process->n_allocations);

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

void leaks_scan(mt_server *server, mt_process *process, int mode)
{
	mt_scan_payload *payload;
	unsigned int payload_len;
	void *addr;
	unsigned long n;
	unsigned long mask;
	unsigned long fmask;
	unsigned long fmode;

	process = process_clone_of(process);

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

void dump_stacks(mt_server *server, mt_process *process, void (*dump)(mt_process *process, const char *outfile), const char *outfile)
{
	process = process_clone_of(process);

	if (!process->n_allocations)
		return;

	if (server->fd != -1) {
		if (MT_SEND_MSG(server, process, MT_XMAP, 0, 0, NULL) <= 0)
			return;

		if (server_wait_op(server, MT_XMAP) == FALSE)
			return;

		if (MT_SEND_MSG(server, process, MT_CONT, 0, 0, NULL) <= 0)
			return;
	}

	dump(process, outfile);
}

void get_info(mt_server *server)
{
	if (server->fd != -1) {
		if (MT_SEND_MSG(server, server_first_process(server), MT_INFO, 0, 0, NULL) <= 0)
			return;

		if (server_wait_op(server, MT_INFO) == FALSE)
			return;
	}

	if (server->info.version != MEMTRACE_SI_VERSION) {
		if (server->info.version != 1)
			fatal("server version v%u does not match client version v%u\n", server->info.version, MEMTRACE_SI_VERSION);
		server->info.page_size = 4096;
	}

	printf("server info:\n");
	printf(" version: %u\n", server->info.version);
	printf(" follow fork: %s\n", server->info.mode & MEMTRACE_SI_FORK ? "yes" : "no");
	printf(" follow exec: %s\n", server->info.mode & MEMTRACE_SI_EXEC ? "yes" : "no");
	printf(" verbose: %s\n", server->info.mode & MEMTRACE_SI_VERBOSE ? "yes" : "no");
	printf(" do trace: %s\n", server->info.do_trace ? "yes" : "no");
	printf(" stack depth: %u\n", server->info.stack_depth);
	printf(" page size: %u\n", server->info.page_size);
}

