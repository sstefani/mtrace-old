/*
 * common defintions, types and functions
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

#ifndef __BASE_H__
#define __BASE_H__

#include <byteswap.h>
#include <poll.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "bfdinc.h"
#include "list.h"
#include "memtrace.h"
#include "rbtree.h"

#define	MT_SEND_MSG(server, process, op, tid, payload_len, payload...) \
({ \
	int __ret = mt_send_msg( \
		server->fd, \
		process->val16(op), \
		process->pid, \
		tid, \
		payload_len, \
		##payload \
	); \
 	if (__ret < 0) \
		server_broken(server); \
	__ret; \
})

#define PRINT_MSG(fmt, arg...)  print_msg(__FILE__, __FUNCTION__, __LINE__, "memtrace", fmt, ##arg)

#define SCAN_ALL	0
#define SCAN_LEAK	1
#define SCAN_NEW	2

struct rb_stack;

typedef enum {
	BLOCK_LEAKED = 1 << 0,
	BLOCK_SCANNED = 1 << 1,
	BLOCK_IGNORE = 2 << 1,
} block_flags;

struct alloc_block {
	unsigned long flags;
	unsigned long refcnt;
	unsigned long addr;
	unsigned long size;
	struct rb_stack *stack;
	pid_t tid;
};

struct file_map {
	struct list_head list;
	unsigned long long start;
	unsigned long long len;
	unsigned long long offset;
	unsigned char perm;
	char *fname;
	struct bin_file *binfile;
	char *real_path;
};

struct _mt_server {
	int fd;
	struct rb_root pid_table;
	int first_pid;
	struct memtrace_si info;
};

typedef struct _mt_server mt_server;

extern const char *rootpath;

extern void print_msg(const char *file, const char *func, int line, const char *info, const char *format, ...);
extern int io_add_watch(int fd, short events, int (*func)(void *, short), void *data);
extern int io_del_watch(int fd);
extern short io_set_events(int fd, short events);
extern int io_watch(int timeout);
extern char **get_search_list(void);

#endif
