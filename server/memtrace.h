/*
 * message defintion for communication between client and server
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

#ifndef __MEMTRACE_H__
#define __MEMTRACE_H__

#include <stdint.h>

#define PERM_R	1
#define PERM_W	2
#define PERM_X	4

#if __LP64__
#define	PTR64
#else
#define	PTR32
#endif

#if __LP64__
#define	_mt_alloc_payload	_mt_alloc_payload_64	
#else
#define	_mt_alloc_payload	_mt_alloc_payload_32	
#endif

typedef struct _mt_alloc_payload mt_alloc_payload;
typedef struct _mt_pid_payload mt_pid_payload;
typedef struct _mt_scan_payload mt_scan_payload;

typedef struct _mt_msg mt_msg;

typedef enum {
	MT_NONE,
	MT_MALLOC,
	MT_REALLOC,
	MT_FREE,
	MT_EXEC,
	MT_NEW,
	MT_FORK,
	MT_CLONE,
	MT_EXIT,
	MT_SCAN,
	MT_XMAP,
	MT_STOP,
	MT_START,
	MT_CONT,
	MT_MEMALIGN,
	MT_POSIX_MEMALIGN,
	MT_ALIGNED_ALLOC,
	MT_VALLOC,
	MT_PVALLOC,
	MT_INFO,
	MT_MMAP,
	MT_MMAP64,
	MT_MUNMAP,
} mt_operation;

#define	MT_64BIT	128

struct _mt_msg {
	uint16_t operation; \
	uint32_t pid; \
	uint32_t tid; \
	uint32_t payload_len;
};

struct _mt_alloc_payload_64 {
	uint64_t ptr;
	uint64_t size;
	uint64_t data[0];
};

struct _mt_alloc_payload_32 {
	uint32_t ptr;
	uint32_t size;
	uint32_t data[0];
};

struct _mt_pid_payload {
	uint32_t pid;
};

struct __attribute__((packed)) xmap {
	uint64_t start;
	uint64_t end;
	uint64_t offset;
	uint16_t flen;
	char fname[0];
};

struct _mt_scan_payload {
	uint32_t ptr_size;
	uint64_t mask;
	char data[0];
};

#define	XMAP_ALIGN(n)		((sizeof(struct xmap) + (n) + 7) & ~7)
#define	XMAP_NEXT(x, flen)	(struct xmap *)(((void *)x) + XMAP_ALIGN(flen))

#endif
