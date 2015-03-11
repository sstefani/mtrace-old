/*
 * header of common functions, defintions and types
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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <errno.h>
#include <semaphore.h>
#include <stdarg.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "memtrace.h"

#define STREAM_PORT	4576

#define	fatal(fmt...)	_fatal(__FILE__,__PRETTY_FUNCTION__,__LINE__ , ##fmt),abort()

/**
 * Macro to convert a constant number value into a string constant
 */
#define XSTR(x)	#x
#define STR(x)	XSTR(x)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


#define	MEMTRACE_SI_VERSION	3

#define	MEMTRACE_SI_FORK	1
#define	MEMTRACE_SI_EXEC	2
#define	MEMTRACE_SI_VERBOSE	4

struct memtrace_si {
	uint8_t	version;
	uint8_t	mode;
	uint8_t	do_trace;
	uint8_t stack_depth;
	uint32_t page_size;
};

struct memtrace_shm {
	struct memtrace_si info;
	uint64_t connection_count;
	union {
		sem_t sem;
		char __size[32];
	};
	char comm_path[64];
};

static const int const_int_1 = 1;

struct sock_descr {
	union {
		struct sockaddr_un u_addr;
		struct sockaddr_in i_addr;
	} addr;

	socklen_t addrlen;

	int domain;
	int proto;
};

void _fatal(const char *file, const char *func, int line, const char *format, ...) __attribute__((visibility("hidden")));

char *safe_strncpy(char *dst, const char *src, size_t size) __attribute__((visibility("hidden")));

int safe_read(int fd, void *dest, size_t n) __attribute__((visibility("hidden")));

int sock_addr_unix(const char *path, struct sock_descr *descr) __attribute__((visibility("hidden")));

int sock_addr_inet(const char *path, struct sock_descr *descr) __attribute__((visibility("hidden")));

int sock_addr(const char *path, struct sock_descr *descr) __attribute__((visibility("hidden")));

int mt_send_msg(int fd, mt_operation op, uint32_t pid, uint32_t tid, size_t payload_len, void *payload, ...) __attribute__((visibility("hidden")));

#endif

