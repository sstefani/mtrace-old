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

#include <byteswap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "common.h"

void _fatal(const char *file, const char *func, int line, const char *format, ...)
{
	va_list args;
	char *message = NULL;

	va_start(args, format);
	if (vasprintf(&message, format, args) == -1)
		abort();
	va_end(args);

	fprintf(stderr,"%s(%s:%d):\n %s\n", file, func, line, message);

	free(message);
}

char *safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size)
		return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

int safe_read(int fd, void *dest, size_t n)
{
	int off = 0;
	ssize_t ret;

	for(;;) {
		ret = TEMP_FAILURE_RETRY(read(fd, dest + off, n));

		if (ret <= 0)
			return ret;

		if (ret >= n)
			break;

		off += ret;
		n -= ret;
	}
	return off + n;
}

int sock_addr_unix(const char *path, struct sock_descr *descr)
{
	struct stat statbuf;

	if (stat(path, &statbuf) >= 0) {
		if (!S_ISSOCK(statbuf.st_mode))
			return -1;
	}

	descr->addr.u_addr.sun_family = AF_UNIX;
	safe_strncpy(descr->addr.u_addr.sun_path, path, sizeof(descr->addr.u_addr.sun_path));
	descr->addrlen = sizeof(descr->addr.u_addr.sun_family) + strlen(descr->addr.u_addr.sun_path);
	descr->domain = PF_UNIX;
	descr->proto = 0;

	return 0;
}

int sock_addr_inet(const char *path, struct sock_descr *descr)
{
	struct in_addr in_addr = { .s_addr= INADDR_ANY };
	int port = STREAM_PORT;
	int ret = 0;
	char *p;
	char *addr;
	
	if (!*path)
		return -1;

	addr = alloca(strlen(path));

	strcpy(addr, path);

	p = strchr(addr, ':');
	if (p) {
		port = atoi(p + 1);

		if (port < 1 || port > 65535)
			return -1;

		*p = 0;
	}

	if (addr != p) {
		if (!inet_aton(addr, &in_addr))
			return -1;
	}

	descr->addr.i_addr.sin_family = AF_INET;
	descr->addr.i_addr.sin_addr.s_addr = in_addr.s_addr;
	descr->addr.i_addr.sin_port = htons(port);
	descr->addrlen = sizeof(descr->addr.i_addr);
	descr->domain = PF_INET;
	descr->proto = IPPROTO_TCP;

	return ret;
}

int sock_addr(const char *path, struct sock_descr *descr)

{
	if (*path == '/')
		return sock_addr_unix(path, descr);

	return sock_addr_inet(path, descr);
}

int mt_send_msg(int fd, mt_operation op, uint32_t pid, uint32_t tid, size_t payload_len, void *payload, ...)
{
	mt_msg mt_msg;
	struct iovec	io[3];
	struct msghdr	msghdr;
	va_list va;
	int ret;

	if (fd == -1)
		return 0;

	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_iov = io;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = 0;
	msghdr.msg_controllen = 0;
	msghdr.msg_flags = 0;

	io[0].iov_base = &mt_msg;
	io[0].iov_len = sizeof(mt_msg);

	if (payload) {
		size_t payload2_len;
		void *payload2;

		io[1].iov_base = payload;
		io[1].iov_len = payload_len;

		msghdr.msg_iovlen++;

		va_start(va, payload);
		payload2_len = va_arg(va, size_t);
		payload2 = va_arg(va, void *);
		va_end(va);

		if (payload2) {
			payload_len += payload2_len;

			io[2].iov_base = payload2;
			io[2].iov_len = payload2_len;
			
			msghdr.msg_iovlen++;
		}
	}

	mt_msg.operation = op;

	if (op > 0xff) {
		mt_msg.pid = bswap_32(pid);
		mt_msg.tid = bswap_32(tid);
		mt_msg.payload_len = bswap_32(payload_len);
	}
	else {
		mt_msg.pid = pid;
		mt_msg.tid = tid;
		mt_msg.payload_len = payload_len;
	}

	ret = TEMP_FAILURE_RETRY(sendmsg(fd, &msghdr, MSG_NOSIGNAL));
	
	if (ret != sizeof(mt_msg) + payload_len) {
		close(fd);
		return -1;
	}

	return ret;
}

