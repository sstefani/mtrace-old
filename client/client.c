/*
 * client side process handling
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
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "binfile.h"
#include "client.h"
#include "common.h"
#include "rbtree.h"

struct rb_process {
	struct rb_node node;
	mt_process *process;
};

static struct rb_process *pid_rb_search(struct rb_root *root, pid_t pid)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct rb_process *data = (struct rb_process *) node;

		if (pid < data->process->pid)
			node = node->rb_left;
		else if (pid > data->process->pid)
			node = node->rb_right;
		else
			return data;
	}
	return NULL;
}

static mt_process *pid_rb_delete(struct rb_root *root, pid_t pid)
{
	struct rb_process *data = pid_rb_search(root, pid);
	mt_process *process;

	if (data) {
		process = data->process;
		
		rb_erase(&data->node, root);
		free(data);
	
		return process;
	}
	return NULL;
}

static int process_rb_insert(struct rb_root *root, mt_process *process)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct rb_process *data;

	/* Figure out where to put new node */
	while (*new) {
		struct rb_process *this = (struct rb_process *) *new;

		parent = *new;
		if (process->pid < this->process->pid)
			new = &((*new)->rb_left);
		else if (process->pid > this->process->pid)
			new = &((*new)->rb_right);
		else
			return FALSE;
	}

	data = malloc(sizeof(*data));
	data->process = process;

	/* Add new node and rebalance tree. */
	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);

	return TRUE;
}

static void create_control_socket(mt_server *server, const char *sock_path)
{
	struct sock_descr descr;

	if (sock_addr(sock_path, &descr) < 0)
		fatal("can't open socket path: %s\n", sock_path);

	server->fd = socket(descr.domain, SOCK_STREAM, descr.proto);
	if (server->fd < 0)
		fatal("socket: %s", strerror(errno));

	if (connect(server->fd, &descr.addr.u_addr, descr.addrlen) == -1)
		fatal("connect: %s", strerror(errno));
}

static void swap_msg(mt_msg *mt_msg)
{
	mt_msg->operation = bswap_16(mt_msg->operation);
	mt_msg->payload_len = bswap_32(mt_msg->payload_len);
	mt_msg->pid = bswap_32(mt_msg->pid);
	mt_msg->tid = bswap_32(mt_msg->tid);
}

static int socket_read_msg(mt_server *server, mt_msg *mt_msg, void **payload, int *swap_endian)
{
	if (TEMP_FAILURE_RETRY(safe_read(server->fd, mt_msg, sizeof(*mt_msg))) <= 0)
		return FALSE;

	if (mt_msg->operation > 0xff) {
		swap_msg(mt_msg);

		*swap_endian = 1;
	}
	else
		*swap_endian = 0;

	if (mt_msg->payload_len) {
		*payload = malloc(mt_msg->payload_len);

		if (TEMP_FAILURE_RETRY(safe_read(server->fd, *payload, mt_msg->payload_len)) <= 0)
			return FALSE;
	}

	return TRUE;
}

static pid_t pid_payload(mt_process *process, void *payload)
{
	mt_pid_payload *mt_pid = payload;

	return process->val32(mt_pid->pid);
}

void server_close(mt_server *server)
{
	if (server->fd != -1) {
		io_del_watch(server->fd);
		close(server->fd);
		server->fd = -1;
	}
}

void server_broken(mt_server *server)
{
	if (server->fd != -1) {
		fprintf(stderr, "connection lost\n");
		server_close(server);
	}
}
static inline int test_64bit_support(int is_64bit)
{
	return !is_64bit || sizeof(unsigned long) == 8;
}

static int socket_func(void *data, short revent)
{
	mt_msg mt_msg;
	mt_server *server = data;
	mt_process *process;
	void *payload = NULL;
	int swap_endian;
	int is_64bit;

	if (socket_read_msg(server, &mt_msg, &payload, &swap_endian) == FALSE) {
		server_broken(server);
		return -1;
	}

	if (mt_msg.operation & MT_64BIT) {
		mt_msg.operation &= ~MT_64BIT;
		is_64bit = 1;
	}
	else
		is_64bit = 0;

	process = server_find_process(server, mt_msg.pid);
	if (!process) {
		process = process_new(mt_msg.pid, swap_endian, is_64bit);

		server_add_process(server, process);

		if (!test_64bit_support(is_64bit))
			fprintf(stderr, "64 bit processes with pid %d not supported on 32 bit hosts\n", mt_msg.pid);
	}

	if (
		(process->swap_endian == swap_endian) &&
		(process->is_64bit == is_64bit)
	) {
		switch(mt_msg.operation) {
		case MT_NONE:
			break;
		case MT_ALLOC:
		case MT_REALLOC:
		case MT_FREE:
		case MT_MEMALIGN:
		case MT_POSIX_MEMALIGN:
		case MT_ALIGNED_ALLOC:
		case MT_VALLOC:
		case MT_PVALLOC:
		case MT_MMAP:
		case MT_MUNMAP:
			process_alloc(server, process, &mt_msg, payload);
			break;
		case MT_FORK:
			process_duplicate(process, server_find_process(server, pid_payload(process, payload)));
			break;
		case MT_NEW:
			process_reinit(process, swap_endian, is_64bit);
			break;
		case MT_CLONE:
//			process_set_clone(process, server_find_process(server, pid_payload(process, payload)));
			break;
		case MT_EXIT:
			process_set_status(process, MT_PROCESS_EXITING);
			break;
		case MT_SCAN:
			process_scan(process, payload, mt_msg.payload_len);
			break;
		case MT_XMAP:
			process_read_map(process, payload, mt_msg.payload_len);
			break;
		case MT_INFO:
			memcpy(&server->info, payload, sizeof(server->info));
			break;
		default:
			fatal("protocol violation 0x%08x", mt_msg.operation);
		}
	}

	if (payload)
		free(payload);

	return mt_msg.operation;
}

int server_wait_op(mt_server *server, mt_operation op)
{
	int			ret;
	struct pollfd		pfd[1];

	pfd[0].fd = server->fd;
	pfd[0].events = POLL_IN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for(;;) {
		if (server->fd == -1)
			return FALSE;

		ret = TEMP_FAILURE_RETRY(poll(pfd, 1, -1));

		if (ret == -1)
			break;

		if (pfd[0].revents & (POLLIN|POLLPRI)) {
			if (socket_func(server, pfd[0].revents) == op)
				break;
		}
	}
	return TRUE;
}

mt_server *server_connect(const char *sock_path)
{
	mt_server *server = malloc(sizeof(*server));

	server->pid_table = RB_ROOT;
	server->first_pid = 0;
	server->info.version = 0;
	server->info.mode = 0;
	server->info.do_trace = 0;
	server->info.stack_depth = 0;

	create_control_socket(server, sock_path);

	io_add_watch(server->fd, POLL_IN | POLLPRI | POLLERR | POLLHUP | POLLNVAL, socket_func, server);

	return server;
}

static int server_release_process(struct rb_node *node, void *user)
{
	struct rb_process *data = (struct rb_process *)node;

	process_finalize(data->process);
	free(data);
	return 0;
}

void server_finalize(mt_server *server)
{
	server_close(server);

	rb_iterate(&server->pid_table, server_release_process, NULL);
}

static int server_iterate_process(struct rb_node *node, void *user)
{
	struct rb_process *data = (struct rb_process *)node;
	int (*func)(mt_process *process) = user;

	return func(data->process);
}

void server_iterate_processes(mt_server *server, int (*func)(mt_process *process))
{
	rb_iterate(&server->pid_table, server_iterate_process, func);
}

mt_process *server_find_process(mt_server *server, pid_t pid)
{
	struct rb_process *data;

	data = pid_rb_search(&server->pid_table, pid);
	if (data)
		return data->process;
	return NULL;
}

mt_process *server_first_process(mt_server *server)
{
	if (!server->first_pid)
		return NULL;
	return server_find_process(server, server->first_pid);
}

void server_add_process(mt_server *server, mt_process *process)
{
	if (!server->first_pid)
		server->first_pid = process->pid;

	process_rb_insert(&server->pid_table, process);
}

void server_remove_process(mt_server *server, mt_process *process)
{
	process = pid_rb_delete(&server->pid_table, process->pid);

	if (process)
		free(process);
}


