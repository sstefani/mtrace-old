/*
 * process jobs: send commands to the server and handle the results
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

void leaks_scan(mt_server *server, mt_process *process, int mode)
{
	process_leaks_scan(server, process, mode);
}

void dump_stacks(mt_server *server, mt_process *process, void (*dump)(mt_process *process, const char *outfile), const char *outfile)
{
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

