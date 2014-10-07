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

#ifndef __SERVER_H__
#define __SERVER_H__

#include "process.h"

extern mt_server *server_connect(const char *port);

extern void server_finalize(mt_server *server);

extern mt_process *server_first_process(mt_server *server);
extern mt_process *server_find_process(mt_server *server, pid_t pid);
extern void server_iterate_processes(mt_server *server, int (*func)(mt_process *process));
extern void server_add_process(mt_server *server, mt_process *process);
extern void server_remove_process(mt_server *server, mt_process *process);
extern int server_wait_op(mt_server *server, mt_operation op);
extern void server_close(mt_server *server);
extern void server_broken(mt_server *server);

#endif
