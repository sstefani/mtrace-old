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

#ifndef __LEAKDETECT_H__
#define __LEAKDETECT_H__

#include "base.h"
#include "process.h"

extern void leaks_scan(mt_server *server, mt_process *process, int mode);
extern void dump_stacks(mt_server *server, mt_process *process, void (*dump)(mt_process *process, const char *outfile), const char *outfile);
extern void get_info(mt_server *server);

#endif
