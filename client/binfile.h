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

#ifndef BIN_FILE_H
#define BIN_FILE_H

#define PACKAGE "binfile"
#define PACKAGE_VERSION "1.0"

#include "bfdinc.h"

#undef PACKAGE
#undef PACKAGE_VERSION

struct bin_file {
	bfd *abfd;
	asymbol **syms;
};

extern struct bin_file *bin_file_new(const char *filename);
extern void bin_file_free(struct bin_file *binfile);
extern char *bin_file_lookup(struct bin_file *binfile, bfd_vma addr, unsigned long off);

#endif
