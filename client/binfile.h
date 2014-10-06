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
