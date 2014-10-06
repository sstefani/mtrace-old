#ifndef __LEAKDETECT_H__
#define __LEAKDETECT_H__

#include "base.h"
#include "process.h"

extern void leaks_scan(mt_server *server, mt_process *process, int mode);
extern void dump_stacks(mt_server *server, mt_process *process, void (*dump)(mt_process *process, const char *outfile), const char *outfile);
extern void get_info(mt_server *server);

#endif
