#ifndef __DUMP_H__
#define __DUMP_H__

int dump_prompt(int prompt);
int dump_open(const char *outfile);
int dump_printf(const char *fmt, ...);
int dump_close(void);

#endif

