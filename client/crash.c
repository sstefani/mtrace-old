/*
 * crash handler
 *  shows call stack, function and source file and line number
 *  of the crash
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

#include <dlfcn.h>
#include <execinfo.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DIM(x)  (sizeof(x) / sizeof(*x))

static void report_fault(int signo, siginfo_t* siginf, void* arg)
{
	int ret;
	int i;
	void *trace[48];
	char **strings;
	char cmd[128];

	fprintf(stderr, "fault signal %d (%s)\n", signo, strsignal(signo));

	ret = backtrace(trace, DIM(trace));

	if (ret) {
		strings = backtrace_symbols(trace, ret);
		if (strings == NULL) {
			perror("backtrace_symbols");
			exit(EXIT_FAILURE);
		}

		for (i = 0; i < ret; ++i) {
			fprintf(stderr, "%d %s ", i, strings[i]);
			sprintf(cmd, "addr2line -e /proc/%d/exe %p\n", getpid(), trace[i]);
			system(cmd);
		}
	}
	fflush(stderr);
	_exit(EXIT_FAILURE);
}

void install_crash_handler(void)
{
	struct sigaction act;
	const int siglist[] = { SIGSEGV, SIGABRT, SIGILL };
	unsigned int i;

	for(i = 0; i < DIM(siglist); i++) {
		act.sa_flags = SA_ONESHOT | SA_SIGINFO;
		act.sa_sigaction = report_fault;
		sigfillset(&act.sa_mask);
		sigaction(siglist[i], &act, NULL);
	}
}

