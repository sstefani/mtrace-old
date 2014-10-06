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

