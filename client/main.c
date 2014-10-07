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

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "binfile.h"
#include "base.h"
#include "client.h"
#include "common.h"
#include "crash.h"
#include "dump.h"
#include "job.h"

#define	PROGNAME "memtrace"

struct io_watch_event {
	int (*func)(void *, short);
	void *data;
};

struct cmd_opt {
	const char *name;
	int match_len;
	void *data;
	const char *info;
	const char *usage;
	struct cmd_opt *options;
};

typedef	int (*opt_call)(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[]);
typedef	int (*cmd_call)(struct cmd_opt *cmd, int argc, const char *argv[]);

static int do_dump(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_help(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_proclist(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_quit(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_reset(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_scan(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_set(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_show(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_status(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_start(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_stop(struct cmd_opt *cmd, int argc, const char *argv[]);
static int do_set_prompt(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[]);
static int do_set_searchpath(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[]);
static int do_show_info(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[]);
static int do_show_prompt(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[]);
static int do_show_searchpath(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[]);

const char dump_str[] = "dump";
const char help_str[] = "help";
const char proclist_str[] = "proclist";
const char quit_str[] = "quit";
const char reset_str[] = "reset";
const char scan_str[] = "scan";
const char set_str[] = "set";
const char show_str[] = "show";
const char start_str[] = "start";
const char status_str[] = "status";
const char stop_str[] = "stop";

struct pollfd *io_watch_poll;
struct io_watch_event *io_watch_event;
static unsigned int io_watch_size;
static unsigned int io_watch_elems;
static mt_server *server;
static const char *sock_path = ":" STR(STREAM_PORT);
static char **search_list;
static const char *outfile;

static struct cmd_opt dump_opts[] = {
	{ "allocations", 2, process_dump_sort_allocations, "sort by number of open allocations" },
	{ "average", 2, process_dump_sort_average, "sort by average allocation of bytes (usage / allocations)" },
	{ "bytes-leaked", 1, process_dump_sort_bytes_leaked, "sort by number of leaked bytes" },
	{ "leaks", 1, process_dump_sort_leaks, "sort by number of detected leaks" },
	{ "stacks", 1, process_dump_stacks, "dump all stack sort by number of total allocations" },
	{ "total", 2, process_dump_sort_total, "sort by number of total allocations" },
	{ "tsc", 2, process_dump_sort_tsc, "sort by time stamp counter" },
	{ "usage", 1, process_dump_sort_usage, "sort by number of bytes" },
	{ NULL, 0, NULL, "\n use > to dump the output into a file" },
};

static struct cmd_opt set_opts[] = {
	{ "prompt", 1, do_set_prompt, "switch dump prompt on/off" },
	{ "searchpath", 1, do_set_searchpath, "set searchpath for binaries and libraries" },
	{ },
};

static struct cmd_opt show_opts[] = {
	{ "info", 1, do_show_info, "show server settings" },
	{ "prompt", 1, do_show_prompt, "dump prompt" },
	{ "searchpath", 1, do_show_searchpath, "show searchpath for binaries and libraries" },
	{ },
};

static struct cmd_opt scan_opts[] = {
	{ "all", 1, (void *)SCAN_ALL, "scan all memory blocks" },
	{ "leak", 1, (void *)SCAN_LEAK, "scan only leaked allocations" },
	{ "new", 1, (void *)SCAN_NEW, "scan only allocations since last scan" },
	{ },
};

static struct cmd_opt cmds[] = {
	{
		dump_str,
		1,
		do_dump,
		"dump stack trees",
		"[sort-by] [<pid>] [>filename]",
		dump_opts
	},
	{
		help_str,
		1,
		do_help,
		"this help",
		"[<command>]",
		cmds
	},
	{
		proclist_str,
		1,
		do_proclist,
		"list processes",
		""
	},
	{
		quit_str,
		1,
		do_quit,
		"exit the program",
		""
	},
	{
		reset_str,
		1,
		do_reset,
		"reset all current memory allocation",
		"[<pid>]"
	},
	{
		scan_str,
		2,
		do_scan,
		"scan new memory leaks",
		"[<pid>]",
		scan_opts
	},
	{
		set_str,
		2,
		do_set,	
		"change settings",
		"<option> [arg]",
		set_opts
	},
	{
		show_str,
		2,
		do_show,	
		"show settings",
		"<option> [arg]",
		show_opts
	},
	{
		start_str,
		4,
		do_start,
		"start allocation tracing",
		""
	},
	{
		status_str,
		4,
		do_status,
		"show allocation status",
		"[<pid>]"
	},
	{
		stop_str,
		3,
		do_stop,
		"stop allocation tracing",
		""
	},
	{ },
};

void print_msg(const char *file, const char *func, int line, const char *info, const char *format, ...)
{
	va_list args;
	char *message = NULL;

	va_start(args, format);
	if (vasprintf(&message, format, args) == -1)
		abort();
	va_end(args);

	fprintf(stderr,"%s %s(%s:%d):\n %s\n", info, file, func, line, message);

	free(message);
}

static inline void io_watch_set(unsigned int idx, int fd, short events, int (*func)(void *, short revent), void *data)
{
	io_watch_event[idx].func = func;
	io_watch_event[idx].data = data;

	io_watch_poll[idx].fd = fd;
	io_watch_poll[idx].events = events;
}

short io_set_events(int fd, short events)
{
	unsigned int i;
	short old = 0;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].fd == fd) {
			old = io_watch_poll[i].events;
			io_watch_poll[i].events = events;
			break;
		}
	}
	return old;
}

int io_add_watch(int fd, short events, int (*func)(void *, short revent), void *data)
{
	unsigned int i;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].fd == fd) {
			io_watch_set(i, fd, events, func, data);
			return 1;
		}
	}

	if (io_watch_size == io_watch_elems) {
		io_watch_size += 16;

		io_watch_poll =	realloc(io_watch_poll, sizeof(struct pollfd) * io_watch_size);
		io_watch_event = realloc(io_watch_event, sizeof(struct io_watch_event) * io_watch_size);
	}

	io_watch_set(io_watch_elems, fd, events, func, data);

	++io_watch_elems;

	return 0;
}

int io_del_watch(int fd)
{
	unsigned int i;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].fd == fd) {
			--io_watch_elems;

			if (i != io_watch_elems) {
				io_watch_set(i,
					io_watch_poll[io_watch_elems].fd,
					io_watch_poll[io_watch_elems].events,
					io_watch_event[io_watch_elems].func,
					io_watch_event[io_watch_elems].data);
			}
			return 0;
		}
	}
	return -1;
}

int io_watch(int timeout)
{
	unsigned int i;
	int ret;

	ret = TEMP_FAILURE_RETRY(poll(io_watch_poll, io_watch_elems, timeout));
	if (ret < 0)
		return ret;

	ret = 0;

	for(i = 0; i < io_watch_elems; ++i) {
		if (io_watch_poll[i].revents) {
			if (io_watch_event[i].func)
				io_watch_event[i].func(io_watch_event[i].data, io_watch_poll[i].revents);
			if (io_watch_poll[i].fd == 0)
				ret = 1;
		}
	}
	return ret;
}

static void _quit(void)
{
	rl_callback_handler_remove();
	_exit(1);
}

static void sigchld_handler(int signum)
{
	for(;;) {
		int pid = waitpid(WAIT_ANY, NULL, WNOHANG);
		if (pid < 0 && errno != ECHILD)
			fatal("waitpid: %s", strerror(errno));
		else
		if (pid <= 0)
			break;
	}
}

static void usage(FILE *file)
{
	fprintf(file,
		"usage: " PROGNAME " <options>\n"
		"\n"
		" -h or --help             show this help message\n"
		" -s or --socket           server socket path or port (default :" STR(STREAM_PORT) ")\n"
		" -p or --searchpath       search pathes for binaries and libraries\n"
	);
	exit(1);
}

static inline char *skip_spaces(const char *s)
{
	while(isspace(*s))
		++s;
	return (char *)s;
}

static inline unsigned int match_chr(const char *s, char c)
{
	unsigned int i;

	for(i = 0; *s != c; ++i) {
		if (!*s++)
			break;
	}

	return i;
}

static inline unsigned int get_string(const char *s)
{
	char c = *s++;

	return match_chr(s, c) + 1;
}

static char *readline_cmd_generator(const char *text, int state)
{
	static int list_index, len;

	if (!state) {
		list_index = 0;
		len = strlen(text);
	}

	text = skip_spaces(text);

	while(list_index < ARRAY_SIZE(cmds) -1) {
		const char *name = cmds[list_index++].name;

		if (strncmp(name, text, len) == 0)
			return strdup(name);
	}
	return NULL;
}

static char **readline_option_complete(const char *text, struct cmd_opt *options)
{
	char **match_list;
	unsigned int len = strlen(text);
	unsigned int i = 1;
	unsigned int match_list_size = 8;

	if (!options)
		return NULL;

	match_list = malloc(match_list_size * sizeof(*match_list));
	if (!match_list)
		return match_list;

	while(options->name) {
		if (!strncmp(options->name, text, len)) {
			if (i + 2 > match_list_size) {
				char **new;

				match_list_size += 8;

				new = realloc(match_list, match_list_size * sizeof(*match_list));
				if (!new)
					break;

				match_list = new;
			}
			match_list[i++] = strdup(options->name);
		}
		++options;
	}

	if (i < 2) {
		free(match_list);

		return NULL;
	}

	if (i == 2) {
		match_list[0] = match_list[1];
		match_list[1] = NULL;
	}
	else {
		match_list[0] = strndup(match_list[1], len);
		match_list[i] = NULL;
	}

	return match_list;
}

static char **readline_completor(const char *text, int start, int end)
{
	char *p;
	unsigned int i, n;

	rl_attempted_completion_over = 1;

	if (start) {
		if (rl_line_buffer[start - 1] == '>')
			return rl_completion_matches(text, rl_filename_completion_function);
	}

	if (rl_line_buffer[end])
		return NULL;

	p = skip_spaces(rl_line_buffer);

	for(n = 0; p[n]; ++n) {
		if (isspace(p[n]))
			break;
	}

	if (isspace(p[n])) {
		for(i = 0; i < ARRAY_SIZE(cmds) - 1; ++i) {
			if (n >= cmds[i].match_len && !strncmp(cmds[i].name, p, n))
				return readline_option_complete(text, cmds[i].options);
		}
		return NULL;
	}

	return rl_completion_matches(text, readline_cmd_generator);
}

static void readline_handler(char *line)
{
	unsigned int i;
	unsigned int n;
	const char **argv = NULL;
	unsigned int argv_size = 8;
	int argc;
	char *linedup;
	char *s;

	linedup = strdup(line);
	if (!linedup)
		goto finish;

	argv = malloc(argv_size * sizeof(*argv));
	if (!argv)
		goto finish;

	s = linedup;
	i = 0;
	
	for(;;) {
		s = skip_spaces(s);
		if (!*s)
			break;

		if (i + 2 > argv_size) {
			const char **new;

			argv_size += 8;

			new = realloc(argv, argv_size * sizeof(*argv));
			if (!new)
				break;

			argv = new;
		}

		if (*s == '\"') {
			argv[i] = s + 1;
			n = get_string(s);
		}
		else
		if (*s == '\'') {
			argv[i] = s + 1;
			n = get_string(s);
		}
		else {
			argv[i] = s;
			for(n = 1; !isspace(s[n]); ++n) {
				if (!s[n])
					break;
			}
		}

		++i;

		if (!s[n])
			break;

		s[n] = 0;
		s += n + 1;
	}
	if (!i)
		return;

	argc = i;
	argv[i++] = NULL;

	outfile = NULL;

	for(i = 0; i < argc; ++i) {
		if (argv[i][0] == '>') {
			unsigned int j;

			outfile = argv[i] + 1;

			for(j = i; j < argc; ++j)
				argv[j] = argv[j + 1];

			--argc;
		}
	}

	if (argc) {
		n = strlen(argv[0]);

		for(i = 0; i != ARRAY_SIZE(cmds) - 1; ++i) {
			if (n >= cmds[i].match_len && !strncmp(argv[0], cmds[i].name, n)) {
				if (((cmd_call)cmds[i].data)(&cmds[i], argc, argv) >= 0)
					add_history(line);
				goto finish;
			}
		}
	}
	printf("unknown command '%s'\n", argv[0]);
finish:
	free(argv);
	free(linedup);

	return;
}


static int connected(void)
{
	if (server->fd != -1)
		return 1;

	printf("connection lost\n");

	return 0;
}

char **get_search_list(void)
{
	static char *def_list[] = { "/", ".", NULL };

	if (!search_list || !*search_list)
		return &def_list[0];

	return search_list;
}

static void split_search_patch(const char *p)
{
	unsigned int search_list_size = 8;
	unsigned int i = 0;

	if (search_list) {
		char **q = search_list;

		while(*q)
			free(*q++);

		free(search_list);
	}

	search_list = malloc(search_list_size * sizeof(*search_list));
	if (!search_list)
		return;

	while(*p) {
		unsigned int n = match_chr(p, ':');

		if (i + 2 > search_list_size) {
			char **new;

			search_list_size += 8;

			new = realloc(search_list, search_list_size * sizeof(*search_list));
			if (!new)
				break;

			search_list = new;
		}
		search_list[i++] = strndup(p, n);

		p += n;

		if (!*p++)
			break;
	}

	search_list[i] = NULL;
}

static int do_set_searchpath(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "%s: missing search path argument for '%s'\n", cmd->name, opt->name);
		return -1;
	}

	split_search_patch(argv[2]);

	return 0;
}

static int do_set_prompt(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "%s: missing option argument for '%s'\n", cmd->name, opt->name);
		return -1;
	}
	
	if (argc > 3) {
		fprintf(stderr, "%s: too many option argument for '%s'\n", cmd->name, opt->name);
		return -1;
	}

	if (!strcmp(argv[2], "on")) {
		dump_prompt(1);
		return 0;
	}

	if (!strcmp(argv[2], "off")) {
		dump_prompt(0);
		return 0;
	}

	fprintf(stderr, "%s: invalid option argument '%s' for '%s'\n", cmd->name, argv[2], opt->name);
	return -1;
}

static int do_show_info(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[])
{
	if (argc > 2) {
		fprintf(stderr, "%s: too many option argument for '%s'\n", cmd->name, opt->name);
		return -1;
	}

	get_info(server);
	return 0;
}

static int do_show_prompt(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[])
{
	if (argc > 2) {
		fprintf(stderr, "%s: too many option argument for '%s'\n", cmd->name, opt->name);
		return -1;
	}

	printf("%s=%s\n", opt->name, dump_prompt(-1) ? "on" : "off");
	return 0;
}

static int do_show_searchpath(struct cmd_opt *cmd, struct cmd_opt *opt, int argc, const char *argv[])
{
	char **p;

	if (argc > 3) {
		fprintf(stderr, "%s: too many option argument for '%s'\n", cmd->name, opt->name);
		return -1;
	}

	printf("%s=", opt->name);


	p = get_search_list();
	if (*p) {
		for(;;) {
			printf("%s", *p);

			if (!*++p)
				break;

			printf(":");
		}
	}

	printf("\n");
	return 0;
}

static int show_process_pid(mt_process *process)
{
	printf(" %d", process->pid);
	return 0;
}

static int do_dump(struct cmd_opt *cmd, int argc, const char *argv[])
{
	mt_process *process;
	size_t len;
	struct cmd_opt *options = cmd->options;;
	unsigned int i;
	void *data;

	process = server_first_process(server);
	if (!process) {
		fprintf(stderr, "no process available\n");
		return -1;
	}

	if (argc == 1)
		data = process_dump_sort_usage;
	else {
		data = NULL;
		len = strlen(argv[1]);

		for(i = 0; options[i].name; ++i) {
			if (options[i].match_len <= len && !strncmp(options[i].name, argv[1], len)) {
				data = options[i].data;
				break;
			}
		}

		if (!data) {
			fprintf(stderr, "%s: unknown sort criteria\n", cmd->name);
			return -1;
		}
	}

	dump_stacks(server, process, data, outfile);

	return 0;
}

static int do_help(struct cmd_opt *cmd, int argc, const char *argv[])
{
	int i;
	unsigned int len;
	
	if (argc <= 1) {
		for(i = 0; i != ARRAY_SIZE(cmds) - 1; ++i)
			printf(" %s - %s\n", cmds[i].name, cmds[i].info);
		return 0;
	}

	len = strlen(argv[1]);

	for(i = 0; i != ARRAY_SIZE(cmds) - 1; ++i) {
		if (cmds[i].match_len <= len && !strncmp(cmds[i].name, argv[1], len)) {
			struct cmd_opt *options = cmds[i].options;;

			printf("usage: %s %s\n", cmds[i].name, cmds[i].usage);

			if (options) {
				while(options->name) {
					printf(" %s - %s\n", options->name, options->info);

					++options;
				}
				if (options->info)
					printf(" %s\n", options->info);
			}
			return 0;
		}
	}

	printf("%s: no help for '%s'\n", cmd->name, argv[1]);

	return -1;
}

static int do_proclist(struct cmd_opt *cmd, int argc, const char *argv[])
{
	if (argc > 1) {
		fprintf(stderr, "%s: expect no arguments\n", proclist_str);
		return -1;
	}

	if (!server->first_pid) {
		fprintf(stderr, "%s: no process available\n", proclist_str);
		return -1;
	}

	printf("available processes:");
	server_iterate_processes(server, show_process_pid);
	printf("\n");

	return 0;
}

static int do_quit(struct cmd_opt *cmd, int argc, const char *argv[])
{
	_quit();

	return 0;
}

static int do_reset(struct cmd_opt *cmd, int argc, const char *argv[])
{
	mt_process *process;

	process = server_first_process(server);
	if (!process) {
		fprintf(stderr, "no process available\n");
		return 0;
	}

	process_reset(process);

	return 0;
}

static int do_scan(struct cmd_opt *cmd, int argc, const char *argv[])
{
	mt_process *process;
	struct cmd_opt *options = cmd->options;;
	size_t len;
	unsigned int i;
	int mode;

	if (!connected())
		return -1;

	process = server_first_process(server);
	if (!process) {
		fprintf(stderr, "no process available\n");
		return 0;
	}
	
	if (argc == 1)
		mode = SCAN_ALL;
	else {
		mode = -1;

		len = strlen(argv[1]);

		for(i = 0; options[i].name; ++i) {
			if (options[i].match_len <= len && !strncmp(options[i].name, argv[1], len)) {
				mode = (unsigned long)options[i].data;
				break;
			}
		}

		if (mode < 0) {
			fprintf(stderr, "%s: unknown scan mode\n", cmd->name);
			return -1;
		}
	}

	leaks_scan(server, process, mode);
	return 0;
}

static int do_set(struct cmd_opt *cmd, int argc, const char *argv[])
{
	struct cmd_opt *opt = cmd->options;
	unsigned int len;

	if (argc < 2) {
		fprintf(stderr, "%s: missing option argument\n", cmd->name);
		return -1;
	}

	len = strlen(argv[1]);

	while(opt->name) {
		if (opt->match_len <= len && !strncmp(opt->name, argv[1], len))
			return ((opt_call)opt->data)(cmd, opt, argc, argv);
		++opt;
	}

	fprintf(stderr, "%s: unknown option '%s'\n", cmd->name, argv[1]);
	return -1;
}

static int do_show(struct cmd_opt *cmd, int argc, const char *argv[])
{
	struct cmd_opt *opt = cmd->options;
	unsigned int len;

	if (argc < 2) {
		fprintf(stderr, "%s: missing option argument\n", cmd->name);
		return -1;
	}

	len = strlen(argv[1]);

	while(opt->name) {
		if (opt->match_len <= len && !strncmp(opt->name, argv[1], len))
			return ((opt_call)opt->data)(cmd, opt, argc, argv);
		++opt;
	}

	fprintf(stderr, "%s: unknown option '%s'\n", cmd->name, argv[1]);
	return -1;
}

static int do_start(struct cmd_opt *cmd, int argc, const char *argv[])
{
	mt_process *process;

	if (!connected())
		return -1;

	process = server_first_process(server);
	if (!process) {
		fprintf(stderr, "no process available\n");
		return 0;
	}

	process_reset(process);

	MT_SEND_MSG(server, process, MT_START, 0, 0, NULL);

	return 0;
}

static int do_status(struct cmd_opt *cmd, int argc, const char *argv[])
{
	mt_process *process;

	if (!connected())
		return -1;

	process = server_first_process(server);
	if (!process) {
		fprintf(stderr, "no process available\n");
		return 0;
	}

	process_status(process);

	return 0;
}

static int do_stop(struct cmd_opt *cmd, int argc, const char *argv[])
{
	mt_process *process;

	if (!connected())
		return -1;

	process = server_first_process(server);
	if (!process) {
		fprintf(stderr, "no process available\n");
		return 0;
	}

	MT_SEND_MSG(server, process, MT_STOP, 0, 0, NULL);

	return 0;
}

static void parse_options(int *argc, char ***argv)
{
	static const struct option longopts[]={
		{ "help", 0, 0, 'h' },
		{ "socket", 1, 0, 's' },
		{ "searchpath", 1, 0, 'p' },
		{ 0, 0, 0, 0 }
	};

	static const char *shortopts="-hs:p:";

	for(;;) {
		int	c;

		c = getopt_long(*argc, *argv, shortopts, longopts, NULL);

		if (c == -1)
			break;

		switch(c) {
		default:
			usage(stderr);
			break;
		case 'h':
			usage(stdout);
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'p':
			split_search_patch(optarg);

			break;
		}
	}
}

int main(int argc, char **argv)
{
	int ret;

	install_crash_handler();

	parse_options(&argc, &argv);

	signal(SIGCHLD, sigchld_handler);

	server = server_connect(sock_path);
	server_wait_op(server, MT_NEW);
	get_info(server);

	rl_terminal_name = getenv("TERM");
	rl_instream = stdin;
	rl_outstream = stderr;
	rl_readline_name = PROGNAME;
	rl_callback_handler_install(PROGNAME "> ", readline_handler);
	rl_attempted_completion_function = readline_completor;

	/* characters that need to be quoted when appearing in filenames. */
	rl_filename_quote_characters = " \t\n\\\"'@<>=;|&()#$`?*[!:{";	/*}*/
#if 0
	rl_filename_quoting_function = NULL;
	rl_filename_dequoting_function = NULL;
	rl_char_is_quoted_p = NULL;
#endif

	rl_completer_quote_characters = "'\"";

#if (RL_VERSION_MAJOR>=5) 
	rl_catch_signals = 1 ;
	rl_catch_sigwinch = 1 ;
	rl_set_signals () ;
#endif

	io_add_watch(0, POLL_IN, NULL, NULL);

	while((ret = io_watch(-1)) != -1) {
		if (ret == 1)
			rl_callback_read_char();
	}
	return 0;
}

