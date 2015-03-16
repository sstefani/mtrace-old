/*
 * server side process handling
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#include "common.h"
#include "memtrace.h"

#define	PROGNAME "memtrace"

#define	MT_SEND_MSG(op, pid, tid, payload_len, payload...) \
	mt_send_msg( \
		server_fd, \
		op | ((sizeof(void *) > 4) ? MT_64BIT : 0), \
		pid, \
		tid, \
		payload_len, \
		##payload)

#define	MIN_STACK	4

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

struct map {
	unsigned long long start;
	unsigned long long end;
};

static struct memtrace_shm *shm = MAP_FAILED;

static int follow_fork;
static int follow_exec;
static int verbose;
static int stack_depth = MIN_STACK;
static const char *lib_path = "/usr/lib";
static const char *sock_path = ":" STR(STREAM_PORT);
static int wait_client;
static int main_pid;

static int sock_fd = -1;
static int comm_fd = -1;
static int server_fd = -1;

static char *shmem_name;

static char *libmemtrace;

static pthread_attr_t	thread_attr;
static pthread_t	thread;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static volatile int wakeup_pid;

static int tgkill(int tgid, int tid, int sig)
{
        return (pid_t)syscall(SYS_tkill, tid, sig);
}

static void error(const char *format, ...)
{
	va_list args;
	char *message = NULL;

	if (!(shm->info.mode & MEMTRACE_SI_VERBOSE))
		return;

	va_start(args, format);
	if (vasprintf(&message, format, args) == -1)
		abort();
	va_end(args);

	fprintf(stderr, "%s", message);
	free(message);
}

static void usage(FILE *file)
{
	fprintf(file,
		"usage: " PROGNAME "-server <parameters> -- prog [args...]\n"
		"\n"
		" -h or --help             show this help message\n"
		" -s or --socket           server socket path or port (default :" STR(STREAM_PORT) ")\n"
		" -d or --depth            max. stack depth (default: " STR(MIN_STACK) ")\n"
		" -l or --libpath          path to libmemtrace.so (default: /usr/lib)\n"
		" -e or --follow-exec      follow exec system calls\n"
		" -f or --follow-fork      follow fork sytem calls\n"
		" -v or --verbose          verbose mode\n"
		" -w or --wait             wait for client connection\n"
	);
	exit(file == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void create_socket(void)
{
	struct sock_descr descr;

	if (sock_addr(sock_path, &descr) < 0)
		fatal("can't open socket path: %s\n", sock_path);

	sock_fd = socket(descr.domain, SOCK_STREAM, descr.proto);
	if (sock_fd < 0)
		fatal("socket (%s)", strerror(errno));

	if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &const_int_1, sizeof(const_int_1)))
		fatal("setsockopt (%s)", strerror(errno));

	if (bind(sock_fd, (struct sockaddr *)&descr.addr, descr.addrlen) < 0)
		fatal("bind (%s)", strerror(errno));

	if (listen(sock_fd, 1) < 0)
		fatal("listen (%s)", strerror(errno));
}

static void remove_shmem(void)
{
	if (shm != MAP_FAILED)
		shm_unlink(shmem_name);
}

static void create_shmem(void)
{
	int shm_fd;

	if (asprintf(&shmem_name, "/%s%d", PROGNAME, getpid()) == -1)
		fatal("asprintf (%s)", strerror(errno));

	shm_fd = shm_open(shmem_name, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR);
	if (shm_fd == -1)
		fatal("shm_open");

	if (ftruncate(shm_fd, sizeof(*shm)) == -1)
		fatal("ftruncate");

	shm = mmap(NULL, sizeof(*shm), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

	close(shm_fd);

	if (shm == MAP_FAILED)
		fatal("mmap");

	memset(shm, 0, sizeof(*shm));
}

static void create_comm(void)
{
	struct sock_descr descr;

	if (snprintf(shm->comm_path, sizeof(shm->comm_path), "/tmp/memtrace%d.sock", getpid()) >= sizeof(shm->comm_path))
		fatal("can't store comm path\n");

	if (sock_addr_unix(shm->comm_path, &descr) < 0)
		fatal("can't open socket path: %s\n", shm->comm_path);

	comm_fd = socket(descr.domain, SOCK_STREAM, descr.proto);
	if (comm_fd < 0)
		fatal("comm (%s)", strerror(errno));

	if (setsockopt(comm_fd, SOL_SOCKET, SO_REUSEADDR, &const_int_1, sizeof(const_int_1)))
		fatal("setsockopt (%s)", strerror(errno));

	if (bind(comm_fd, (struct sockaddr *)&descr.addr, descr.addrlen) < 0)
		fatal("bind (%s)", strerror(errno));

	if (listen(comm_fd, 1) < 0)
		fatal("listen (%s)", strerror(errno));
}

static int thread_signal(pid_t pid, pid_t tid, int sig)
{
	int status;
	int ret;
	
	ret = tgkill(pid, tid, sig);
	if (ret == -1)
		return -1;

	for(;;) {
		int stop_sig = 0;

		if (TEMP_FAILURE_RETRY(waitpid(tid, &status, __WALL)) == -1)
			return -1;

		if (WIFEXITED(status))
			return -1;

		if (WIFSTOPPED(status)) {
			stop_sig = WSTOPSIG(status);

			if (stop_sig == sig)
				break;

			if (stop_sig == SIGTRAP)
				stop_sig = 0;
			else
			if (stop_sig == SIGSTOP)
				stop_sig = 0;
		}

		if (ptrace(PTRACE_CONT, tid, 0, stop_sig) == -1) {
			fprintf(stderr, "%s:%d ptrace CONT (%s)\n", __FUNCTION__, __LINE__, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static void thread_stop(pid_t pid, pid_t tid)
{
	thread_signal(pid, tid, SIGSTOP);
}

static void thread_cont(pid_t pid, pid_t tid)
{
	if (ptrace(PTRACE_CONT, tid, 0, 0) == -1) {
		if (errno != ESRCH)
			fatal("%s:%d ptrace CONT (%s)\n", __FUNCTION__, __LINE__, strerror(errno));
	}
}

static void for_each_thread(pid_t pid, void (*func)(pid_t, pid_t))
{
	DIR *dir;
	struct dirent *dentry;
	pid_t task;
	char *dirname;

	if (asprintf(&dirname, "/proc/%d/task", pid) == -1)
		fatal("asprintf (%s)", strerror(errno));

	dir = opendir(dirname);
	if (!dir)
		fatal("opendir (%s)", strerror(errno));

	free(dirname);

	while((dentry = readdir(dir))) {
		if (dentry->d_name[0] == '.')
			continue;

		task = atoi(dentry->d_name);

		if (task == pid)
			continue;

		func(pid, task);
	}

	closedir(dir);
}

static void cleanup(void)
{
	remove_shmem();

	if (sock_fd >= 0) {
		if (*sock_path != ':')
			unlink(sock_path);
	}

	if (comm_fd >= 0)
		unlink(shm->comm_path);

	pthread_cancel(thread);
}

static void sigint_handler(int signum)
{
	cleanup();
	_exit(EXIT_SUCCESS);
}

static void sigchld_handler(int signum)
{
//fprintf(stderr, "%s:%d\n", __FUNCTION__, __LINE__);
}

static inline unsigned long find_block(unsigned long (*get_val)(void *data, unsigned long index), void *arr, unsigned long n, unsigned long addr)
{
	unsigned long first, middle, last, val;

	first = 0;
	last = n;

	if (addr < get_val(arr,first))
		return n;

	if (addr > get_val(arr, last - 1))
		return n;

	do {
		middle = (first + last) >> 1;
		val = get_val(arr, middle);

		if (addr < val)
			last = middle;
		else if (addr > val)
			first = middle + 1;
		else
			return middle;

	} while (first < last);

	return n;
}

static unsigned long get_val32(void *data, unsigned long index)
{
	return (unsigned long)*(uint32_t *)(data + index * sizeof(uint32_t));
}

static unsigned long get_val64(void *data, unsigned long index)
{
	return (unsigned long)*(uint64_t *)(data + index * sizeof(uint64_t));
}

static int open_mem(pid_t pid)
{
	int h;
	char *proc_name;

	if (asprintf(&proc_name, "/proc/%u/mem", pid) == -1)
		fatal("asprintf (%s)", strerror(errno));

	h = open(proc_name, O_RDONLY);
	if (h == -1)
		fatal("open: '%s'(%s)", proc_name, strerror(errno));

	free(proc_name);

	return h;
}

static struct map *get_writeable_mappings(pid_t pid)
{
	unsigned long long start;
	unsigned long long end;
	char permr;
	char permw;
	char filename[PATH_MAX + 2];
	char nl;
	FILE *in;
	unsigned int maps_size = 0;
	struct map *maps = NULL;
	unsigned int map = 0;

	maps_size = 16;
	maps = malloc(maps_size * sizeof(*maps));

	snprintf(filename, sizeof(filename)-1, "/proc/%d/maps", pid);

	in = fopen(filename, "r");
	if (!in)
		goto skip;

	while(fscanf(in, "%llx-%llx %c%c%*c%*c %*x %*x:%*x %*u%*64[ ]%c", &start, &end, &permr, &permw, filename) == 5) {
		if (*filename != '\n') {
			if (fscanf(in, "%" STR(PATH_MAX) "[^\n]%c", filename + 1, &nl) != 2)
				break;
			if (nl != '\n')
				break;
		}
		else
			*filename = 0;

		if (*filename != '[' && *filename != 0) {
			struct stat statbuf;

			if (stat(filename, &statbuf) < 0)
				continue;

			if (S_ISCHR(statbuf.st_mode)) {
				if (statbuf.st_rdev != makedev(1, 5))
					continue;
			}
		}

		if (permr != 'r' || permw != 'w')
			continue;

		if (map >= maps_size - 1) {
			maps_size += 16;
			maps = realloc(maps, maps_size * sizeof(*maps));
		}

		maps[map].start = start;
		maps[map].end = end;

		map++;
	}

	fclose(in);
skip:
	maps[map].start = 0;
	maps[map].end = 0;

	return maps;
}

static void *mem_scan(mt_msg *cmd, void *payload, unsigned long *data_len)
{
	mt_scan_payload *mt_scan = payload;
	unsigned long mask = (unsigned long)mt_scan->mask;
	uint32_t ptr_size = mt_scan->ptr_size;
	void *blocks = mt_scan->data;
	unsigned long n = (cmd->payload_len - (blocks - payload)) / ptr_size;
	unsigned long map;
	struct map *maps;
	int h;
	unsigned long (*get_val)(void *data, unsigned long index);
	unsigned long start;
	unsigned long end;

	if (!n)
		return NULL;

	if (ptr_size == sizeof(uint32_t))
		get_val = get_val32;
	else
		get_val = get_val64;

	h = open_mem(cmd->pid);
	if (h == -1)
		return NULL;

	maps = get_writeable_mappings(cmd->pid);

	for(map = 0; (start = maps[map].start) && (end = maps[map].end); ++map) {
		int do_peek = 0;

		while(start < end) {
			unsigned long i;
			char page_buf[PAGE_SIZE];

			if (!do_peek) {
				if (lseek(h, start, SEEK_SET) != (off_t)start || read(h, page_buf, sizeof(page_buf)) == -1)
					do_peek = 1;
			}

			if (do_peek) {
				errno = 0;

				for(i = 0; i < sizeof(page_buf); i += sizeof(long)) {
					long val;

					val = ptrace(PTRACE_PEEKDATA, cmd->pid, start + i, 0);
					if (val == -1 && errno) {
						fprintf(stderr, "%s:%d ptrace PEEKDATA (%s)\n", __FUNCTION__, __LINE__, strerror(errno));
						break;
					}

					*(long *)&page_buf[i] = val;
				}
				if (i < sizeof(page_buf))
					break;
			}

			for(i = 0; i < sizeof(page_buf) / ptr_size; ++i) {
				unsigned long found, addr;

				addr = get_val(page_buf, i);

				if (addr & mask)
					continue;

				found = find_block(get_val, blocks, n, addr);
				if (found != n) {
					if (!--n)
						goto finish;

					if (found != n)
						memmove(blocks + found * ptr_size, blocks + (found + 1) * ptr_size, (n - found) * ptr_size);
				}
			}

			start += sizeof(page_buf);
		}
	}

finish:
	close(h);

	*data_len = n * ptr_size;

	free(maps);

	return blocks;
}

static void proc_cont(uint32_t pid)
{
	if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
		fatal("%s:%d ptrace (%s)", __FUNCTION__, __LINE__, strerror(errno));

	for_each_thread(pid, thread_cont);
}

static void proc_stop(uint32_t pid)
{
	int ret;

	ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
	if (!ret) {
		if (thread_signal(pid, pid, SIGSTOP) != -1)
			for_each_thread(pid, thread_stop);

		sem_post(&shm->sem);
	}
}

static void *get_executable_mappings(pid_t pid, unsigned int *size)
{
	unsigned long long start;
	unsigned long long end;
	unsigned long long offset;
	char permr;
	char permw;
	char permx;
	char filename[PATH_MAX + 2];
	char nl;
	FILE *in;
	struct xmap *xmap = NULL;
	void *xmap_base = NULL;
	unsigned int xmap_size = 0;

	proc_stop(pid);

	*size = 0;

	snprintf(filename, sizeof(filename)-1, "/proc/%d/maps", pid);

	in = fopen(filename, "r");
	if (!in)
		return NULL;

	while(fscanf(in, "%llx-%llx %c%c%c%*c %llx %*x:%*x %*u%*64[ ]%c", &start, &end, &permr, &permw, &permx, &offset, filename) == 7) {
		size_t flen;
		size_t xmap_off;

		if (*filename != '\n') {
			if (fscanf(in, "%" STR(PATH_MAX) "[^\n]%c", filename + 1, &nl) != 2)
				break;
			if (nl != '\n')
				break;
		}
		else
			*filename = 0;

		if (*filename != '[' && *filename != 0) {
			struct stat statbuf;

			if (stat(filename, &statbuf) < 0)
				continue;

			if (S_ISCHR(statbuf.st_mode))
				continue;
		
			flen = strlen(filename);
		}
		else
			flen = 0;

		if (permx != 'x' || permr != 'r' || permw == 'w')
			continue;

		xmap_off = (void *)xmap - xmap_base;

		if (xmap_off + XMAP_ALIGN(flen + 1) > xmap_size) {
			xmap_size += 4096 + XMAP_ALIGN(flen + 1);
			xmap_base = realloc(xmap_base, xmap_size);
			xmap = (struct xmap *)(xmap_base + xmap_off);
		}

		xmap->start = start;
		xmap->end = end;
		xmap->offset = offset;

		xmap->flen = flen;
		strncpy(xmap->fname, filename, flen);
		xmap->fname[flen] = 0;

#if 0
fprintf(stderr, "start: %llx end: %llx offset: %llx flen: %u fname: %s\n",
		xmap->start,
		xmap->end,
		xmap->offset,
		xmap->flen,
		xmap->fname);
#endif

		xmap = XMAP_NEXT(xmap, flen + 1);
	}
	fclose(in);

	*size = (void *)xmap - xmap_base;

	return xmap_base;
}

ssize_t sock_fd_write(int sock, void *buf, ssize_t buflen, int fd)
{
	ssize_t		size;
	struct msghdr	msg;
	struct iovec	iov;
	union {
		struct cmsghdr	cmsghdr;
		char		control[CMSG_SPACE(sizeof (int))];
	} cmsgu;
	struct cmsghdr	*cmsg;

	iov.iov_base = buf;
	iov.iov_len = buflen;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (fd != -1) {
		msg.msg_control = cmsgu.control;
		msg.msg_controllen = sizeof(cmsgu.control);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof (int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;

		*((int *) CMSG_DATA(cmsg)) = fd;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	size = sendmsg(sock, &msg, MSG_DONTWAIT);

	return size;
}

static void handle_comm(void)
{
	char c = 0;
	int tmp_fd = TEMP_FAILURE_RETRY(accept(comm_fd, NULL, 0));

	if (tmp_fd < 0)
		fatal("accept (%s)", strerror(errno));

	sock_fd_write(tmp_fd, &c, 1, server_fd);
	close(tmp_fd);
}

static void handle_requests(void)
{
	int			ret;
	struct pollfd		pfd[2];

	pfd[0].fd = server_fd;
	pfd[0].events = POLLIN|POLLPRI;

	pfd[1].fd = comm_fd;
	pfd[1].events = POLLIN|POLLPRI;

	for(;;) {
		ret = TEMP_FAILURE_RETRY(poll(pfd, 2, -1));

		if (ret == -1)
			break;

		if (pfd[0].revents & (POLLIN|POLLPRI)) {
			int pid;

			pthread_mutex_lock(&mutex);

			pid = vfork();
			if (pid == 0)
				_exit(0);
			wakeup_pid = pid;

			while(wakeup_pid != -1)
				pthread_cond_wait(&cond, &mutex);

			pthread_mutex_unlock(&mutex);

			if (server_fd == -1)
				break;
		}

		if (pfd[1].revents & (POLLIN|POLLPRI))
			handle_comm();
	}
}

static void handle_command(void)
{
	int ret;
	mt_msg cmd;
	void *payload = NULL;

	ret = safe_read(server_fd, &cmd, sizeof(cmd));

	if (ret != sizeof(cmd)) {
		if (ret > 0)
			error("cmd read wrong size %d\n", ret);
		close(server_fd);
		server_fd = -1;
		return;
	}

	if (cmd.payload_len) {
		payload = malloc(cmd.payload_len);

		if (safe_read(server_fd, payload, cmd.payload_len) != cmd.payload_len) {
			fprintf(stderr, "can't read payload_len (%u)\n", cmd.payload_len);
			goto finish;
		}
	}

	switch(cmd.operation) {
	case MT_SCAN:
	 {
		unsigned long data_len;
		void * data = mem_scan(&cmd, payload, &data_len);

		ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
		if (!ret) {
			MT_SEND_MSG(MT_SCAN, cmd.pid, 0, data_len, data, 0, NULL);
			sem_post(&shm->sem);
		}
		break;
	 }
	case MT_XMAP:
	 {
		void *xmap_base = NULL;
		unsigned int xmap_size = 0;

		xmap_base = get_executable_mappings(cmd.pid, &xmap_size);

		ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
		if (!ret) {
			MT_SEND_MSG(MT_XMAP, cmd.pid, cmd.tid, xmap_size, xmap_base, 0, NULL);
			sem_post(&shm->sem);
		}
		free(xmap_base);
		break;
	 }
	case MT_START:
		shm->info.do_trace = 1;
		break;
	case MT_STOP:
		shm->info.do_trace = 0;
		break;
	case MT_CONT:
		proc_cont(cmd.pid);
		break;
	case MT_INFO:
		ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
		if (!ret) {
			MT_SEND_MSG(MT_INFO, cmd.pid, cmd.tid, sizeof(shm->info), &shm->info, 0, NULL);
			sem_post(&shm->sem);
		}
		break;
	default:
		break;
	}
finish:
	if (payload)
		free(payload);
}

static int app_start(char **argv)
{
	int pid;

	pid = fork();
	if (pid < 0)
		fatal("Cannot fork (%s)", strerror(errno));

	if (!pid) {
		if (setenv("LD_PRELOAD", libmemtrace, 1) == -1)
			fatal("setenv LD_PRELOAD (%s)", strerror(errno));

		if (setenv("_MEMTRACE_SHM", shmem_name, 1) == -1)
			fatal("setenv _MEMTRACE_SHM (%s)", strerror(errno));

		close(sock_fd);
		close(comm_fd);
		close(server_fd);

		prctl(PR_SET_PDEATHSIG, SIGKILL);

		if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
			fatal("%s:%d ptrace TRACEME (%s)", __FUNCTION__, __LINE__, strerror(errno));
		raise(SIGSTOP);

		execvp(*argv, argv);

		fprintf(stderr, "Cannot execute program: %s (%s)", *argv, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	return pid;
}

static void server_run(void)
{
	int pid = main_pid;
	int status;

	if (TEMP_FAILURE_RETRY(waitpid(pid, &status, 0)) == -1)
		fatal("waitpid");

	if (WIFEXITED(status))
		fatal("WIFEXITED");

	if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE) == -1)
		fatal("%s:%d ptrace SETOPTIONS (%s)", __FUNCTION__, __LINE__, strerror(errno));

	if (ptrace(PTRACE_CONT, pid, 0, 0) == -1)
		fatal("%s:%d ptrace CONT (%s)", __FUNCTION__, __LINE__, strerror(errno));

	for (;;) {
		int stop_sig = 0;

		pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, __WALL));
		if (!pid)
			continue;

		if (pid == -1) {
			if (errno == ECHILD)
				break;
			fatal("waitpid (%s)", strerror(errno));
		}

		pthread_mutex_lock(&mutex);
		if (pid == wakeup_pid) {
			handle_command();
			wakeup_pid = -1;
			pthread_cond_broadcast(&cond);
		}
		pthread_mutex_unlock(&mutex);

		if (WIFEXITED(status))
			continue;

		if (WIFSTOPPED(status)) {
			stop_sig = WSTOPSIG(status);

			if (stop_sig == SIGTRAP)
				stop_sig = 0;
			else
			if (stop_sig == SIGSTOP)
				stop_sig = 0;
		}

		if (ptrace(PTRACE_CONT, pid, 0, stop_sig) == -1) {
			if (errno != ESRCH)
				fatal("%s:%d ptrace CONT (%s)", __FUNCTION__, __LINE__, strerror(errno));
		}
	}

	printf("No more childs.\n");
}

static void *server(void *ptr)
{
	int ret;
	struct pollfd	pfd[2];

	pfd[0].fd = sock_fd;
	pfd[0].events = POLLIN|POLLPRI;

	pfd[1].fd = comm_fd;
	pfd[1].events = POLLIN|POLLPRI;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	for(;;) {
		ret = TEMP_FAILURE_RETRY(poll(pfd, 2, -1));

		if (ret == -1)
			break;

		if (pfd[0].revents & (POLLIN|POLLPRI)) {
			server_fd = TEMP_FAILURE_RETRY(accept(sock_fd, NULL, 0));
			if (server_fd < 0)
				fatal("accept (%s)", strerror(errno));

			MT_SEND_MSG(MT_NEW, main_pid, 0, 0, NULL);

			pthread_mutex_lock(&mutex);
			wait_client = 0;
			pthread_cond_signal(&cond);
			pthread_mutex_unlock(&mutex);

			handle_requests();
			close(server_fd);

			shm->connection_count++;
			shm->info.do_trace = 0;
			server_fd = -1;
		}

		if (pfd[1].revents & (POLLIN|POLLPRI))
			handle_comm();
	}
	return NULL;
}

static void init_server(void)
{
	int ret;

	if (stack_depth < MIN_STACK)
		stack_depth = MIN_STACK;
	if (stack_depth > 64)
		stack_depth = 64;

	shm->info.version = MEMTRACE_SI_VERSION;
	shm->info.stack_depth = stack_depth;

	if (follow_fork)
		shm->info.mode |= MEMTRACE_SI_FORK;

	if (follow_exec)
		shm->info.mode |= MEMTRACE_SI_EXEC;

	if (verbose)
		shm->info.mode |= MEMTRACE_SI_VERBOSE;

	shm->info.do_trace = (wait_client) ? 1 : 0;
	shm->info.page_size = getpagesize();
	shm->connection_count = 0;
	sem_init(&shm->sem, 1, 1);

	ret = pthread_attr_init(&thread_attr);
	if (ret)
		fatal("pthread_attr_init failed: %d (%s)", ret, strerror(ret));

	ret = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_JOINABLE);
	if (ret)
		fatal("pthread_attr_setdetachstate failed: %d (%s)\n", strerror(ret));

	ret = pthread_create(&thread, &thread_attr, server, NULL);
	if (ret)
		fatal("pthread_create failed: %d (%s)\npossible reason: insufficient resources or maybe missing root privileges", ret, strerror(ret));

	pthread_mutex_lock(&mutex);
	if (wait_client)
		pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);
}

static void parse_options(int *argc, char ***argv)
{
	static const struct option longopts[]={
		{ "help", 0, 0, 'h' },
		{ "follow-fork", 0, 0, 'f' },
		{ "follow-exec", 0, 0, 'e' },
		{ "socket", 1, 0, 's' },
		{ "libpath", 1, 0, 'l' },
		{ "depth", 1, 0, 'd' },
		{ "verbose", 0, 0, 'v' },
		{ "wait", 0, 0, 'w' },
		{ 0, 0, 0, 0 }
	};

	static const char *shortopts="-hefs:l:d:vw";

	for(;;) {
		int	c;

		c=getopt_long(*argc, *argv, shortopts, longopts, NULL);

		if (c==-1)
			break;

		switch(c) {
		default:
			usage(stderr);
			break;
		case 'h':
			usage(stdout);
			break;
		case 'f':
			follow_fork = 1;
			break;
		case 'e':
			follow_exec = 1;
			break;
		case 'd':
			stack_depth = atoi(optarg);
			if (stack_depth <= 0) {
				fprintf(stderr,"invalid stack depth parameter: %s\n", optarg);
				exit(1);
			}
			break;
		case 'l':
			lib_path = optarg;
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		case 'w':
			wait_client = 1;
			break;
		}
	}

	(*argv)[optind - 1] = (*argv)[0];
	*argc -= optind - 1;
	*argv += optind - 1;

	if (*argc < 2)
		usage(stderr);
}

int main(int argc, char **argv)
{
	struct sigaction actions;

	parse_options(&argc, &argv);

	if (asprintf(&libmemtrace, "%s/libmemtrace.so", lib_path) == -1)
		fatal("asprintf (%s)", strerror(errno));

	create_shmem();

	main_pid = app_start((char **)(argv + 1));

	atexit(cleanup);

	signal(SIGINT, sigint_handler);

	sigemptyset(&actions.sa_mask);
	actions.sa_flags = SA_RESTART;
	actions.sa_handler = sigchld_handler;

	if (sigaction(SIGCHLD, &actions, NULL)) {
		perror("sigaction(SIGCHLD)");
		return 1;
	}

	create_socket();
	create_comm();
	init_server();

	server_run();

	return EXIT_SUCCESS;
}

