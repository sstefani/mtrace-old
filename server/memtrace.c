/*
 * library for intercepting some libc functions
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

#include <alloca.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <link.h>
#include <sys/mman.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "common.h"
#include "memtrace.h"

#define MEM_TRACE_HANDLE 1000

#define	mt_printf(fmt, arg...) _mt_printf("memintercept: " fmt, ##arg)

#define	MT_SEND_MSG(op, payload_len, payload...) \
	if (mt_send_msg( \
		info_ptr->out_fd, \
		op | ((sizeof(void *) > 4) ? MT_64BIT : 0), \
		info_ptr->pid, \
		tid, \
		payload_len, \
		##payload) < 0) \
			mt_send_msg_err(); 

struct mt_info {
	int out_fd;
	int connection_count;
	int connection_done;
	pid_t pid;
};

static __thread pid_t tid;
static __thread struct mt_info info = { .out_fd = -1 };
static __thread struct mt_info *info_ptr;
static __thread int in_report;
static __thread int in_trace;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static int no_trace;
static struct memtrace_shm *shm;

static int (*old_execve)(const char *filename, char *const argv[], char *const envp[]);
static int (*old_fork)(void);
static int (*old_clone)(int (*fn) (void *arg), void *child_stack, int flags, void *arg, void *xarg1, void *xarg2, void *xarg3, void *xarg4);
static void (*old_exit)(int status);
static void *(*old_malloc)(size_t size);
static void *(*old_memalign)(size_t alignment, size_t size);
static void *(*old_realloc)(void *ptr, size_t size);
static void (*old_free)(void *ptr);
static int (*old_posix_memalign)(void **memptr, size_t alignment, size_t size);
static void *(*old_aligned_alloc)(size_t alignment, size_t size);
static void *(*old_valloc)(size_t size);
static void *(*old_pvalloc)(size_t size);
static void *(*old_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
static void *(*old_mmap64)(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset);
static int (*old_munmap)(void *addr, size_t length);

static void _mt_printf(const char *format, ...);
static void mt_check_init(void);

static int initialized;

static pid_t gettid(void)
{
	return (pid_t)syscall(SYS_gettid);
}

static void reset_info(void)
{
	info_ptr = &info;
	info_ptr->connection_count = 0;
	info_ptr->connection_done = 0;
	info_ptr->out_fd = -1;
	info_ptr->pid = 0;
}

static ssize_t sock_fd_read(int sock, void *buf, ssize_t bufsize, int *fd)
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
	iov.iov_len = bufsize;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgu.control;
	msg.msg_controllen = sizeof(cmsgu.control);

	size = TEMP_FAILURE_RETRY(recvmsg(sock, &msg, 0));
	if (size < 0)
		return -1;

	if ((msg.msg_flags & MSG_TRUNC) ||
	    (msg.msg_flags & MSG_CTRUNC))
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg && cmsg->cmsg_len == CMSG_LEN(sizeof(int))) {
		if (cmsg->cmsg_level != SOL_SOCKET)
			return -1;

		if (cmsg->cmsg_type != SCM_RIGHTS)
			return -1;

		*fd = *((int *) CMSG_DATA(cmsg));
	} else
		*fd = -1;

	return size;
}

static int write_all(int fd, const void *buf, int total)
{
	int ret;
	int written = 0;

	while (written < total) {
		ret = TEMP_FAILURE_RETRY(write(fd, buf + written, total - written));
		if (ret < 0)
			return ret;
		written += ret;
	}

	return total;
}

static void _mt_printf(const char *format, ...)
{
	static int init = 0;
	static sem_t sema;
	int sem_ret;
	int n;
	char buf[256];
	va_list va;
	int old_errno = errno;

	if (!(shm->info.mode & MEMTRACE_SI_VERBOSE))
		return;

	if (init == 0) {
		init = 1;
		sem_init(&sema, 0, 1);
	}

	sem_ret = TEMP_FAILURE_RETRY(sem_wait(&sema));

	va_start(va, format);
	n = vsnprintf(buf, sizeof(buf), format, va);
	va_end(va);

	if (n > sizeof(buf))
		n = sizeof(buf);

	write_all(2, buf, n);

	if (!sem_ret)
		sem_post(&sema);

	errno = old_errno;
}

void mt_send_msg_err(void)
{
	mt_printf("sendmsg: %s\n", strerror(errno));
	info_ptr->out_fd = -1;
}

static int mt_connect(void)
{
	int fd;
	struct sock_descr descr;
	char c;

	if (info_ptr->out_fd == -1) {
		if (info_ptr->connection_done)
			goto fail1;

		info_ptr->connection_done = 1;

		if (sock_addr(shm->comm_path, &descr) < 0) {
			mt_printf("can't open socket path: %s\n", shm->comm_path);

			goto fail1;
		}

		fd = socket(descr.domain, SOCK_STREAM|SOCK_CLOEXEC, descr.proto);
		if (fd < 0) {
			mt_printf("socket: %s\n", strerror(errno));

			goto fail1;
		}

		if (TEMP_FAILURE_RETRY(connect(fd, &descr.addr.u_addr, descr.addrlen)) == -1) {
			mt_printf("connect: %s\n", strerror(errno));

			goto fail2;
		}

		if (sock_fd_read(fd, &c, 1, &info_ptr->out_fd) == -1) {
			mt_printf("sock_fd_read: %s\n", strerror(errno));

			goto fail2;
		}

		close(fd);

		if (info_ptr->out_fd != -1) {
			if (fcntl(MEM_TRACE_HANDLE, F_GETFD) == -1) {
				dup2(info_ptr->out_fd, MEM_TRACE_HANDLE);
				close(info_ptr->out_fd);
				info_ptr->out_fd = MEM_TRACE_HANDLE;
			}
			fcntl(info_ptr->out_fd, F_SETFD, FD_CLOEXEC);
		}
	}
	return 1;
fail2:
	close(fd);
fail1:
	return 0;
}

static int mt_check(void)
{
	int old_errno = errno;
	int ret;

	if (initialized < 1)
		return 0;

	if (no_trace)
		return 0;

	if (in_report)
		return 0;

	if (!shm->info.do_trace)
		return 0;

	if (info_ptr->out_fd != -1)
		return 1;

	pthread_mutex_lock(&mutex);

	if (info_ptr->connection_count != shm->connection_count) {
		if (info_ptr->out_fd != -1) {
			int fd = info_ptr->out_fd;

			info_ptr->out_fd = -1;

			close(fd);
		}

		info_ptr->connection_done = 0;
		info_ptr->connection_count = shm->connection_count;
	}

	ret = mt_connect();

	pthread_mutex_unlock(&mutex);
	
	errno = old_errno;

	return ret;
}

static inline int do_backtrace(void **buffer, int size)
{
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip;
	int n = 0;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);

	while(size > n) {
		if (unw_step(&cursor) <= 0)
			break;

		if (unw_get_reg(&cursor, UNW_REG_IP, &ip) < 0)
			break;

		buffer[n++] = (void *)ip;
	}
	return n;
}

static void mt_call_with_backtrace(int to_skip, uint16_t operation, void *ptr, unsigned long size)
{
	int old_errno = errno;
	int ret;
	int n_frames;
	void **frames;
	mt_alloc_payload mt_alloc;
	int n = shm->info.stack_depth + to_skip;

	if (!ptr)
		return;

	in_report = 1;

	frames = alloca(sizeof(void *) * n);

	n_frames = do_backtrace(frames, n) - to_skip;

	if (n_frames <= 0)
		n_frames = 0;

	mt_alloc.ptr = (typeof(mt_alloc.ptr))ptr;
	mt_alloc.size = (typeof(mt_alloc.size))size;

	ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
	if (!ret) {
		MT_SEND_MSG(operation, sizeof(mt_alloc), &mt_alloc, n_frames * sizeof(void *), frames + to_skip);

		sem_post(&shm->sem);
	}

	in_report = 0;

	errno = old_errno;

	return;
}

static void mt_call(uint16_t operation, void *ptr, unsigned long size)
{
	int old_errno = errno;
	int ret;
	mt_alloc_payload mt_alloc;

	if (!ptr)
		return;

	in_report = 1;

	mt_alloc.ptr = (typeof(mt_alloc.ptr))ptr;
	mt_alloc.size = (typeof(mt_alloc.size))size;

	ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
	if (!ret) {
		MT_SEND_MSG(operation, sizeof(mt_alloc), &mt_alloc, 0, NULL);

		sem_post(&shm->sem);
	}

	in_report = 0;

	errno = old_errno;

	return;
}

static void new_process(pid_t old_pid, pid_t curr_pid, mt_operation operation)
{
	int old_errno = errno;
	mt_pid_payload mt_pid;
	int ret = 0;

	if (no_trace)
		return;

	info_ptr->pid = curr_pid;
	tid = gettid();

	if (!mt_check())
		return;

	mt_pid.pid = old_pid;

	ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
	if (!ret) {
		MT_SEND_MSG(operation, sizeof(mt_pid), &mt_pid, 0, NULL);

		sem_post(&shm->sem);
	}

	errno = old_errno;
}

static void mt_init(pid_t ppid)
{
	char *env;
	int old_errno = errno;
	int shm_fd = -1;

	shm = NULL;

	reset_info();

	env = getenv("_MEMTRACE_SHM");
	if (!env)
		goto fail;

	shm_fd = shm_open(env, O_RDWR|O_CLOEXEC, 0);
	if (shm_fd == -1)
		goto fail;

	shm = old_mmap(NULL, sizeof(*shm), PROT_READ|PROT_WRITE, MAP_SHARED, shm_fd, 0);

	close(shm_fd);

	if (shm == MAP_FAILED)
		goto fail;

	if (shm->info.version != MEMTRACE_SI_VERSION)
		goto fail;

	new_process(ppid, getpid(), MT_NEW);

	errno = old_errno;

	return;
fail:
	if (shm_fd != -1) {
		if (shm != MAP_FAILED)
			old_munmap(shm, sizeof(*shm));

		shm = MAP_FAILED;
	}

	no_trace = 1;

	errno = old_errno;
}

static void mt_exit(void)
{
	int ret;
	int fd;
	int old_errno = errno;

	if (no_trace)
		return;

	ret = TEMP_FAILURE_RETRY(sem_wait(&shm->sem));
	if (!ret) {
		MT_SEND_MSG(MT_EXIT, 0, NULL);

		sem_post(&shm->sem);
	}

	fd = info_ptr->out_fd;

	info_ptr->out_fd = -1;
	info_ptr->pid = 0;
	tid = 0;
	no_trace = 1;

	close(fd);

	errno = old_errno;
}

static void mt_check_init(void)
{
	if (initialized)
		return;

	initialized = -1;

	old_execve = dlsym(RTLD_NEXT, "execve");
	old_fork = dlsym(RTLD_NEXT, "fork");
	old_clone = dlsym(RTLD_NEXT, "__clone");
	old_exit = dlsym(RTLD_NEXT, "_exit");
	old_malloc = dlsym(RTLD_NEXT, "malloc");
	old_realloc = dlsym(RTLD_NEXT, "realloc");
	old_free = dlsym(RTLD_NEXT, "free");
	old_memalign = dlsym(RTLD_NEXT, "memalign");
	old_posix_memalign = dlsym(RTLD_NEXT, "posix_memalign");
	old_aligned_alloc = dlsym(RTLD_NEXT, "aligned_alloc");
	old_valloc = dlsym(RTLD_NEXT, "valloc");
	old_pvalloc = dlsym(RTLD_NEXT, "pvalloc");
#if 1
	old_mmap = dlsym(RTLD_NEXT, "mmap");
	old_mmap64 = dlsym(RTLD_NEXT, "mmap64");
	old_munmap = dlsym(RTLD_NEXT, "munmap");
#endif

	mt_init(0);

	if (!no_trace)
		atexit(mt_exit);

	initialized = 1;
}

static void *do_malloc(size_t size, int to_skip)
{
	void *result;

	if (!old_malloc) {
		mt_check_init();

		if (!old_malloc)
			return NULL;
	}

	++in_trace;

	result = old_malloc(size);
	if (result) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(to_skip + 2, MT_MALLOC, result, size);
	}

	--in_trace;

	return result;
}

void *memalign(size_t alignment, size_t size)
{
	void *result;

	if (!old_memalign) {
		mt_check_init();

		if (!old_memalign)
			return NULL;
	}

	++in_trace;

	result = old_memalign(alignment, size);
	if (result) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_MEMALIGN, result, size);
	}

	--in_trace;

	return result;
}


int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	int ret;

	if (!old_posix_memalign) {
		mt_check_init();

		if (!old_posix_memalign)
			return ENOMEM;
	}

	++in_trace;

	ret = old_posix_memalign(memptr, alignment, size);
	if (!ret) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_POSIX_MEMALIGN, *memptr, size);
	}

	--in_trace;

	return ret;
}

void *aligned_alloc(size_t alignment, size_t size)
{
	void *result;

	if (!old_aligned_alloc) {
		mt_check_init();

		if (!old_aligned_alloc)
			return NULL;
	}

	++in_trace;

	result = old_aligned_alloc(alignment, size);
	if (result) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_ALIGNED_ALLOC, result, size);
	}

	--in_trace;

	return result;
}

void *valloc(size_t size)
{
	void *result;

	if (!old_valloc) {
		mt_check_init();

		if (!old_valloc)
			return NULL;
	}

	++in_trace;

	result = old_valloc(size);
	if (result) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_VALLOC, result, size);
	}

	--in_trace;

	return result;
}

void *pvalloc(size_t size)
{
	void *result;

	if (!old_pvalloc) {
		mt_check_init();

		if (!old_pvalloc)
			return NULL;
	}

	++in_trace;

	result = old_pvalloc(size);
	if (result) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_PVALLOC, result, size);
	}

	--in_trace;

	return result;
}

void *realloc(void *ptr, size_t size)
{
	void *result;

	if (!old_realloc) {
		mt_check_init();

		if (!old_realloc)
			return NULL;
	}

	++in_trace;

	if (in_trace == 1 && mt_check())
		mt_call(MT_FREE, ptr, 0);

	result = old_realloc(ptr, size);
	if (result) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_REALLOC, result, size);
	}

	--in_trace;

	return result;
}

void free(void *ptr)
{
	if (!old_free) {
		mt_check_init();

		if (!old_free)
			return;
	}

	++in_trace;

	if (in_trace == 1 && mt_check())
		mt_call(MT_FREE, ptr, 0);

	old_free(ptr);

	--in_trace;
}

void *malloc(size_t size)
{
	return do_malloc(size, 0);
}

void *calloc(size_t nmemb, size_t size)
{
	int total = nmemb * size;
	void *result = do_malloc(total, 1);

	if (result)
		memset(result, 0, total);

	return result;
}

#if 1
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	void *result;

	if (!old_mmap) {
		mt_check_init();

		if (!old_mmap)
			return NULL;
	}

	++in_trace;

	result = old_mmap(addr, length, prot, flags, fd, offset);
	if (result != MAP_FAILED) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_MMAP, result, length);
	}

	--in_trace;

	return result;
}

void *mmap64(void *addr, size_t length, int prot, int flags, int fd, __off64_t offset)
{
	void *result;

	if (!old_mmap) {
		mt_check_init();

		if (!old_mmap64)
			return NULL;
	}

	++in_trace;

	result = old_mmap64(addr, length, prot, flags, fd, offset);
	if (result != MAP_FAILED) {
		if (in_trace == 1 && mt_check())
			mt_call_with_backtrace(2, MT_MMAP64, result, length);
	}

	--in_trace;

	return result;
}

int munmap(void *addr, size_t length)
{
	int ret;

	if (!old_munmap) {
		mt_check_init();

		if (!old_munmap) {
			errno = EINVAL;
			return -1;
		}
	}

	++in_trace;

	if (in_trace == 1 && mt_check())
		mt_call(MT_MUNMAP, addr, length);

	ret = old_munmap(addr, length);

	--in_trace;

	return ret;
}
#endif

static void unset_memtrace(char *const envp[])
{
	const char ld_preload_env[] = "LD_PRELOAD=";
	const char libname[] = "libmemtrace.so";
	char *const *p = envp;

	no_trace = 1;

	while(*p) {
		if (strncmp(*p, ld_preload_env, sizeof(ld_preload_env)-1) == 0)
			break;
		p++;
	}

	if (*p) {
		char *s = *p + sizeof(ld_preload_env)-1;
		char *r = strstr(s, libname);

		if (r) {
			if (r[sizeof(libname)-1] != ':' && r[sizeof(libname)-1] != '\0')
				return;

			memset(r, ':', sizeof(libname)-1);

			while(s != r--) {
				if (*r == ':')
					break;
				*r = ':';
			}
		}
	}
}

int fork(void)
{
	int pid;
	int old_pid;

	if (!info_ptr)
		return old_fork();

	old_pid = info_ptr->pid;

	pid = old_fork();

	if (!pid) {	/* New child process */
		if (shm->info.mode & MEMTRACE_SI_FORK)
			new_process(old_pid, getpid(), MT_FORK);
		else
			unset_memtrace(__environ);
	}

	return pid;
}

int execve(const char *filename, char *const argv[], char *const envp[])
{
	if (!(shm->info.mode & MEMTRACE_SI_EXEC))
		unset_memtrace(envp);

	return old_execve(filename, argv, envp);
}

typedef struct {
	int (*fn) (void *);
	void *arg;
	int flags;
	struct mt_info *info_ptr;
} CloneData;

static int clone_helper(void *arg)
{
	CloneData data;

	memcpy(&data, arg, sizeof(data));

	old_free(arg);

	if (data.flags & CLONE_FILES)
		info_ptr = data.info_ptr;
	else
		reset_info();

	if (data.flags & CLONE_VM)
		new_process(data.info_ptr->pid, (data.flags & CLONE_THREAD) ? data.info_ptr->pid : getpid(), MT_CLONE);
	else {
		if (shm->info.mode & MEMTRACE_SI_FORK)
			mt_init(data.info_ptr->pid);
		else
			no_trace = 1;
	}

	return (*data.fn) (data.arg);
}

static int do_clone(int (*fn) (void *arg), void *child_stack, int flags, void *arg, void *xarg1, void *xarg2, void *xarg3, void *xarg4)
{
	if (!no_trace && old_malloc && old_free) {
		CloneData *data;

		data = old_malloc(sizeof(CloneData));

		data->fn = fn;
		data->arg = arg;
		data->info_ptr = info_ptr;
		data->flags = flags;

		return old_clone(clone_helper, child_stack, flags, (void *)data, xarg1, xarg2, xarg3, xarg4);
	}

	return old_clone(fn, child_stack, flags, arg, xarg1, xarg2, xarg3, xarg4);
}

int __clone(int (*fn) (void *arg), void *child_stack, int flags, void *arg, ...)
{
	va_list ap;
	void *xarg1;
	void *xarg2;
	void *xarg3;
	void *xarg4;
	
	va_start(ap, arg),
	xarg1 = va_arg(ap, void *);
	xarg2 = va_arg(ap, void *);
	xarg3 = va_arg(ap, void *);
	xarg4 = va_arg(ap, void *);
	va_end(ap);

	return do_clone(fn, child_stack, flags, arg, xarg1, xarg2, xarg3, xarg4);
}

void _exit(int status)
{
	mt_exit();

	old_exit(status);

	/*
	 * Not reached as old_exit will not return but makes the compiler happy.
	 */
	assert(0);
}

static void construct() __attribute__ ((constructor));
static void construct()
{
	mt_check_init();
}

