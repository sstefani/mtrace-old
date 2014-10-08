﻿mtrace is an interactive dynamic memory tracer/debugger for C and C++ using
GLIBC, which intercepts and reports all kinds of dynamic memory allocations
using a preloaded library.

It supports the developer to get statistics about the memory usage and finding
memory leaks in an arbitrate application. There is no need of modification of
the source code nor any recompilation.

Unlike other dynamic memory tracer, mtrace is able to find no longer referenced
memory allocation by scanning all writable memory mappings of the program
against the addresses of the allocation. If the memory address will be not found
during a scan there is a high change for a missing reference and therefore for
a memory leak.

The mtrace utility was designed to run in a very constrained environment, like
small embedded systems. This is one of the reasons for a client/server
architecture. The server runs on the target side and the interactive client
runs on the host side, the communication is done via TCP. If server and client
are on the same machine then the communication can be done via UNIX Domain
Socket. Both sides can run on different architectures, address sizes and
endianness, but for tracing 64 bit programs the client must be compiled as a 64
bit program. On the host side all binaries (including debug information) must
be accessible, there is no need for debug information on the target side.

The preloaded library libmemtrace.so intercepts the following GLIBC calls:

- malloc()
- memalign()
- realloc()
- free()
- posix_memalign()
- aligned_alloc()
- valloc()
- pvalloc()
- mmap()
- munmap()
- clone()
- system()
- execve()
- exit()

The new() method is using malloc(), so memory allocations of a C++ application
can be also traced.

Tracing child process it currently not full implemented, but will be one of the
next steps.

Future version will use breakpoints instead of a preloaded library, which makes
it possible to attach the memory leak debugger to an application at any time,
similarly to strace or ltrace. This features allows also to trace internal libc
allocations, statical linked programs and other C libraries (uClibc, bionic).

Currently mtrace supports only Linux, but there are plans to support different
operating systems like Windows (sigh).

Stay tuned...

