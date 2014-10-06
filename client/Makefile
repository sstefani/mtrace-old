.PHONY : all clean clobber depend echo install
.SUFFIXES : .o .cpp .s

MAKEFILE	= Makefile
SHELL		= /bin/sh
LIBS		= -ldl -lrt -lz -lreadline -lbfd

PROGNAME	?= memtrace
INSTALLBASE	?= /usr

CFLAGS         = -Wall -O2 -D_GNU_SOURCE -ggdb
LDFLAGS        = -ggdb -pthread -rdynamic

CC             = $(CROSS_COMPILE)gcc 
LD             = $(CROSS_COMPILE)gcc 

all: $(PROGNAME)

OBJS=\
        binfile.o \
        client.o \
        common.o \
        crash.o \
        dump.o \
        job.o \
        main.o \
        process.o \
	rbtree.o

binfile.o:\
	binfile.c \
	base.h \
	bfdinc.h \
	binfile.h \
	memtrace.h \
	process.h \
	rbtree.h

client.o:\
	client.c \
	base.h \
	bfdinc.h \
	binfile.h \
	client.h \
	common.h \
	memtrace.h \
	process.h \
	rbtree.h

common.o:\
	common.c \
	common.h \
	memtrace.h

crash.o:\
	crash.c \
	crash.h

dump.o:\
	dump.c \
	base.h \
	bfdinc.h \
	dump.h \
	list.h \
	memtrace.h \
	rbtree.h

job.o:\
	job.c \
	base.h \
	bfdinc.h \
	client.h \
	common.h \
	job.h \
	list.h \
	memtrace.h \
	process.h \
	rbtree.h

main.o:\
	main.c \
	base.h \
	bfdinc.h \
	binfile.h \
	client.h \
	common.h \
	crash.h \
	dump.h \
	job.h \
	list.h \
	memtrace.h \
	process.h \
	rbtree.h

process.o:\
	process.c \
	base.h \
	bfdinc.h \
	binfile.h \
	client.h \
	common.h \
	dump.h \
	job.h \
	list.h \
	memtrace.h \
	process.h \
	rbtree.h

rbtree.o:\
	rbtree.c \
	rbtree.h

$(OBJS):
		$(CC) $(CFLAGS) -c $< -o $@

$(PROGNAME):	$(OBJS)
		$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

clean:;		rm -f $(OBJS) $(PROGNAME)

strip:;		$(CROSS_COMPILE)strip $(PROGNAME)

install: strip
		cp $(PROGNAME) $(INSTALLBASE)/lib

