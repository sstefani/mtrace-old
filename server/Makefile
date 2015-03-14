.PHONY : all clean clobber depend echo install
.SUFFIXES : .o .cpp .s

MAKEFILE	= Makefile
SHELL		= /bin/sh

INSTALL_BASE	?= /usr

LIB_NAME	= libmemtrace.so
LIB_CFLAGS	= -Wall -O2 -D_GNU_SOURCE -g -fpic -fno-strict-aliasing
LIB_LDFLAGS	= -g -shared
LIB_LIBS	= -ldl -lrt -lunwind

SERVER_NAME	= memtrace-server
SERVER_CFLAGS	= -Wall -O2 -D_GNU_SOURCE -g -fno-strict-aliasing
SERVER_LDFLAGS	= -g
SERVER_LIBS	= -lpthread -lrt

#CROSS_COMPILE = /home/buildsys4/ppc/powerpc-603-linux-gnu/bin/powerpc-603-linux-gnu-

CC             = $(CROSS_COMPILE)gcc 
LD             = $(CROSS_COMPILE)gcc 

all: $(SERVER_NAME) $(LIB_NAME)

LIB_OBJS=\
        memtrace.o \
	common_memtrace.o

SERVER_OBJS=\
	server.o \
	common_server.o

memtrace.o:\
	memtrace.c \
	memtrace.h \
	common.h

common_memtrace.o:\
	common.c \
	common.h \
	memtrace.h

server.o:\
	server.c \
	memtrace.h \
	common.h

common_server.o:\
	common.c \
	common.h \
	memtrace.h

$(LIB_OBJS):
		$(CC) $(LIB_CFLAGS) -c $< -o $@

$(LIB_NAME):	$(LIB_OBJS)
		$(LD) $(LIB_LDFLAGS) $(LIB_OBJS) $(LIB_LIBS) -o $@

$(SERVER_OBJS):
		$(CC) $(SERVER_CFLAGS) -c $< -o $@

$(SERVER_NAME):	$(SERVER_OBJS)
		$(LD) $(SERVER_LDFLAGS) $(SERVER_OBJS) $(SERVER_LIBS) -o $@

clean:;		rm -f $(LIB_OBJS) $(LIB_NAME) $(SERVER_OBJS) $(SERVER_NAME) 


strip:;		$(CROSS_COMPILE)strip $(LIB_NAME) $(SERVER_NAME)

install: strip
		cp $(LIB_NAME) $(INSTALL_BASE)/lib
		cp mt $(INSTALLBASE)/bin

