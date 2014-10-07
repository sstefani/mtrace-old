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

#include <errno.h> 
#include <string.h> 
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <termios.h>
#include <stdarg.h>
#include <ncurses.h>

#include "base.h"
#include "dump.h"

static int dump_prmt = 1;
static int dump_last;
static int dump_term;
static FILE *dump_outfile;

static int rows, cols;
static int row, col;

int idx;

static int get_term_size(void)
{
#ifdef TIOCGSIZE
	struct ttysize ttys;
#endif
#ifdef TIOCGWINSZ
	struct winsize wins;
#endif
	const char *s;

	if (dump_prmt)
		rows = -1;
	else
		rows = 0;

#ifdef TIOCGSIZE
	if (ioctl(0, TIOCGSIZE, &ttys) != -1) {
		rows += ttys.ts_lines;
		cols = ttys.ts_cols;
		return 0;
	}
#endif
#ifdef TIOCGWINSZ
	if (ioctl(0, TIOCGWINSZ, &wins) != -1) {
		rows += wins.ws_row;
		cols = wins.ws_col;
		return 0;
	}
#endif
	if (rows) {
		s = getenv("LINES");
		if (s)
			rows += strtol(s, NULL, 10);
		else
			rows += 25;
	}

	if (cols) {
		s=getenv("COLUMNS");
		if (s)
			cols = strtol(s, NULL, 10);
		else
			cols = 80;
	}


	return 0;
}

int dump_prompt(int prompt)
{
	if (prompt != -1)
		dump_prmt = prompt;
	return dump_prmt;
}

int dump_open(const char *outfile)
{
	dump_last = 0;
	dump_term = 0;
	dump_outfile = NULL;

	if (outfile) {
		dump_outfile = fopen(outfile, "w");

		if (!dump_outfile) {
			fprintf(stderr, "cannot open output file: %s (%s)\n", outfile, strerror(errno));
			dump_term = 1;
			return -1;
		}

		return 0;
	}

	get_term_size();

	row = 0;
	col = 0;

	return 0;
}

static int dump_pager(void)
{
	struct termios termios;
	struct termios termios_old;
	int c;
	int ret;
	short events;
	
	if (dump_last)
		return 0;

	dump_last = 1;

	if (dump_prmt)
		printf("Press <space> for next line, q for quit and any other for next page\r");

	fflush(stdout);

	tcgetattr(0, &termios_old);
	termios = termios_old;
	cfmakeraw(&termios);

	tcsetattr(0, TCSADRAIN, &termios);
	events = io_set_events(0, POLL_IN);
	while((ret = io_watch(-1)) != 1) {
		if (ret == -1)
			break;
	}
	c = getchar();
	io_set_events(0, events);
	tcsetattr(0, TCSADRAIN, &termios_old);

	if (dump_prmt) {
		printf("                                                                              \r");
		fflush(stdout);
	}

	switch(c) {
	case '\03':
	case 'q':
		dump_term = 1;
		return -1;
	case ' ':
		get_term_size();
		row = rows - 1;
		break;
	default:
		get_term_size();
		row = 0;
		break;
	}

	return 0;
}

static int next_nl(char *str, int l)
{
	int n;

	for(n = 0; *str; ++n) {
		if (!l--)
			break;

		if (*str++ == '\n')
			break;
	}
	return n;
}

static int dump_line(char *s, int n)
{
	dump_last = 0;

	col += fwrite(s, sizeof(char), n, stdout);

	if (s[n] == '\n') {
		if (col < cols)
			fputc('\n', stdout);
		row++;
		col = 0;
	}
	else {
		if (col >= cols) {
			row++;
			col = 0;
		}
	}

	if (row >= rows) {
		if (dump_pager())
			return -1;
	}
	return 0;
}
			
int dump_printf(const char *fmt, ...)
{
	char *str;
	char *s;
	int n;
	va_list args;

	if (dump_term)
		return -1;

	va_start(args, fmt);
	n = vasprintf(&str, fmt, args);
	va_end(args);

	if (n == -1)
		return -1;

	if (dump_outfile)
		fputs(str, dump_outfile);
	else {
		s = str;

		while(*s) {
			n = next_nl(s, cols - col);

			if (dump_line(s, n))
				return -1;

			s += n;

			if (*s == '\n') {
				++s;
				++n;
			}
		}
	}

	free(str);
	return 0;
}

int dump_close(void)
{
	if (dump_outfile) {
		fclose(dump_outfile);

		dump_outfile = NULL;
		dump_term = 1;

		return 0;
	}

	if (!dump_term) {
		if (col) {
			row++;
			col = 0;

			fputc('\n', stdout);
		}
	}
	return fflush(stdout);
}
