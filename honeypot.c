/*
 * honeypot.c
 * 
 * 
 * This is telnet honeypot server. It asks the user for a username and password
 * and logs it shamelessly to a file.
 * 
 * This honeypot drops all privileges and chroots to /var/empty, after opening the
 * log file and binding to the telnet port.
 * 
 * 
 * Copyright (C) 2012 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * 
 * Much of the telnet setup logic has been taken from the hilarious nyancat
 * telnet server, nyancat.c, which is Copyright 2011 by Kevin Lange.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal with the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimers.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimers in the
 *      documentation and/or other materials provided with the distribution.
 *   3. Neither the names of the Jason A. Donenfeld, Association for Computing
 *      Machinery, Kevin Lange, nor the names of its contributors may be used
 *      to endorse or promote products derived from this Software without
 *      specific prior written permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * WITH THE SOFTWARE.
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <netinet/in.h>

/*
 * telnet.h contains some #defines for the various
 * commands, escape characters, and modes for telnet.
 * (it surprises some people that telnet is, really,
 *  a protocol, and not just raw text transmission)
 */
#include "telnet.h"
#include "seccomp-bpf.h"


FILE *input = 0;
FILE *output = 0;
FILE *logfile = 0;
int is_telnet_client = 0;

/*
 * Telnet requires us to send a specific sequence
 * for a line break (\r\000\n), so let's make it happy.
 */
void newline(int n)
{
	int i;

	for (i = 0; i < n; ++i) {
		/* Send the telnet newline sequence */
		putc('\r', output);
		putc(0, output);
		putc('\n', output);
	}
}


/*
 * When the listener dies, we want to kill the clients too, but
 * first we make sure to send a nice message and restore the cursor.
 */
void SIGINT_handler(int sig)
{
	fprintf(stderr, "Got SIGINT, exiting gracefully.\n");
	newline(3);
	fprintf(output, "\033[1;33m*** Server shutting down. Goodbye. ***\033[0m\033[?25h");
	newline(2);
	fflush(output);
	_exit(EXIT_SUCCESS);
}

/*
 * Handle the alarm which breaks us off of options
 * handling if we didn't receive a terminal.
 */
void SIGALRM_handler(int sig)
{
	alarm(0);
	if (!is_telnet_client) {
		fprintf(stderr, "Bad telnet negotiation, exiting.\n");
		fprintf(output, "\033[?25h\033[0m\033[H\033[2J");
		fprintf(output, "\033[1;31m*** You must connect using a real telnet client. ***\033[0m");
		newline(1);
		fflush(output);
		_exit(EXIT_FAILURE);
	} else {
		fprintf(stderr, "Timeout reached, exiting.\n");
		newline(3);
		fprintf(output, "\033[1;33m*** Authentication timed out. Please reconnect. ***\033[0m\033[?25h");
		newline(2);
		fflush(output);
		_exit(EXIT_SUCCESS);
	}
}

/*
 * A child has exited.
 */
void SIGCHLD_handler(int sig)
{
	int status;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		printf("Process %d has exited with code %d.\n", pid, WEXITSTATUS(status));
}

/*
 * Reads a line character by character for when local echo mode is turned off.
 */
void readline(char *buffer, size_t size, int password)
{
	int i;
	unsigned char c;
	
	/* We make sure to restore the cursor. */
	fprintf(output, "\033[?25h");
	fflush(output);
	
	for (i = 0; i < size - 1; ++i) {
		if (feof(input))
			_exit(EXIT_SUCCESS);
		c = getc(input);
		if (c == '\r' || c == '\n') {
			if (c == '\r') {
				/* the next char is either \n or \0, which we can discard. */
				getc(input);
			}
			newline(1);
			break;
		} else if (c == '\b' || c == 0x7f) {
			if (!i) {
				i = -1;
				continue;
			}
			if (password) {
				fprintf(output, "\033[%dD\033[K", i);
				fflush(output);
				i = -1;
				continue;
			} else {
				fprintf(output, "\b \b");
				fflush(output);
				i -= 2;
				continue;
			}
		} else if (c == 0xff)
			_exit(EXIT_SUCCESS);
		else if (iscntrl(c)) {
			--i;
			continue;
		}
		buffer[i] = c;
		putc(password ? '*' : c, output);
		fflush(output);
	}
	buffer[i] = 0;
	
	/* And we hide it again at the end. */
	fprintf(output, "\033[?25l");
	fflush(output);
}

/*
 * These are the options we want to use as
 * a telnet server. These are set in set_options()
 */
unsigned char telnet_options[256] = { 0 };
unsigned char telnet_willack[256] = { 0 };

/*
 * These are the values we have set or
 * agreed to during our handshake.
 * These are set in send_command(...)
 */
unsigned char telnet_do_set[256]  = { 0 };
unsigned char telnet_will_set[256]= { 0 };

/*
 * Send a command (cmd) to the telnet client
 * Also does special handling for DO/DONT/WILL/WONT
 */
void send_command(int cmd, int opt)
{
	/* Send a command to the telnet client */
	if (cmd == DO || cmd == DONT) {
		/* DO commands say what the client should do. */
		if (((cmd == DO) && (telnet_do_set[opt] != DO)) || ((cmd == DONT) && (telnet_do_set[opt] != DONT))) {
			/* And we only send them if there is a disagreement */
			telnet_do_set[opt] = cmd;
			fprintf(output, "%c%c%c", IAC, cmd, opt);
		}
	} else if (cmd == WILL || cmd == WONT) {
		/* Similarly, WILL commands say what the server will do. */
		if (((cmd == WILL) && (telnet_will_set[opt] != WILL)) || ((cmd == WONT) && (telnet_will_set[opt] != WONT))) {
			/* And we only send them during disagreements */
			telnet_will_set[opt] = cmd;
			fprintf(output, "%c%c%c", IAC, cmd, opt);
		}
	} else
		/* Other commands are sent raw */
		fprintf(output, "%c%c", IAC, cmd);
	fflush(output);
}

/*
 * Set the default options for the telnet server.
 */
void set_options()
{
	int option;
	
	/* We will echo input */
	telnet_options[ECHO] = WILL;
	/* We will set graphics modes */
	telnet_options[SGA] = WILL;
	/* We will not set new environments */
	telnet_options[NEW_ENVIRON] = WONT;
	
	/* The client should not echo its own input */
	telnet_willack[ECHO] = DONT;
	/* The client can set a graphics mode */
	telnet_willack[SGA] = DO;
	/* We do not care about window size updates */
	telnet_willack[NAWS] = DONT;
	/* The client should tell us its terminal type (very important) */
	telnet_willack[TTYPE] = DO;
	/* No linemode */
	telnet_willack[LINEMODE] = DONT;
	/* And the client can set a new environment */
	telnet_willack[NEW_ENVIRON] = DO;
	
	
	/* Let the client know what we're using */
	for (option = 0; option < sizeof(telnet_options); ++option) {
		if (telnet_options[option])
			send_command(telnet_options[option], option);
	}
	for (option = 0; option < sizeof(telnet_willack); ++option) {
		if (telnet_willack[option])
			send_command(telnet_willack[option], option);
	}
}

/*
 * Negotiate the telnet options.
 */
void negotiate_telnet()
{
	/* The default terminal is ANSI */
	char term[1024] = {'a','n','s','i', 0};
	int ttype, done = 0, sb_mode = 0, do_echo = 0, sb_len = 0;
	/* Various pieces for the telnet communication */
	char sb[1024];
	unsigned char opt, i;
	memset(sb, 0, sizeof(sb));
	
	
	/* Set the default options. */
	set_options();	

	/* We will stop handling options after ten seconds */
	alarm(10);

	/* Let's do this */
	while (!feof(stdin) && done < 1) {
		/* Get either IAC (start command) or a regular character (break, unless in SB mode) */
		i = getc(input);
		if (i == IAC) {
			/* If IAC, get the command */
			i = getc(input);
			switch (i) {
				case SE:
					/* End of extended option mode */
					sb_mode = 0;
					if (sb[0] == TTYPE) {
						alarm(0);
						is_telnet_client = 1;
						/* This was a response to the TTYPE command, meaning
						 * that this should be a terminal type */
						strncpy(term, &sb[2], sizeof(term) - 1);
						term[sizeof(term) - 1] = 0;
						++done;
					}
					break;
				case NOP:
					/* No Op */
					send_command(NOP, 0);
					fflush(output);
					break;
				case WILL:
				case WONT:
					/* Will / Won't Negotiation */
					opt = getc(input);
					if (opt < 0 || opt >= sizeof(telnet_willack))
						_exit(EXIT_FAILURE);
					if (!telnet_willack[opt])
						/* We default to WONT */
						telnet_willack[opt] = WONT;
					send_command(telnet_willack[opt], opt);
					fflush(output);
					if ((i == WILL) && (opt == TTYPE)) {
						/* WILL TTYPE? Great, let's do that now! */
						fprintf(output, "%c%c%c%c%c%c", IAC, SB, TTYPE, SEND, IAC, SE);
						fflush(output);
					}
					break;
				case DO:
				case DONT:
					/* Do / Don't Negotiation */
					opt = getc(input);
					if (opt < 0 || opt >= sizeof(telnet_options))
						_exit(EXIT_FAILURE);
					if (!telnet_options[opt])
						/* We default to DONT */
						telnet_options[opt] = DONT;
					send_command(telnet_options[opt], opt);
					if (opt == ECHO)
						do_echo = (i == DO);
					fflush(output);
					break;
				case SB:
					/* Begin Extended Option Mode */
					sb_mode = 1;
					sb_len  = 0;
					memset(sb, 0, sizeof(sb));
					break;
				case IAC: 
					/* IAC IAC? That's probably not right. */
					done = 2;
					break;
				default:
					break;
			}
		} else if (sb_mode) {
			/* Extended Option Mode -> Accept character */
			if (sb_len < (sizeof(sb) - 1))
				/* Append this character to the SB string,
				 * but only if it doesn't put us over
				 * our limit; honestly, we shouldn't hit
				 * the limit, as we're only collecting characters
				 * for a terminal type or window size, but better safe than
				 * sorry (and vulnerable).
				 */
				sb[sb_len++] = i;
		}
	}
	
	/* What shall we now do with term, ttype, do_echo, and terminal_width? */
}

/*
 * Drops us into a chroot, if possible, and drops privs.
 */
void drop_privileges()
{
	struct passwd *user;
	struct rlimit limit;
	
	if (!geteuid()) {
		user = getpwnam("nobody");
		if (!user) {
			perror("getpwnam");
			exit(EXIT_FAILURE);
		}
		if (chroot("/var/empty")) {
			perror("chroot");
			exit(EXIT_FAILURE);
		}
		if (chdir("/")) {
			perror("chdir");
			exit(EXIT_FAILURE);
		}
		if (setresgid(user->pw_gid, user->pw_gid, user->pw_gid)) {
			perror("setresgid");
			exit(EXIT_FAILURE);
		}
		if (setgroups(1, &user->pw_gid)) {
			perror("setgroups");
			exit(EXIT_FAILURE);
		}
		if (setresuid(user->pw_uid, user->pw_uid, user->pw_uid)) {
			perror("setresuid");
			exit(EXIT_FAILURE);
		}
		if (!geteuid() || !getegid()) {
			fprintf(stderr, "Mysteriously still running as root... Goodbye.\n");
			exit(EXIT_FAILURE);
		}
	}
	
	
	
	limit.rlim_cur = limit.rlim_max = 4194304 /* 4 megs */;
	setrlimit(RLIMIT_DATA, &limit);
	setrlimit(RLIMIT_FSIZE, &limit);
	setrlimit(RLIMIT_MEMLOCK, &limit);
	setrlimit(RLIMIT_STACK, &limit);
	limit.rlim_cur = limit.rlim_max = 15728640 /* 15 megabytes */;
	setrlimit(RLIMIT_AS, &limit);
	limit.rlim_cur = limit.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &limit);
	limit.rlim_cur = limit.rlim_max = 100;
	setrlimit(RLIMIT_NPROC, &limit);

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS");
		exit(EXIT_FAILURE);
	}
}

void seccomp_enable_filter()
{
	struct sock_filter filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		ALLOW_SYSCALL(rt_sigreturn),
		ALLOW_SYSCALL(rt_sigprocmask),
		ALLOW_SYSCALL(rt_sigaction),
		ALLOW_SYSCALL(nanosleep),
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		ALLOW_SYSCALL(alarm),
		KILL_PROCESS
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter
	};
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		exit(EXIT_FAILURE);
	}
}

void handle_connection(int fd, char *ipaddr)
{
	char username[1024];
	char password[1024];
	struct rlimit limit;

	limit.rlim_cur = limit.rlim_max = 90;
	setrlimit(RLIMIT_CPU, &limit);
	limit.rlim_cur = limit.rlim_max = 0;
	setrlimit(RLIMIT_NPROC, &limit);

	input = fdopen(fd, "r");
	if (!input) {
		perror("fdopen");
		_exit(EXIT_FAILURE);
	}
	output = fdopen(fd, "w");
	if (!output) {
		perror("fdopen");
		_exit(EXIT_FAILURE);
	}

	seccomp_enable_filter();
	
	/* Set the alarm handler to quit on bad telnet clients. */
	if (signal(SIGALRM, SIGALRM_handler) == SIG_ERR) {
		perror("signal");
		_exit(EXIT_FAILURE);
	}
	/* Accept ^C -> restore cursor. */
	if (signal(SIGINT, SIGINT_handler) == SIG_ERR) {
		perror("signal");
		_exit(EXIT_FAILURE);
	}

	negotiate_telnet();
	
	/* Quit after a minute and a half. */
	alarm(90);

	/* Attempt to set terminal title for various different terminals. */
	fprintf(output, "\033kWelcome to kexec.com\033\134");
	fprintf(output, "\033]1;Welcome to kexec.com\007");
	fprintf(output, "\033]2;Welcome to kexec.com\007");

	/* Clear the screen */
	fprintf(output, "\033[H\033[2J\033[?25l");
	
	fprintf(output, "                  \033[1mkexec.com Administration Console\033[0m");
	newline(3);
	fprintf(output, "This console uses \033[1;34mGoogle App Engine\033[0m for authentication. To login as");
	newline(1);
	fprintf(output, "an administrator, enter the admin account credentials. If you do not");
	newline(1);
	fprintf(output, "yet have an account on kexec, enter your \033[1m\033[34mG\033[31mo\033[33mo\033[34mg\033[32ml\033[31me\033[0m credentials to begin.");
	newline(4);
	fflush(output);
	
	while (1) {
		fprintf(output, "\033[1;32mUsername: \033[0m");
		readline(username, sizeof(username), 0);
		fprintf(output, "\033[1;32mPassword: \033[0m");
		readline(password, sizeof(password), 1);
		newline(2);
		fflush(output);
		fprintf(logfile, "%s - %s:%s\n", ipaddr, username, password);
		fflush(logfile);
		printf("Honeypotted: %s - %s:%s\n", ipaddr, username, password);
		sleep(1);
		newline(1);
		fprintf(output, "\033[1;31mInvalid credentials. Please try again.\033[0m");
		fflush(output);
		sleep(2);
		fprintf(output, "\033[H\033[2J\033[?25l");
		fprintf(output, "                  \033[1mkexec.com Administration Console\033[0m");
		newline(2);
		if (!strchr(username, '@')) {
			fprintf(output, "\033[1;34mBe sure to include the domain in your username (e.g. @gmail.com).\033[0m");
			newline(2);
		}
		fflush(output);
	}
	fclose(input);
	fclose(output);
}

int main(int argc, char *argv[])
{
	int listen_fd, connection_fd, flag;
	struct sockaddr_in6 listen_addr;
	struct sockaddr_storage connection_addr;
	socklen_t connection_addr_len;
	pid_t child;

	int daemonize = 0, option_index = 0, debug_file, option;
	char *debug_log = 0, *honey_log = 0, *pid_file = 0;
	FILE *pidfile;
	static struct option long_options[] = {
		{"daemonize", no_argument, NULL, 'd'},
		{"foreground", no_argument, NULL, 'f'},
		{"debug-log", required_argument, NULL, 'l'},
		{"honey-log", required_argument, NULL, 'o'},
		{"pid-file", required_argument, NULL, 'p'},
		{"help", no_argument, NULL, 'h'},
		{0, 0, 0, 0}
	};

	close(STDIN_FILENO);

	while ((option = getopt_long(argc, argv, "dfl:o:p:h", long_options, &option_index)) != -1) {
		switch (option) {
			case 'd':
				daemonize = 1;
				break;
			case 'f':
				daemonize = 0;
				break;
			case 'l':
				debug_log = optarg;
				break;
			case 'o':
				honey_log = optarg;
				break;
			case 'p':
				pid_file = optarg;
				break;
			case 'h':
			case '?':
			default:
				fprintf(stderr, "Honeypot Telnet Server by zx2c4\n\n");
				fprintf(stderr, "Usage: %s [OPTION]...\n", argv[0]);
				fprintf(stderr, "  -d, --daemonize              run as a background daemon\n");
				fprintf(stderr, "  -f, --foreground             run in the foreground (default)\n");
				fprintf(stderr, "  -l FILE, --debug-log=FILE    log debug messages to FILE instead of to stdout/stderr\n");
				fprintf(stderr, "  -o FILE, --honey-log=FILE    log collected honey information to FILE\n");
				fprintf(stderr, "  -p FILE, --pid-file=FILE     write pid of listener process to FILE\n");
				fprintf(stderr, "  -h, --help                   display this message\n");
				return option == 'h' ? EXIT_SUCCESS : EXIT_FAILURE;
		}
	}
	if (debug_log) {
		debug_file = open(debug_log, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		if (debug_file < 0) {
			perror("open");
			return EXIT_FAILURE;
		}
		if (dup2(debug_file, STDOUT_FILENO) < 0) {
			perror("dup2");
			return EXIT_FAILURE;
		}
		if (dup2(debug_file, STDERR_FILENO) < 0) {
			perror("dup2");
			return EXIT_FAILURE;
		}
		close(debug_file);
		setbuf(stdout, NULL);
		setbuf(stderr, NULL);
	}
	if (!honey_log) {
		fprintf(stderr, "Warning: collected honey information is not being logged anywhere. See the --honey-log option.\n");
		honey_log = "/dev/null";
	}
	
	/* We open the log file before chrooting. */
	logfile = fopen(honey_log, "a");
	if (!logfile) {
		perror("fopen");
		return EXIT_FAILURE;
	}
	
	/* We bind to port 23 before chrooting, as well. */
	listen_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}
	flag = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
	flag = 0;
	setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
	
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin6_family = AF_INET6;
	listen_addr.sin6_addr = in6addr_any;
	listen_addr.sin6_port = htons(23);
	if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}
	if (listen(listen_fd, 5) < 0) {
		perror("listen");
		return EXIT_FAILURE;
	}

	if (pid_file) {
		pidfile = fopen(pid_file, "w");
		if (!pidfile) {
			perror("fopen");
			return EXIT_FAILURE;
		}
	}
	if (daemonize) {
		if (daemon(0, debug_log != 0) < 0) {
			perror("daemon");
			return EXIT_FAILURE;
		}
	}
	if (pid_file) {
		if (fprintf(pidfile, "%d\n", getpid()) < 0) {
			perror("fprintf");
			return EXIT_FAILURE;
		}
		fclose(pidfile);
	}
	
	/* Before accepting any connections, we chroot. */
	drop_privileges();

	prctl(PR_SET_NAME, "honeypot listen");
	
	/* Print message when child exits. */
	signal(SIGCHLD, SIGCHLD_handler);
	
	while ((connection_addr_len = sizeof(connection_addr)) &&
		(connection_fd = accept(listen_fd, (struct sockaddr *)&connection_addr, &connection_addr_len)) >= 0) {
		child = fork();
		if (child < 0) {
			perror("fork");
			close(connection_fd);
			continue;
		}
		if (!child) {
			char ipaddr[INET6_ADDRSTRLEN];
			struct in6_addr *v6;
			prctl(PR_SET_PDEATHSIG, SIGINT);
			if (getppid() == 1)
				kill(getpid(), SIGINT);
			prctl(PR_SET_NAME, "honeypot serve");
			close(listen_fd);
			memset(ipaddr, 0, sizeof(ipaddr));
			if (connection_addr.ss_family == AF_INET6) {
				v6 = &(((struct sockaddr_in6 *)&connection_addr)->sin6_addr);
				if (v6->s6_addr32[0] == 0 && v6->s6_addr32[1] == 0 && v6->s6_addr16[4] == 0 && v6->s6_addr16[5] == 0xFFFF)
					inet_ntop(AF_INET, &v6->s6_addr32[3], ipaddr, INET_ADDRSTRLEN);
				else
					inet_ntop(AF_INET6, v6, ipaddr, INET6_ADDRSTRLEN);
			} else if (connection_addr.ss_family == AF_INET)
				inet_ntop(AF_INET, &(((struct sockaddr_in *)&connection_addr)->sin_addr), ipaddr, INET_ADDRSTRLEN);
			printf("Forked process %d for connection %s.\n", getpid(), ipaddr);
			handle_connection(connection_fd, ipaddr);
			_exit(EXIT_FAILURE);
		} else
			close(connection_fd);
	}
	fclose(logfile);
	return 0;
}
