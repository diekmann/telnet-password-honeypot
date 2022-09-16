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
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <grp.h>

#include "telnet_srv.h"




/*
 * A child has exited.
 */
static void SIGCHLD_handler(int sig)
{
	(void) sig;
	int status;
	pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		printf("Process %d has exited with code %d.\n", pid, WEXITSTATUS(status));
}

/*
 * Drops us into a chroot, if possible, and drops privs.
 */
static void drop_privileges()
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

	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) {
		perror("prctl(PR_SET_DUMPABLE)");
		exit(EXIT_FAILURE);
	}
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
