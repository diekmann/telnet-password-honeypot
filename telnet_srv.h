#ifndef TELNET_SRV_H
#define TELNET_SRV_H

#include <stdio.h>

extern FILE *logfile;

void handle_connection(int fd, char *ipaddr);

#endif
