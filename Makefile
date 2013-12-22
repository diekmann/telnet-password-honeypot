CFLAGS		= -Wall -Wextra -O2 -DDEBUG #-ansi -std=c99  #-Werror

EXECUTABLE	= honeypot

$(EXECUTABLE): honeypot.c telnet.h seccomp-bpf.h


clean:
	rm -f $(EXECUTABLE)
	rm -f *.o
