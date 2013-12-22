CFLAGS		= -Wall -Wextra -O2 -DDEBUG #-ansi -std=c99  #-Werror

EXECUTABLE	= honeypot

$(EXECUTABLE): honeypot.o telnet_srv.o telnet_srv.h telnet.h seccomp-bpf.h
	$(CC) -o $(EXECUTABLE) $(CFLAGS) honeypot.o telnet_srv.o

honeypot.o: honeypot.c telnet.h
	$(CC) -c -o $@ $(CFLAGS) $<
	
telnet_srv.o: telnet_srv.c telnet_srv.h telnet.h seccomp-bpf.h
	$(CC) -c -o $@ $(CFLAGS) $<
	
clean:
	rm -f $(EXECUTABLE)
	rm -f *.o
