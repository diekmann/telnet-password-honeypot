#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>

#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# warning "Platform does not support seccomp filter yet"
# define REG_SYSCALL	0
# define ARCH_NR	0
#endif

#define VALIDATE_ARCHITECTURE \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
