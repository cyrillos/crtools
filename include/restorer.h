#ifndef CR_RESTORER_H__
#define CR_RESTORER_H__

#include <signal.h>
#include <limits.h>

#include "compiler.h"
#include "types.h"
#include "image.h"
#include "lock.h"
#include "util.h"
#include "crtools.h"

#ifndef CONFIG_X86_64
# error Only x86-64 is supported
#endif

struct task_restore_core_args;
struct thread_restore_args;

extern long restore_task(long cmd, struct task_restore_core_args *args);
extern long restore_thread(long cmd, struct thread_restore_args *args);

typedef long (*task_restore_fcall_t) (long cmd, struct task_restore_core_args *args);
typedef long (*thread_restore_fcall_t) (long cmd, struct thread_restore_args *args);

#define RESTORE_CMD__NONE		0
#define RESTORE_CMD__GET_SELF_LEN	1
#define RESTORE_CMD__RESTORE_CORE	2
#define RESTORE_CMD__RESTORE_THREAD	3

/*
 * These *must* be power of two values.
 */
#define RESTORE_ARGS_SIZE		(512)
#define RESTORE_STACK_REDZONE		(128)
#define RESTORE_STACK_SIGFRAME		(KILO(16))
#define RESTORE_STACK_SIZE		(KILO(32))
#define RESTORE_HEAP_SIZE		(KILO(16))

#define RESTORE_ALIGN_STACK(start, size)	\
	(ALIGN((start) + (size) - sizeof(long), sizeof(long)))

struct restore_mem_zone {
	u8				redzone[RESTORE_STACK_REDZONE];
	u8				stack[RESTORE_STACK_SIZE];
	u8				rt_sigframe[RESTORE_STACK_SIGFRAME];
	u8				heap[RESTORE_HEAP_SIZE];
} __aligned(sizeof(long));

#define first_on_heap(ptr, heap)	((typeof(ptr))heap)
#define next_on_heap(ptr, prev)		((typeof(ptr))((long)(prev) + sizeof(*(prev))))

/* Make sure it's pow2 in size */
struct thread_restore_args {
	struct restore_mem_zone		mem_zone;

	int				pid;
	int				fd_core;
	u32				*rst_lock;
} __aligned(sizeof(long));

struct task_restore_core_args {
	struct restore_mem_zone		mem_zone;

	int				pid;			/* task pid */
	int				fd_core;		/* opened core file */
	int				fd_self_vmas;		/* opened file with running VMAs to unmap */
	char				ns_last_pid_path[sizeof(LAST_PID_PATH) + 1];
	bool				restore_threads;	/* if to restore threads */
	u32				rst_lock;

	/* threads restoration */
	int				nr_threads;		/* number of threads */
	thread_restore_fcall_t		clone_restore_fn;	/* helper address for clone() call */
	struct thread_restore_args	*thread_args;		/* array of thread arguments */
	struct shmems			*shmems;
	struct task_entries		*task_entries;
} __aligned(sizeof(long));

struct pt_regs {
	unsigned long	r15;
	unsigned long	r14;
	unsigned long	r13;
	unsigned long	r12;
	unsigned long	bp;
	unsigned long	bx;

	unsigned long	r11;
	unsigned long	r10;
	unsigned long	r9;
	unsigned long	r8;
	unsigned long	ax;
	unsigned long	cx;
	unsigned long	dx;
	unsigned long	si;
	unsigned long	di;
	unsigned long	orig_ax;

	unsigned long	ip;
	unsigned long	cs;
	unsigned long	flags;
	unsigned long	sp;
	unsigned long	ss;
};

struct rt_sigcontext {
	unsigned long			r8;
	unsigned long			r9;
	unsigned long			r10;
	unsigned long			r11;
	unsigned long			r12;
	unsigned long			r13;
	unsigned long			r14;
	unsigned long			r15;
	unsigned long			rdi;
	unsigned long			rsi;
	unsigned long			rbp;
	unsigned long			rbx;
	unsigned long			rdx;
	unsigned long			rax;
	unsigned long			rcx;
	unsigned long			rsp;
	unsigned long			rip;
	unsigned long			eflags;
	unsigned short			cs;
	unsigned short			gs;
	unsigned short			fs;
	unsigned short			__pad0;
	unsigned long			err;
	unsigned long			trapno;
	unsigned long			oldmask;
	unsigned long			cr2;
	struct user_fpregs_entry	*fpstate;
	unsigned long			reserved1[8];
};

#ifndef __ARCH_SI_PREAMBLE_SIZE
#define __ARCH_SI_PREAMBLE_SIZE	(3 * sizeof(int))
#endif

#define SI_MAX_SIZE	128
#ifndef SI_PAD_SIZE
#define SI_PAD_SIZE	((SI_MAX_SIZE - __ARCH_SI_PREAMBLE_SIZE) / sizeof(int))
#endif

typedef struct rt_siginfo {
	int	si_signo;
	int	si_errno;
	int	si_code;
	int	_pad[SI_PAD_SIZE];
} rt_siginfo_t;

typedef struct rt_sigaltstack {
	void	*ss_sp;
	int	ss_flags;
	size_t	ss_size;
} rt_stack_t;

struct rt_ucontext {
	unsigned long		uc_flags;
	struct rt_ucontext	*uc_link;
	rt_stack_t		uc_stack;
	struct rt_sigcontext	uc_mcontext;
	rt_sigset_t		uc_sigmask;	/* mask last for extensibility */
};

struct rt_sigframe {
	char			*pretcode;
	struct rt_ucontext	uc;
	struct rt_siginfo	info;

	/* fp state follows here */
};

#define add_ord(c)			\
	do {				\
		if (c < 10)		\
			c += '0';	\
		else			\
			c += 'a' - 10;	\
	} while (0)

static void always_inline write_char(char c)
{
	sys_write(STDERR_FILENO, &c, 1);
}

static void always_inline write_string(char *str)
{
	int len = 0;

	while (str[len])
		len++;

	sys_write(STDERR_FILENO, str, len);
}

static void always_inline write_string_n(char *str)
{
	char new_line = '\n';

	write_string(str);
	sys_write(STDERR_FILENO, &new_line, 1);
}

static void always_inline write_num_n(long num)
{
	unsigned long d = 1000000000000000000;
	unsigned int started = 0;
	unsigned int minus = 0;
	unsigned int c;

	if (num < 0) {
		num = -num;
		c = '-';
		sys_write(STDERR_FILENO, &c, 1);
	}

	while (d) {
		c = num / d;
		num -= d * c;
		d /= 10;
		if (!c && !started)
			continue;
		if (!started)
			started = 1;
		add_ord(c);
		sys_write(STDERR_FILENO, &c, 1);

	}
	c = '\n';
	sys_write(STDERR_FILENO, &c, 1);
}

static long always_inline vprint_num(char *buf, long num)
{
	unsigned long d = 1000000000000000000;
	unsigned int started = 0;
	unsigned int minus = 0;
	unsigned int i = 0;
	unsigned int c;

	if (num < 0) {
		num = -num;
		buf[i++] = '-';
	}

	while (d) {
		c = num / d;
		num -= d * c;
		d /= 10;
		if (!c && !started)
			continue;
		if (!started)
			started = 1;
		add_ord(c);
		buf[i++] = c;

	}

	buf[i++] = 0;

	return i;
}

static void always_inline write_hex_n(unsigned long num)
{
	unsigned char *s = (unsigned char *)&num;
	unsigned char c;
	int i;

	c = 'x';
	sys_write(STDERR_FILENO, &c, 1);
	for (i = sizeof(long)/sizeof(char) - 1; i >= 0; i--) {
		c = (s[i] & 0xf0) >> 4;
		add_ord(c);
		sys_write(STDERR_FILENO, &c, 1);

		c = (s[i] & 0x0f);
		add_ord(c);
		sys_write(STDERR_FILENO, &c, 1);
	}

	c = '\n';
	sys_write(STDERR_FILENO, &c, 1);
}

#define SHMEMS_SIZE	4096

struct shmem_info {
	unsigned long	start;
	unsigned long	end;
	unsigned long	shmid;
	int		pid;
	int		real_pid;
	u32		lock;		/* futex */
};

struct shmems {
	int			nr_shmems;
	struct shmem_info	entries[0];
};

#define TASK_ENTRIES_SIZE 4096

struct task_entry {
	int pid;
	u32 done; // futex
};

struct task_entries {
	int nr;
	u32 start; //futex
	struct task_entry entries[0];
};


static always_inline struct shmem_info *
find_shmem_by_pid(struct shmems *shmems, unsigned long start, int pid)
{
	struct shmem_info *si;
	int i;

	for (i = 0; i < shmems->nr_shmems; i++) {
		si = &shmems->entries[i];
		if (si->start == start	&&
		    si->end > start	&&
		    si->real_pid == pid)
			return si;
	}

	return NULL;
}

static always_inline struct task_entry *
task_get_entry(struct task_entries *base, int pid)
{
	int i;

	for (i = 0; i < base->nr; i++)
		if (base->entries[i].pid == pid)
			return &base->entries[i];

	return NULL;
}

#endif /* CR_RESTORER_H__ */
