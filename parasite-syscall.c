#include <unistd.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "syscall.h"
#include "ptrace.h"
#include "processor-flags.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"
#include "parasite.h"
#include "crtools.h"

#include <string.h>
#include <stdlib.h>

#ifdef CONFIG_X86_64
static const char code_syscall[] = {0x0f, 0x05, 0xcc, 0xcc,
				    0xcc, 0xcc, 0xcc, 0xcc};

#define code_syscall_size	(round_up(sizeof(code_syscall), sizeof(long)))
#define parasite_size		(round_up(sizeof(parasite_blob), sizeof(long)))

static int can_run_syscall(unsigned long ip, unsigned long start, unsigned long end)
{
	return ip >= start && ip < (end - code_syscall_size);
}

static int syscall_fits_vma_area(struct vma_area *vma_area)
{
	return can_run_syscall((unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.start,
			       (unsigned long)vma_area->vma.end);
}

static struct vma_area *get_vma_by_ip(struct list_head *vma_area_list, unsigned long ip)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (!in_vma_area(vma_area, ip))
			continue;
		if (!(vma_area->vma.prot & PROT_EXEC))
			continue;
		if (syscall_fits_vma_area(vma_area))
			return vma_area;
	}

	return NULL;
}

/* Note it's destructive on @regs */
static void parasite_setup_regs(unsigned long new_ip, user_regs_struct_t *regs)
{
	regs->ip = new_ip;

	/* Avoid end of syscall processing */
	regs->orig_ax = -1;

	/* Make sure flags are in known state */
	regs->flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_DF | X86_EFLAGS_IF);
}

/* we run at @regs->ip */
static int __parasite_execute(struct parasite_ctl *ctl, pid_t pid, user_regs_struct_t *regs)
{
	siginfo_t siginfo;
	int status;
	int ret = -1;

again:
	if (ptrace(PTRACE_SETREGS, pid, NULL, regs)) {
		pr_err("Can't set registers (pid: %d)\n", pid);
		goto err;
	}

	/*
	 * Most ideas are taken from Tejun Heo's parasite thread
	 * https://code.google.com/p/ptrace-parasite/
	 */

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_err("Can't continue (pid: %d)\n", pid);
		goto err;
	}

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_err("Waited pid mismatch (pid: %d)\n", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_err("Can't get siginfo (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETREGS, pid, NULL, regs)) {
		pr_err("Can't obtain registers (pid: %d)\n", pid);
			goto err;
	}

	if (WSTOPSIG(status) != SIGTRAP || siginfo.si_code != SI_KERNEL) {
retry_signal:
		pr_debug("** delivering signal %d si_code=%d\n",
			 siginfo.si_signo, siginfo.si_code);

		if (ctl->signals_blocked) {
			pr_err("Unexpected %d task interruption, aborting\n", pid);
			goto err;
		}

		/* FIXME: jerr(siginfo.si_code > 0, err_restore); */

		/*
		 * This requires some explanation. If a signal from original
		 * program delivered while we're trying to execute our
		 * injected blob -- we need to setup original registers back
		 * so the kernel would make sigframe for us and update the
		 * former registers.
		 *
		 * Then we should swap registers back to our modified copy
		 * and retry.
		 */

		if (ptrace(PTRACE_SETREGS, pid, NULL, &ctl->regs_orig)) {
			pr_err("Can't set registers (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
			pr_err("Can't interrupt (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)siginfo.si_signo)) {
			pr_err("Can't continue (pid: %d)\n", pid);
			goto err;
		}

		if (wait4(pid, &status, __WALL, NULL) != pid) {
			pr_err("Waited pid mismatch (pid: %d)\n", pid);
			goto err;
		}

		if (!WIFSTOPPED(status)) {
			pr_err("Task is still running (pid: %d)\n", pid);
			goto err;
		}

		if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
			pr_err("Can't get siginfo (pid: %d)\n", pid);
			goto err;
		}

		if (SI_EVENT(siginfo.si_code) != PTRACE_EVENT_STOP)
			goto retry_signal;

		/*
		 * Signal is delivered, so we should update
		 * original registers.
		 */
		{
			user_regs_struct_t r;
			if (ptrace(PTRACE_GETREGS, pid, NULL, &r)) {
				pr_err("Can't obtain registers (pid: %d)\n", pid);
				goto err;
			}
			ctl->regs_orig = r;
		}

		goto again;
	}

	/*
	 * Our code is done.
	 */
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) {
		pr_err("Can't interrupt (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
		pr_err("Can't continue (pid: %d)\n", pid);
		goto err;
	}

	if (wait4(pid, &status, __WALL, NULL) != pid) {
		pr_err("Waited pid mismatch (pid: %d)\n", pid);
		goto err;
	}

	if (!WIFSTOPPED(status)) {
		pr_err("Task is still running (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &siginfo)) {
		pr_err("Can't get siginfo (pid: %d)\n", pid);
		goto err;
	}

	if (SI_EVENT(siginfo.si_code) != PTRACE_EVENT_STOP) {
		pr_err("si_code doesn't match (pid: %d si_code: %d)\n",
			pid, siginfo.si_code);
		goto err;
	}

	ret = 0;
err:
	return ret;
}

static int parasite_execute_by_pid(unsigned long cmd, struct parasite_ctl *ctl,
			    pid_t pid,
			    parasite_status_t *args, int args_size)
{
	int ret;
	user_regs_struct_t regs_orig, regs;

	if (ctl->pid == pid)
		regs = ctl->regs_orig;
	else {
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs_orig)) {
			pr_err("Can't obtain registers (pid: %d)\n", pid);
			return -1;
		}
		regs = regs_orig;
	}

	memcpy(ctl->addr_cmd, &cmd, sizeof(cmd));
	if (args)
		memcpy(ctl->addr_args, args, args_size);

	parasite_setup_regs(ctl->parasite_ip, &regs);

	ret = __parasite_execute(ctl, pid, &regs);

	if (args)
		memcpy(args, ctl->addr_args, args_size);

	BUG_ON(ret && !args);

	if (ret)
		pr_err("Parasite exited with %d ret (%li at %li)\n",
		       ret, args->ret, args->line);

	if (ctl->pid != pid)
		if (ptrace(PTRACE_SETREGS, pid, NULL, &regs_orig)) {
			pr_err("Can't restore registers (pid: %d)\n", ctl->pid);
			return -1;
		}

	return ret;
}

static int parasite_execute(unsigned long cmd, struct parasite_ctl *ctl,
			    parasite_status_t *args, int args_size)
{
	return parasite_execute_by_pid(cmd, ctl, ctl->pid, args, args_size);
}

static void *mmap_seized(struct parasite_ctl *ctl,
			 void *addr, size_t length, int prot,
			 int flags, int fd, off_t offset)
{
	user_regs_struct_t regs = ctl->regs_orig;
	void *map = NULL;
	int ret;

	regs.ax = (unsigned long)__NR_mmap;	/* mmap		*/
	regs.di = (unsigned long)addr;		/* @addr	*/
	regs.si = (unsigned long)length;	/* @length	*/
	regs.dx = (unsigned long)prot;		/* @prot	*/
	regs.r10= (unsigned long)flags;		/* @flags	*/
	regs.r8 = (unsigned long)fd;		/* @fd		*/
	regs.r9 = (unsigned long)offset;	/* @offset	*/

	parasite_setup_regs(ctl->syscall_ip, &regs);

	ret = __parasite_execute(ctl, ctl->pid, &regs);
	if (ret)
		goto err;

	if ((long)regs.ax > 0)
		map = (void *)regs.ax;
err:
	return map;
}

static int munmap_seized(struct parasite_ctl *ctl, void *addr, size_t length)
{
	user_regs_struct_t regs = ctl->regs_orig;
	int ret;

	regs.ax = (unsigned long)__NR_munmap;	/* mmap		*/
	regs.di = (unsigned long)addr;		/* @addr	*/
	regs.si = (unsigned long)length;	/* @length	*/

	parasite_setup_regs(ctl->syscall_ip, &regs);

	ret = __parasite_execute(ctl, ctl->pid, &regs);
	if (!ret)
		ret = (int)regs.ax;

	return ret;
}

static int gen_parasite_saddr(struct sockaddr_un *saddr, int key)
{
	int sun_len;

	saddr->sun_family = AF_UNIX;
	snprintf(saddr->sun_path, UNIX_PATH_MAX,
			"X/crtools-pr-%d", key);

	sun_len = SUN_LEN(saddr);
	*saddr->sun_path = '\0';

	return sun_len;
}

static int parasite_send_fd(struct parasite_ctl *ctl, int fd)
{
	struct sockaddr_un saddr;
	int sun_len, ret = -1;
	int sock;

	sun_len = gen_parasite_saddr(&saddr, ctl->pid);

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	if (send_fd(sock, &saddr, sun_len, fd) < 0) {
		pr_perror("Can't send file descriptor");
		goto out;
	}
	ret = 0;
out:
	close(sock);
	return ret;
}

static int parasite_prep_file(int fd, struct parasite_ctl *ctl)
{
	int ret;

	if (fchmod(fd, CR_FD_PERM_DUMP)) {
		pr_perror("Can't change permissions on file");
		return -1;
	}

	ret = parasite_send_fd(ctl, fd);
	if (ret)
		return ret;

	return 0;
}

static int parasite_file_cmd(char *what, int cmd, int type,
			     struct parasite_ctl *ctl,
			     struct cr_fdset *cr_fdset)
{
	parasite_status_t args = { };
	int ret = -1, fd;

	pr_info("\n");
	pr_info("Dumping %s (pid: %d)\n", what, ctl->pid);
	pr_info("----------------------------------------\n");

	fd = fdset_fd(cr_fdset, type);
	ret = parasite_prep_file(fd, ctl);
	if (ret < 0)
		goto out;

	ret = parasite_execute(cmd, ctl, (parasite_status_t *)&args, sizeof(args));

	fchmod(fd, CR_FD_PERM);
out:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parasite_init(struct parasite_ctl *ctl, pid_t pid)
{
	struct parasite_init_args args = { };

	args.sun_len = gen_parasite_saddr(&args.saddr, pid);

	return parasite_execute(PARASITE_CMD_INIT, ctl,
				(parasite_status_t *)&args, sizeof(args));
}

static int parasite_set_logfd(struct parasite_ctl *ctl, pid_t pid)
{
	parasite_status_t args = { };
	int ret;

	ret = parasite_send_fd(ctl, log_get_fd());
	if (ret)
		return ret;

	ret = parasite_execute(PARASITE_CMD_SET_LOGFD, ctl, &args, sizeof(args));
	if (ret < 0)
		return ret;

	return 0;
}

int parasite_dump_thread_seized(struct parasite_ctl *ctl, pid_t pid,
					unsigned int **tid_addr, u32 *tid)
{
	struct parasite_dump_tid_addr args = { };
	int ret;

	ret = parasite_execute_by_pid(PARASITE_CMD_DUMP_TID_ADDR, ctl, pid,
			(parasite_status_t *)&args, sizeof(args));

	*tid_addr = args.tid_addr;
	*tid = args.tid;

	return ret;
}

int parasite_dump_sigacts_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	return parasite_file_cmd("sigactions", PARASITE_CMD_DUMP_SIGACTS,
				 CR_FD_SIGACT, ctl, cr_fdset);
}

int parasite_dump_itimers_seized(struct parasite_ctl *ctl, struct cr_fdset *cr_fdset)
{
	return parasite_file_cmd("timers", PARASITE_CMD_DUMP_ITIMERS,
				 CR_FD_ITIMERS, ctl, cr_fdset);
}

int parasite_dump_misc_seized(struct parasite_ctl *ctl, struct parasite_dump_misc *misc)
{
	return parasite_execute(PARASITE_CMD_DUMP_MISC, ctl,
				(parasite_status_t *)misc,
				sizeof(struct parasite_dump_misc));
}

/*
 * This routine drives parasite code (been previously injected into a victim
 * process) and tells it to dump pages into the file.
 */
int parasite_dump_pages_seized(struct parasite_ctl *ctl, struct list_head *vma_area_list,
			       struct cr_fdset *cr_fdset)
{
	struct parasite_dump_pages_args parasite_dumppages = { };
	parasite_status_t *st = &parasite_dumppages.status;
	unsigned long nrpages_dumped = 0, nrpages_skipped = 0, nrpages_total = 0;
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping pages (type: %d pid: %d)\n", CR_FD_PAGES, ctl->pid);
	pr_info("----------------------------------------\n");

	ret = parasite_prep_file(fdset_fd(cr_fdset, CR_FD_PAGES), ctl);
	if (ret < 0)
		goto out;

	ret = parasite_execute(PARASITE_CMD_DUMPPAGES_INIT, ctl, st, sizeof(*st));
	if (ret < 0) {
		pr_err("Dumping pages failed with %li at %li\n",
				parasite_dumppages.status.ret,
				parasite_dumppages.status.line);
		goto out;
	}

	list_for_each_entry(vma_area, vma_area_list, list) {

		/*
		 * The special areas are not dumped.
		 */
		if (!(vma_area->vma.status & VMA_AREA_REGULAR))
			continue;

		/* No dumps for file-shared mappings */
		if (vma_area->vma.status & VMA_FILE_SHARED)
			continue;

		/* No dumps for SYSV IPC mappings */
		if (vma_area->vma.status & VMA_AREA_SYSVIPC)
			continue;

		if (vma_area_is(vma_area, VMA_ANON_SHARED))
			continue;

		parasite_dumppages.vma_entry = vma_area->vma;

		if (!vma_area_is(vma_area, VMA_ANON_PRIVATE) &&
		    !vma_area_is(vma_area, VMA_FILE_PRIVATE)) {
			pr_warn("Unexpected VMA area found\n");
			continue;
		}

		ret = parasite_execute(PARASITE_CMD_DUMPPAGES, ctl,
				       (parasite_status_t *) &parasite_dumppages,
				       sizeof(parasite_dumppages));
		if (ret) {
			pr_err("Dumping pages failed with %li at %li\n",
				 parasite_dumppages.status.ret,
				 parasite_dumppages.status.line);

			goto out;
		}

		pr_info("vma %lx-%lx  dumped: %lu pages %lu skipped %lu total\n",
				vma_area->vma.start, vma_area->vma.end,
				parasite_dumppages.nrpages_dumped,
				parasite_dumppages.nrpages_skipped,
				parasite_dumppages.nrpages_total);

		nrpages_dumped += parasite_dumppages.nrpages_dumped;
		nrpages_skipped += parasite_dumppages.nrpages_skipped;
		nrpages_total += parasite_dumppages.nrpages_total;
	}

	parasite_execute(PARASITE_CMD_DUMPPAGES_FINI, ctl, NULL, 0);

	pr_info("\n");
	pr_info("Summary: %lu dumped %lu skipped %lu total\n",
			nrpages_dumped, nrpages_skipped, nrpages_total);
	ret = 0;

out:
	fchmod(fdset_fd(cr_fdset, CR_FD_PAGES), CR_FD_PERM);
	pr_info("----------------------------------------\n");

	return ret;
}

int parasite_drain_fds_seized(struct parasite_ctl *ctl, int *fds, int *lfds, int nr_fds, char *flags)
{
	struct parasite_drain_fd *args;
	parasite_status_t *st;
	int ret = -1;
	int sock;

	args = xmalloc(sizeof(*args));
	if (!args)
		return -ENOMEM;
	st = &args->status;

	args->sun_len = gen_parasite_saddr(&args->saddr, (int)-2u);
	args->nr_fds = nr_fds;

	sock = socket(PF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0) {
		pr_perror("Can't create socket");
		ret = sock;
		goto out;
	}

	ret = bind(sock, (struct sockaddr *)&args->saddr, args->sun_len);
	if (ret < 0) {
		pr_perror("Can't bind socket");
		goto err;
	}

	memcpy(&args->fds, fds, sizeof(int) * nr_fds);

	ret = parasite_execute(PARASITE_CMD_DRAIN_FDS, ctl, st, sizeof(*args));
	if (ret) {
		pr_err("Parasite failed to drain descriptors\n");
		goto err;
	}

	ret = recv_fds(sock, lfds, nr_fds, flags);
	if (ret) {
		pr_err("Can't retrieve FDs from socket\n");
		goto err;
	}

err:
	close(sock);
out:
	xfree(args);
	return ret;
}

int parasite_cure_seized(struct parasite_ctl *ctl)
{
	int ret = 0;

	if (ctl->parasite_ip) {
		ctl->signals_blocked = 0;
		parasite_execute(PARASITE_CMD_FINI, ctl, NULL, 0);
	}

	if (ctl->remote_map) {
		if (munmap_seized(ctl, (void *)ctl->remote_map, ctl->map_length)) {
			pr_err("munmap_seized failed (pid: %d)\n", ctl->pid);
			ret = -1;
		}
	}

	if (ctl->local_map) {
		if (munmap(ctl->local_map, parasite_size)) {
			pr_err("munmap failed (pid: %d)\n", ctl->pid);
			ret = -1;
		}
	}

	if (ptrace_poke_area(ctl->pid, (void *)ctl->code_orig,
			     (void *)ctl->syscall_ip, sizeof(ctl->code_orig))) {
		pr_err("Can't restore syscall blob (pid: %d)\n", ctl->pid);
		ret = -1;
	}

	if (ptrace(PTRACE_SETREGS, ctl->pid, NULL, &ctl->regs_orig)) {
		pr_err("Can't restore registers (pid: %d)\n", ctl->pid);
		ret = -1;
	}

	free(ctl);
	return ret;
}

struct parasite_ctl *parasite_infect_seized(pid_t pid, struct list_head *vma_area_list)
{
	struct parasite_ctl *ctl = NULL;
	struct vma_area *vma_area;
	int ret, fd;

	/*
	 * Control block early setup.
	 */
	ctl = xzalloc(sizeof(*ctl));
	if (!ctl) {
		pr_err("Parasite control block allocation failed (pid: %d)\n", pid);
		goto err;
	}

	if (ptrace(PTRACE_GETREGS, pid, NULL, &ctl->regs_orig)) {
		pr_err("Can't obtain registers (pid: %d)\n", pid);
		goto err;
	}

	vma_area = get_vma_by_ip(vma_area_list, ctl->regs_orig.ip);
	if (!vma_area) {
		pr_err("No suitable VMA found to run parasite "
		       "bootstrap code (pid: %d)\n", pid);
		goto err;
	}

	ctl->pid	= pid;
	ctl->syscall_ip	= vma_area->vma.start;

	/*
	 * Inject syscall instruction and remember original code,
	 * we will need it to restore original program content.
	 */
	BUILD_BUG_ON(sizeof(code_syscall) != sizeof(ctl->code_orig));
	BUILD_BUG_ON(!is_log2(sizeof(code_syscall)));

	memcpy(ctl->code_orig, code_syscall, sizeof(ctl->code_orig));
	if (ptrace_swap_area(ctl->pid, (void *)ctl->syscall_ip,
			     (void *)ctl->code_orig, sizeof(ctl->code_orig))) {
		pr_err("Can't inject syscall blob (pid: %d)\n", pid);
		goto err;
	}

	/*
	 * Inject a parasite engine. Ie allocate memory inside alien
	 * space and copy engine code there. Then re-map the engine
	 * locally, so we will get an easy way to access engine memory
	 * without using ptrace at all.
	 */
	ctl->remote_map = mmap_seized(ctl, NULL, (size_t)parasite_size,
				      PROT_READ | PROT_WRITE | PROT_EXEC,
				      MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (!ctl->remote_map) {
		pr_err("Can't allocate memory for parasite blob (pid: %d)\n", pid);
		goto err_restore;
	}

	ctl->map_length = round_up(parasite_size, PAGE_SIZE);

	fd = open_proc_rw(pid, "map_files/%p-%p",
		 ctl->remote_map, ctl->remote_map + ctl->map_length);
	if (fd < 0)
		goto err_restore;

	ctl->local_map = mmap(NULL, parasite_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_FILE, fd, 0);
	close(fd);

	if (ctl->local_map == MAP_FAILED) {
		ctl->local_map = NULL;
		pr_perror("Can't map remote parasite map");
		goto err_restore;
	}

	pr_info("Putting parasite blob into %p->%p\n", ctl->local_map, ctl->remote_map);
	memcpy(ctl->local_map, parasite_blob, sizeof(parasite_blob));

	/* Setup the rest of a control block */
	ctl->parasite_ip	= PARASITE_HEAD_ADDR((unsigned long)ctl->remote_map);
	ctl->addr_cmd		= (void *)PARASITE_CMD_ADDR((unsigned long)ctl->local_map);
	ctl->addr_args		= (void *)PARASITE_ARGS_ADDR((unsigned long)ctl->local_map);

	ret = parasite_init(ctl, pid);
	if (ret) {
		pr_err("%d: Can't create a transport socket\n", pid);
		goto err_restore;
	}

	ctl->signals_blocked = 1;

	ret = parasite_set_logfd(ctl, pid);
	if (ret) {
		pr_err("%d: Can't set a logging descriptor\n", pid);
		goto err_restore;
	}

	return ctl;

err_restore:
	parasite_cure_seized(ctl);
	return NULL;

err:
	xfree(ctl);
	return NULL;
}

#else /* CONFIG_X86_64 */
# error x86-32 is not yet implemented
#endif /* CONFIG_X86_64 */
