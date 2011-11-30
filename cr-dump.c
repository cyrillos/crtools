#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include <sys/sendfile.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "syscall.h"
#include "util.h"

#include "image.h"

#include "parasite.h"
#include "parasite-syscall.h"
#include "parasite-blob.h"

#include <stdarg.h>

#ifndef CONFIG_X86_64
# error No x86-32 support yet
#endif

static char big_buffer[PATH_MAX];
static char loc_buf[PAGE_SIZE];

static void free_pstree(struct list_head *pstree_list)
{
	struct pstree_item *item, *p;

	list_for_each_entry_safe(item, p, pstree_list, list) {
		xfree(item->children);
		xfree(item->threads);
		xfree(item);
	}

	INIT_LIST_HEAD(pstree_list);
}

void free_mappings(struct list_head *vma_area_list)
{
	struct vma_area *vma_area, *p;

	list_for_each_entry_safe(vma_area, p, vma_area_list, list) {
		if (vma_area->vm_file_fd > 0)
			close(vma_area->vm_file_fd);
		free(vma_area);
	}

	INIT_LIST_HEAD(vma_area_list);
}

static int collect_mappings(pid_t pid, struct list_head *vma_area_list)
{
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Collecting mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	ret = parse_maps(pid, vma_area_list, true);
	if (ret)
		goto err;

	pr_info_vma_list(vma_area_list);

	pr_info("----------------------------------------\n");

err:
	return ret;

err_bogus_mapping:
	pr_err("Bogus mapping %lx-%lx\n",
	       vma_area->vma.start,
	       vma_area->vma.end);
	goto err;
}

static int dump_one_reg_file(int type, unsigned long fd_name, int lfd,
			     bool do_close, unsigned long pos, unsigned int flags,
			     struct cr_fdset *cr_fdset)
{
	struct fdinfo_entry e;
	char fd_str[128];
	int len;
	int ret = -1;

	snprintf(fd_str, sizeof(fd_str), "/proc/self/fd/%d", lfd);
	len = readlink(fd_str, big_buffer, sizeof(big_buffer) - 1);
	if (len < 0) {
		pr_perror("Can't readlink %s\n", fd_str);
		goto err;
	}

	big_buffer[len] = '\0';
	pr_info("Dumping path for %lx fd via self %d [%s]\n",
		fd_name, lfd, big_buffer);

	if (do_close)
		close(lfd);

	e.type	= type;
	e.len	= len;
	e.flags = flags;
	e.pos	= pos;
	e.addr	= fd_name;

	pr_info("fdinfo: type: %2x len: %2x flags: %4x pos: %8x addr: %16lx\n",
		type, len, flags, pos, fd_name);

	write_ptr_safe(cr_fdset->desc[CR_FD_FDINFO].fd, &e, err);
	write_safe(cr_fdset->desc[CR_FD_FDINFO].fd, big_buffer, e.len, err);

	ret = 0;
err:
	return ret;
}

static int dump_pipe_and_data(int lfd, struct pipe_entry *e,
			      struct cr_fdset *cr_fdset)
{
	int fd_pipes;
	int steal_pipe[2];
	int pipe_size;
	int has_bytes;
	int ret = -1;

	fd_pipes = cr_fdset->desc[CR_FD_PIPES].fd;

	pr_info("Dumping data from pipe %x\n", e->pipeid);
	if (pipe(steal_pipe) < 0) {
		pr_perror("Can't create pipe for stealing data\n");
		goto err;
	}

	pipe_size = fcntl(lfd, F_GETPIPE_SZ);
	if (pipe_size < 0) {
		pr_err("Can't obtain piped data size\n");
		goto err;
	}

	has_bytes = tee(lfd, steal_pipe[1], pipe_size, SPLICE_F_NONBLOCK);
	if (has_bytes < 0) {
		if (errno != EAGAIN) {
			pr_perror("Can't pick pipe data\n");
			goto err_close;
		} else
			has_bytes = 0;
	}

	e->bytes = has_bytes;
	write_ptr_safe(fd_pipes, e, err_close);

	if (has_bytes) {
		ret = splice(steal_pipe[0], NULL, fd_pipes,
			     NULL, has_bytes, 0);
		if (ret < 0) {
			pr_perror("Can't push pipe data\n");
			goto err_close;
		}
	}

	ret = 0;

err_close:
	close(steal_pipe[0]);
	close(steal_pipe[1]);

err:
	return ret;
}

static int dump_one_pipe(int fd, int lfd, unsigned int id, unsigned int flags,
			 struct cr_fdset *cr_fdset)
{
	struct pipe_entry e;
	int ret = -1;

	pr_info("Dumping pipe %d/%x flags %x\n", fd, id, flags);

	e.fd		= fd;
	e.pipeid	= id;
	e.flags		= flags;

	if (flags & O_WRONLY) {
		e.bytes = 0;
		write_ptr_safe(cr_fdset->desc[CR_FD_PIPES].fd, &e, err);
		ret = 0;
	} else
		ret = dump_pipe_and_data(lfd, &e, cr_fdset);

err:
	if (!ret)
		pr_info("Dumped pipe: fd: %8lx pipeid: %8lx flags: %8lx bytes: %8lx\n",
			e.fd, e.pipeid, e.flags, e.bytes);
	else
		pr_err("Dumping pipe %d/%x flags %x\n", fd, id, flags);

	return ret;
}

static int dump_one_fd(char *pid_fd_dir, int dir, char *fd_name, unsigned long pos,
		       unsigned int flags, struct cr_fdset *cr_fdset)
{
	struct statfs stfs_buf;
	struct stat st_buf;
	int fd;

	fd = openat(dir, fd_name, O_RDONLY);
	if (fd < 0) {
		pr_perror("Failed to openat %s/%d %s\n", pid_fd_dir, dir, fd_name);
		return -1;
	}

	if (fstat(fd, &st_buf) < 0) {
		pr_perror("Can't get stat on %s\n", fd_name);
		return -1;
	}

	if (S_ISCHR(st_buf.st_mode) &&
		( major(st_buf.st_rdev) == TTY_MAJOR ||
		  major(st_buf.st_rdev) == UNIX98_PTY_SLAVE_MAJOR)) {
		/* skip only standard destriptors */
		if (atoi(fd_name) < 3) {
			pr_info("... Skipping tty ... %s/%s\n", pid_fd_dir, fd_name);
			return 0;
		}
		goto err;
	}

	if (S_ISREG(st_buf.st_mode))
		return dump_one_reg_file(FDINFO_FD, atol(fd_name),
					 fd, 1, pos, flags, cr_fdset);

	if (S_ISFIFO(st_buf.st_mode)) {
		if (fstatfs(fd, &stfs_buf) < 0) {
			pr_perror("Can't fstatfs on %s\n", fd_name);
			return -1;
		}

		if (stfs_buf.f_type == PIPEFS_MAGIC)
			return dump_one_pipe(atol(fd_name), fd,
					     st_buf.st_ino, flags, cr_fdset);
	}

err:
	pr_err("Can't dump file %s of that type [%x]\n", fd_name, st_buf.st_mode);
	return 1;
}

static int read_fd_params(pid_t pid, char *fd, unsigned long *pos, unsigned int *flags)
{
	FILE *file;

	file = fopen_proc("%d/fdinfo/%s", "r", pid, fd);
	if (!file) {
		pr_perror("Can't open %d's %s fdinfo\n", pid, fd);
		return -1;
	}

	fscanf(file, "pos:\t%li\nflags:\t%o\n", pos, flags);
	fclose(file);

	pr_info("%d fdinfo %s: pos: %16lx flags: %16lx\n", pid, fd, *pos, *flags);

	return 0;
}

static int dump_task_files(pid_t pid, struct cr_fdset *cr_fdset)
{
	char pid_fd_dir[64];
	struct dirent *de;
	unsigned long pos;
	unsigned int flags;
	DIR *fd_dir;

	pr_info("\n");
	pr_info("Dumping opened files (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	snprintf(pid_fd_dir, sizeof(pid_fd_dir), "/proc/%d/fd", pid);
	fd_dir = opendir(pid_fd_dir);
	if (!fd_dir) {
		pr_perror("Can't open %s\n", pid_fd_dir);
		return -1;
	}

	while ((de = readdir(fd_dir))) {
		if (de->d_name[0] == '.')
			continue;
		if (read_fd_params(pid, de->d_name, &pos, &flags))
			return -1;
		if (dump_one_fd(pid_fd_dir, dirfd(fd_dir), de->d_name, pos, flags, cr_fdset))
			return -1;
	}

	pr_info("----------------------------------------\n");

	closedir(fd_dir);
	return 0;
}

static int dump_task_mappings(pid_t pid, struct list_head *vma_area_list, struct cr_fdset *cr_fdset)
{
	struct vma_area *vma_area;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping mappings (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	list_for_each_entry(vma_area, vma_area_list, list) {

		struct vma_entry *vma = &vma_area->vma;

		if (!vma_entry_is(vma, VMA_AREA_REGULAR))
			continue;

		pr_info_vma(vma_area);

		if (vma->flags & (MAP_SHARED | MAP_PRIVATE)) {

			if (vma_entry_is(vma, VMA_ANON_SHARED)) {
				struct shmem_entry e;

				e.start	= vma->start;
				e.end	= vma->end;
				e.shmid	= vma_area->shmid;

				pr_info("shmem: s: %16lx e: %16lx shmid: %16lx\n",
					e.start, e.end, e.shmid);

				write_ptr_safe(cr_fdset->desc[CR_FD_SHMEM].fd, &e, err);
			} else if (vma_entry_is(vma, VMA_FILE_PRIVATE) ||
				   vma_entry_is(vma, VMA_FILE_SHARED)) {

				unsigned int flags;

				if (vma->prot & PROT_WRITE &&
				    vma_entry_is(vma, VMA_FILE_SHARED))
					flags = O_RDWR;
				else
					flags = O_RDONLY;

				ret = dump_one_reg_file(FDINFO_MAP,
							vma->start,
							vma_area->vm_file_fd,
							0, 0, flags,
							cr_fdset);
				if (ret)
					goto err;
			}
		} else {
			pr_panic("Unknown VMA (pid: %d)\n", pid);
			goto err;
		}
	}

	ret = 0;

	pr_info("----------------------------------------\n");

err:
	return ret;
}

#define assign_reg(dst, src, e)		dst.e = (__typeof__(dst.e))src.e
#define assign_array(dst, src, e)	memcpy(&dst.e, &src.e, sizeof(dst.e))

static int get_task_stat(pid_t pid, u8 *comm, u32 *flags,
			 u64 *start_code, u64 *end_code,
			 u64 *start_data, u64 *end_data,
			 u64 *start_stack, u64 *start_brk,
			 u64 *task_sigset)
{
	FILE *file = NULL;
	char *tok1, *tok2;
	int i, ret = -1;

	/*
	 * NOTE: Be careful, /proc/$pid/stat has a parasite
	 * '0' symbol at argument 20 in format string.
	 */

	file = fopen_proc("%d/stat", "r", pid);
	if (!file) {
		pr_perror("Can't open %d stat", pid);
		goto err;
	}

	if (!fgets(loc_buf, sizeof(loc_buf), file)) {
		perror("Can't read task stat");
		goto err;
	}

	tok1 = strtok(loc_buf, "(");
	tok2 = strtok(NULL, ")");
	if ((long)tok1 & (long)tok2) {
		strncpy((char *)comm, tok2, TASK_COMM_LEN);
		ret = 0;
	} else {
		printf("Unable to parse task stat\n");
		ret = -1;
	}

	if (!ret) {
		ret = -1;
		for (i = 0; i < 7; i++) {
			tok1 = strtok(NULL, " \n\t");
			if (!tok1)
				goto err_corrupted;
		}
		*flags = atoi(tok1);
		ret = 0;
	}

	if (!ret) {
		ret = -1;
		for (i = 0; i < 16; i++) {
			tok1 = strtok(NULL, " \n\t");
			if (!tok1)
				goto err_corrupted;
		}

		tok1 = strtok(NULL, " \n\t");
		if (!tok1)
			goto err_corrupted;
		*start_code = atol(tok1);

		tok1 = strtok(NULL, " \n\t");
		if (!tok1)
			goto err_corrupted;
		*end_code = atol(tok1);
		ret = 0;

		tok1 = strtok(NULL, " \n\t");
		if (!tok1)
			goto err_corrupted;
		*start_stack = atol(tok1);
		ret = 0;
	}

	if (!ret) {
		ret = -1;
		for (i = 0; i < 16; i++) {
			tok1 = strtok(NULL, " \n\t");
			if (!tok1)
				goto err_corrupted;
		}

		tok1 = strtok(NULL, " \n\t");
		if (!tok1)
			goto err_corrupted;
		*start_data = atol(tok1);

		tok1 = strtok(NULL, " \n\t");
		if (!tok1)
			goto err_corrupted;
		*end_data = atol(tok1);

		tok1 = strtok(NULL, " \n\t");
		if (!tok1)
			goto err_corrupted;
		*start_brk = atol(tok1);
		ret = 0;
	}

	/*
	 * Now signals.
	 */
	fclose(file);
	file = fopen_proc("%d/status", "r", pid);
	if (!file) {
		pr_perror("Can't open %d status", pid);
		goto err;
	}

	while (fgets(loc_buf, sizeof(loc_buf), file)) {
		if (!strncmp(loc_buf, "SigBlk:", 7)) {
			char *end;
			*task_sigset = strtol(&loc_buf[8], &end, 16);
			break;
		}
	}

err:
	if (file)
		fclose(file);
	return ret;

err_corrupted:
	pr_err("/proc/%d/stat is corrupted\n", pid);
	goto err;
}

static int get_task_personality(pid_t pid, u32 *personality)
{
	FILE *file = NULL;
	int ret = -1;

	file = fopen_proc("%d/personality", "r", pid);
	if (!file) {
		pr_perror("Can't open %d personality", pid);
		goto err;
	}

	if (!fgets(loc_buf, sizeof(loc_buf), file)) {
		perror("Can't read task personality");
		goto err;
	}

	*personality = atoi(loc_buf);
	ret = 0;

err:
	if (file)
		fclose(file);
	return ret;
}

static int get_task_regs(pid_t pid, struct core_entry *core)
{
	user_fpregs_struct_t fpregs	= {-1};
	user_regs_struct_t regs		= {-1};
	int ret = -1;

	jerr(ptrace(PTRACE_GETREGS,	pid, NULL, &regs), err);
	jerr(ptrace(PTRACE_GETFPREGS,	pid, NULL, &fpregs), err);

	assign_reg(core->u.arch.gpregs, regs,		r15);
	assign_reg(core->u.arch.gpregs, regs,		r14);
	assign_reg(core->u.arch.gpregs, regs,		r13);
	assign_reg(core->u.arch.gpregs, regs,		r12);
	assign_reg(core->u.arch.gpregs, regs,		bp);
	assign_reg(core->u.arch.gpregs, regs,		bx);
	assign_reg(core->u.arch.gpregs, regs,		r11);
	assign_reg(core->u.arch.gpregs, regs,		r10);
	assign_reg(core->u.arch.gpregs, regs,		r9);
	assign_reg(core->u.arch.gpregs, regs,		r8);
	assign_reg(core->u.arch.gpregs, regs,		ax);
	assign_reg(core->u.arch.gpregs, regs,		cx);
	assign_reg(core->u.arch.gpregs, regs,		dx);
	assign_reg(core->u.arch.gpregs, regs,		si);
	assign_reg(core->u.arch.gpregs, regs,		di);
	assign_reg(core->u.arch.gpregs, regs,		orig_ax);
	assign_reg(core->u.arch.gpregs, regs,		ip);
	assign_reg(core->u.arch.gpregs, regs,		cs);
	assign_reg(core->u.arch.gpregs, regs,		flags);
	assign_reg(core->u.arch.gpregs, regs,		sp);
	assign_reg(core->u.arch.gpregs, regs,		ss);
	assign_reg(core->u.arch.gpregs, regs,		fs_base);
	assign_reg(core->u.arch.gpregs, regs,		gs_base);
	assign_reg(core->u.arch.gpregs, regs,		ds);
	assign_reg(core->u.arch.gpregs, regs,		es);
	assign_reg(core->u.arch.gpregs, regs,		fs);
	assign_reg(core->u.arch.gpregs, regs,		gs);

	assign_reg(core->u.arch.fpregs, fpregs,		cwd);
	assign_reg(core->u.arch.fpregs, fpregs,		swd);
	assign_reg(core->u.arch.fpregs, fpregs,		twd);
	assign_reg(core->u.arch.fpregs, fpregs,		fop);
	assign_reg(core->u.arch.fpregs, fpregs,		rip);
	assign_reg(core->u.arch.fpregs, fpregs,		rdp);
	assign_reg(core->u.arch.fpregs, fpregs,		mxcsr);
	assign_reg(core->u.arch.fpregs, fpregs,		mxcsr_mask);

	assign_array(core->u.arch.fpregs, fpregs,	st_space);
	assign_array(core->u.arch.fpregs, fpregs,	xmm_space);
	assign_array(core->u.arch.fpregs, fpregs,	padding);

	ret = 0;

err:
	return ret;
}

static int dump_task_core_seized(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct core_entry *core		= xzalloc(sizeof(*core));
	int fd_core			= cr_fdset->desc[CR_FD_CORE].fd;
	int ret				= -1;
	unsigned long brk;

	pr_info("\n");
	pr_info("Dumping core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	if (!core)
		goto err;

	lseek(fd_core, MAGIC_OFFSET, SEEK_SET);

	pr_info("Dumping GP/FPU registers ... ");
	ret = get_task_regs(pid, core);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Obtainting personality ... ");
	ret = get_task_personality(pid, &core->task_personality);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Obtainting task stat ... ");
	ret = get_task_stat(pid, core->task_comm,
			    &core->task_flags,
			    &core->mm_start_code,
			    &core->mm_end_code,
			    &core->mm_start_data,
			    &core->mm_end_data,
			    &core->mm_start_stack,
			    &core->mm_start_brk,
			    &core->task_sigset);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	pr_info("Obtainting task brk ... ");
	brk = brk_seized(pid, 0);
	if ((long)brk < 0)
		goto err_free;
	core->mm_brk = brk;
	pr_info("OK\n");

	pr_info("Dumping header ... ");
	core->header.version	= HEADER_VERSION;
	core->header.arch	= HEADER_ARCH_X86_64;
	core->header.flags	= 0;

	write_ptr_safe(fd_core, core, err_free);

	pr_info("OK\n");
	ret = 0;

err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int parse_threads(pid_t pid, int nr_threads, u32 **threads)
{
	struct dirent *de;
	DIR *dir;

	u32 *t = NULL;
	int ret = -1, i = 0;

	ret = -1;

	dir = opendir_proc("%d/task", pid);
	if (!dir) {
		pr_perror("Can't open %d/task", pid);
		goto err;
	}

	t = xmalloc(nr_threads);
	if (!t)
		goto err;

	while ((de = readdir(dir))) {
		/* We expect numbers only here */
		if (de->d_name[0] == '.')
			continue;

		if (i >= nr_threads) {
			pr_err("Threads inconsistency, kernel bug?\n");
			goto err;
		}

		t[i++] = atoi(de->d_name);
	}

	closedir(dir);

	*threads = t, t = NULL;
	ret = 0;

err:
	xfree(t);
	return ret;
}

static struct pstree_item *find_pstree_entry(pid_t pid)
{
	struct pstree_item *item = NULL;
	u32 *children = NULL;
	u32 *threads = NULL;
	u32 nr_allocated = 0;
	u32 nr_children = 0;
	u32 nr_threads = 0;
	char *children_str = NULL;
	FILE *file;
	char *tok;

	pr_debug("pid: %d\n", pid);

	file = fopen_proc("%d/status", "r", pid);
	if (!file) {
		pr_perror("Can't open %d status", pid);
		goto err;
	}

	while ((fgets(loc_buf, sizeof(loc_buf), file))) {
		if (!strncmp(loc_buf, "Children:", 9)) {
			children_str = xstrdup(&loc_buf[10]);
			if (!children_str)
				goto err;
			if (nr_threads)
				break;
		} else if (!strncmp(loc_buf, "Threads:", 8)) {
			nr_threads = atoi(&loc_buf[9]);
			if (children_str)
				break;
		} else
			continue;
	}

	fclose(file), file = NULL;

	if (nr_threads < 1) {
		pr_err("Unable to find out how many threads are used\n");
		goto err;
	}

	if (!children_str) {
		pr_err("Children marker is not found\n");
		goto err;
	}

	item = xzalloc(sizeof(*item));
	if (!item)
		goto err;

	if (parse_threads(pid, nr_threads, &threads))
		goto err_free;

	tok = strtok(children_str, " \n");
	while (tok) {
		u32 child_pid = atoi(tok);

		pr_debug("child_pid: %d\n", child_pid);

		if (nr_allocated <= nr_children) {
			nr_allocated += 64;
			if (xrealloc_safe((void **)&children, nr_allocated))
				goto err_free;
		}

		children[nr_children++] = child_pid;
		tok = strtok(NULL, " \n");
	}

	item->pid		= pid;
	item->nr_children	= nr_children;
	item->nr_threads	= nr_threads;
	item->children		= children;
	item->threads		= threads;

err:
	xfree(children_str);
	return item;

err_free:
	xfree(threads);
	xfree(children);
	xfree(item);
	item = NULL;
	goto err;
}

static int collect_pstree(pid_t pid, struct list_head *pstree_list)
{
	struct pstree_item *item;
	unsigned long i;
	int ret = -1;

	item = find_pstree_entry(pid);
	if (!item)
		goto err;

	list_add_tail(&item->list, pstree_list);

	for (i = 0; i < item->nr_children; i++) {
		ret = collect_pstree(item->children[i], pstree_list);
		if (ret)
			goto err;
	}
	ret = 0;

err:
	return ret;
}

static int dump_pstree(pid_t pid, struct list_head *pstree_list, struct cr_fdset *cr_fdset)
{
	struct pstree_item *item;
	struct pstree_entry e;
	unsigned long i;
	int ret = -1;

	pr_info("\n");
	pr_info("Dumping pstree (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	list_for_each_entry(item, pstree_list, list) {

		pr_info("Process: %d (%d children)\n",
			item->pid, item->nr_children);

		e.pid		= item->pid;
		e.nr_children	= item->nr_children;
		e.nr_threads	= item->nr_threads;

		write_ptr_safe(cr_fdset->desc[CR_FD_PSTREE].fd, &e, err);

		pr_info("Children:");
		for (i = 0; i < item->nr_children; i++) {
			pr_info(" %d", item->children[i]);
			write_ptr_safe(cr_fdset->desc[CR_FD_PSTREE].fd,
				       &item->children[i], err);
		}
		pr_info("\n");

		pr_info("Threads:\n");
		for (i = 0; i < item->nr_threads; i++) {
			pr_info(" %d", item->threads[i]);
			write_ptr_safe(cr_fdset->desc[CR_FD_PSTREE].fd,
				       &item->threads[i], err);
		}
		pr_info("\n");
	}
	ret = 0;

err:
	pr_info("----------------------------------------\n");
	return ret;
}

static struct vma_area *find_vma_by_addr(struct list_head *vma_area_list, unsigned long addr)
{
	struct vma_area *vma_area;

	list_for_each_entry(vma_area, vma_area_list, list) {
		if (in_vma_area(vma_area, addr))
			return vma_area;
	}

	return NULL;
}

static int append_thread_core(struct cr_fdset *dst, struct cr_fdset *src)
{
	const int size = sizeof(struct core_entry);
	int fd_core_dst = dst->desc[CR_FD_CORE].fd;
	int fd_code_src = src->desc[CR_FD_CORE].fd;
	int ret = -1;

	lseek(fd_core_dst, 0, SEEK_END);
	lseek(fd_code_src, MAGIC_OFFSET, SEEK_SET);

	if (sendfile(fd_core_dst, fd_code_src, NULL, size) != size) {
		pr_perror("Appending thread code failed\n");
		goto err;
	}

	ret = 0;
err:
	return ret;
}

/* kernel expects a special format in core file */
static int finalize_core(pid_t pid, struct list_head *vma_area_list, struct cr_fdset *cr_fdset)
{
	int fd_pages, fd_pages_shmem, fd_core;
	unsigned long num, num_anon;
	struct vma_area *vma_area;
	struct vma_entry ve;
	int ret = -1;
	u64 va;

	pr_info("\n");
	pr_info("Finalizing core (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	fd_core		= cr_fdset->desc[CR_FD_CORE].fd;
	fd_pages	= cr_fdset->desc[CR_FD_PAGES].fd;
	fd_pages_shmem	= cr_fdset->desc[CR_FD_PAGES_SHMEM].fd;

	pr_debug("dsc: fd_core %d fd_pages %d fd_pages_shmem %d\n",
		 fd_core, fd_pages, fd_pages_shmem);

	lseek(fd_core,		GET_FILE_OFF_AFTER(struct core_entry), SEEK_SET);
	lseek(fd_pages,		MAGIC_OFFSET, SEEK_SET);
	lseek(fd_pages_shmem,	MAGIC_OFFSET, SEEK_SET);

	num = 0;
	pr_info("Appending VMAs ... ");

	/* All VMAs first */

	list_for_each_entry(vma_area, vma_area_list, list) {
		ret = write(fd_core, &vma_area->vma, sizeof(vma_area->vma));
		if (ret != sizeof(vma_area->vma)) {
			pr_perror("\nUnable to write vma entry (%li written)\n", num);
			goto err;
		}
		num++;
	}

	/* Ending marker */
	memzero_p(&ve);
	write_ptr_safe(fd_core, &ve, err);

	pr_info("OK (%li written)\n", num);

	num = 0;
	num_anon = 0;

	pr_info("Appending pages ... ");
	while (1) {
		ret = read(fd_pages, &va, sizeof(va));
		if (!ret)
			break;
		if (ret != sizeof(va)) {
			pr_perror("\nUnable to read VA of page (%li written)\n", num);
			goto err;
		}

		/* Ending marker */
		if (va == 0) {
			write_ptr_safe(fd_core,		&zero_page_entry, err);
			write_ptr_safe(fd_pages_shmem,	&zero_page_entry, err);
			break;
		}

		vma_area = find_vma_by_addr(vma_area_list, (unsigned long)va);
		if (!vma_area) {
			pr_panic("\nA page with address %lx is unknown\n", va);
			goto err;
		}

		/*
		 * Just in case if someone broke parasite page
		 * dumper code.
		 */
		if (!vma_area_is(vma_area, VMA_AREA_REGULAR)) {
			pr_panic("\nA page with address %lx has a wrong status\n", va);
			goto err;
		}

		if (vma_area_is(vma_area, VMA_ANON_PRIVATE) ||
		    vma_area_is(vma_area, VMA_FILE_PRIVATE)) {
			ret  = write(fd_core, &va, sizeof(va));
			ret += sendfile(fd_core, fd_pages, NULL, PAGE_SIZE);
			if (ret != sizeof(va) + PAGE_SIZE) {
				pr_perror("\nUnable to write VMA_FILE_PRIVATE|VMA_ANON_PRIVATE "
					  "page (%li, %li written)\n",
					  num, num_anon);
				goto err;
			}
			num++;
		} else if (vma_area_is(vma_area, VMA_ANON_SHARED)) {
			ret  = write(fd_pages_shmem, &va, sizeof(va));
			ret += sendfile(fd_pages_shmem, fd_pages, NULL, PAGE_SIZE);
			if (ret != sizeof(va) + PAGE_SIZE) {
				pr_perror("\nUnable to write VMA_ANON_SHARED "
					  "page (%li, %li written)\n",
					  num, num_anon);
				goto err;
			}
			num_anon++;
		} else {
			pr_warning("Unexpected VMA area found\n");
			pr_info_vma(vma_area);
			lseek(fd_pages, PAGE_SIZE, SEEK_CUR);
		}
	}
	ret = 0;

	pr_info("OK (%li written)\n", num + num_anon);

err:
	pr_info("----------------------------------------\n");
	return ret;

err_strno:
	pr_perror("Error catched\n");
	goto err;
}

static int dump_task_thread(pid_t pid, struct cr_fdset *cr_fdset)
{
	struct core_entry *core		= xzalloc(sizeof(*core));
	int fd_core			= cr_fdset->desc[CR_FD_CORE].fd;
	int ret				= -1;

	pr_info("\n");
	pr_info("Dumping core for thread (pid: %d)\n", pid);
	pr_info("----------------------------------------\n");

	if (!core)
		goto err;

	lseek(fd_core, MAGIC_OFFSET, SEEK_SET);

	ret = seize_task(pid);
	if (ret) {
		pr_err("Failed to seize thread (pid: %d) with %d\n",
		       pid, ret);
		goto err_free;
	}

	pr_info("Dumping GP/FPU registers ... ");
	ret = get_task_regs(pid, core);
	if (ret)
		goto err_free;
	pr_info("OK\n");

	ret = unseize_task(pid);
	if (ret) {
		pr_err("Can't unsieze thread (pid: %d)\n", pid);
		goto err_free;
	}

	pr_info("Dumping header ... ");
	core->header.version	= HEADER_VERSION;
	core->header.arch	= HEADER_ARCH_X86_64;
	core->header.flags	= 0;

	write_ptr_safe(fd_core, core, err_free);

	pr_info("OK\n");
	ret = 0;

err_free:
	free(core);
err:
	pr_info("----------------------------------------\n");

	return ret;
}

static int dump_one_task(pid_t pid, struct cr_fdset *cr_fdset)
{
	LIST_HEAD(vma_area_list);
	struct parasite_ctl *parasite_ctl;
	int ret = 0;

	pr_info("========================================\n");
	pr_info("Dumping task (pid: %d)\n", pid);
	pr_info("========================================\n");

	ret = collect_mappings(pid, &vma_area_list);
	if (ret) {
		pr_err("Collect mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = seize_task(pid);
	if (ret) {
		pr_err("Failed to seize task (pid: %d) with %d\n",
		       pid, ret);
		goto err;
	}

	ret = dump_task_core_seized(pid, cr_fdset);
	if (ret) {
		pr_err("Dump core (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	parasite_ctl = parasite_infect_seized(pid, NULL, &vma_area_list);
	if (!parasite_ctl) {
		pr_err("Can't infect (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_pages_seized(parasite_ctl, &vma_area_list,
					 cr_fdset, CR_FD_PAGES);
	if (ret) {
		pr_err("Can't dump pages (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_dump_sigacts_seized(parasite_ctl, cr_fdset);
	if (ret) {
		pr_err("Can't dump sigactions (pid: %d) with parasite\n", pid);
		goto err;
	}

	ret = parasite_cure_seized(&parasite_ctl, &vma_area_list);
	if (ret) {
		pr_err("Can't cure (pid: %d) from parasite\n", pid);
		goto err;
	}

	ret = unseize_task(pid);
	if (ret) {
		pr_err("Can't unsieze (pid: %d) task\n", pid);
		goto err;
	}

	ret = dump_task_files(pid, cr_fdset);
	if (ret) {
		pr_err("Dump files (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = dump_task_mappings(pid, &vma_area_list, cr_fdset);
	if (ret) {
		pr_err("Dump mappings (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

	ret = finalize_core(pid, &vma_area_list, cr_fdset);
	if (ret) {
		pr_err("Finalizing core (pid: %d) failed with %d\n", pid, ret);
		goto err;
	}

err:
	free_mappings(&vma_area_list);
	return ret;
}

int cr_dump_tasks(pid_t pid, struct cr_options *opts)
{
	LIST_HEAD(pstree_list);
	struct cr_fdset *cr_fdset = NULL;
	struct cr_fdset *cr_fdset_thread = NULL;
	struct pstree_item *item;
	int i, ret = -1;

	pr_info("========================================\n");
	if (!opts->leader_only)
		pr_info("Dumping process group (pid: %d)\n", pid);
	else
		pr_info("Dumping process (pid: %d)\n", pid);
	pr_info("========================================\n");

	if (collect_pstree(pid, &pstree_list))
		goto err;

	/*
	 * Since ptrace-seize doesn't work on frozen tasks
	 * we stick with explicit tasks stopping via stop
	 * signal, but in future it's aimed to switch to
	 * kernel freezer.
	 */
	list_for_each_entry(item, &pstree_list, list) {
		stop_task(item->pid);
		if (opts->leader_only)
			break;
	}

	list_for_each_entry(item, &pstree_list, list) {

		cr_fdset = alloc_cr_fdset(item->pid);
		if (!cr_fdset)
			goto err;

		if (item->pid == pid) {
			if (prep_cr_fdset_for_dump(cr_fdset, CR_FD_DESC_ALL))
				goto err;
			if (dump_pstree(pid, &pstree_list, cr_fdset))
				goto err;
		} else {
			if (prep_cr_fdset_for_dump(cr_fdset, CR_FD_DESC_NOPSTREE))
				goto err;
		}

		if (dump_one_task(item->pid, cr_fdset))
			goto err;

		if (item->nr_threads > 1) {
			for (i = 0; i < item->nr_threads; i++) {


				/* Leader is already dumped */
				if (item->pid == item->threads[i])
					continue;

				cr_fdset_thread = alloc_cr_fdset(item->threads[i]);
				if (!cr_fdset_thread)
					goto err;

				if (prep_cr_fdset_for_dump(cr_fdset_thread, CR_FD_DESC_CORE))
					goto err;

				if (dump_task_thread(item->threads[i], cr_fdset_thread))
					goto err;

				if (append_thread_core(cr_fdset, cr_fdset_thread))
					goto err;

				close_cr_fdset(cr_fdset_thread);
				free_cr_fdset(&cr_fdset_thread);
			}
		}

		close_cr_fdset(cr_fdset);
		free_cr_fdset(&cr_fdset);

		if (opts->leader_only)
			break;
	}
	ret = 0;

err:
	switch (opts->final_state) {
	case CR_TASK_LEAVE_RUNNING:
		list_for_each_entry(item, &pstree_list, list) {
			continue_task(item->pid);
			if (opts->leader_only)
				break;
		}
		break;
	case CR_TASK_KILL:
		list_for_each_entry(item, &pstree_list, list) {
			kill_task(item->pid);
			if (opts->leader_only)
				break;
		}
		break;
	case CR_TASK_LEAVE_STOPPED:
	default:
		break;
	}

	free_pstree(&pstree_list);

	close_cr_fdset(cr_fdset);
	free_cr_fdset(&cr_fdset);

	close_cr_fdset(cr_fdset_thread);
	free_cr_fdset(&cr_fdset_thread);

	return ret;
}
