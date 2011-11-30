#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <getopt.h>
#include <string.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/sendfile.h>

#include "types.h"
#include "list.h"

#include "compiler.h"
#include "crtools.h"
#include "util.h"

static struct cr_options opts;
struct page_entry zero_page_entry;

/*
 * The cr fd set is the set of files where the information
 * about dumped processes is stored. Each file carries some
 * small portion of info about the whole picture, see below
 * for more details.
 */

struct cr_fd_desc_tmpl fdset_template[CR_FD_MAX] = {

	 /* info about file descriptiors */
	[CR_FD_FDINFO] = {
		.fmt	= FMT_FNAME_FDINFO,
		.magic	= FDINFO_MAGIC,
	},

	/* private memory pages data */
	[CR_FD_PAGES] = {
		.fmt	= FMT_FNAME_PAGES,
		.magic	= PAGES_MAGIC,
	},

	/* shared memory pages data */
	[CR_FD_PAGES_SHMEM] = {
		.fmt	= FMT_FNAME_PAGES_SHMEM,
		.magic	= PAGES_MAGIC,
	},

	/* core data, such as regs and vmas and such */
	[CR_FD_CORE] = {
		.fmt	= FMT_FNAME_CORE,
		.magic	= CORE_MAGIC,
	},

	/* info about pipes - fds, pipe id and pipe data */
	[CR_FD_PIPES] = {
		.fmt	= FMT_FNAME_PIPES,
		.magic	= PIPES_MAGIC,
	},

	 /* info about process linkage */
	[CR_FD_PSTREE] = {
		.fmt	= FMT_FNAME_PSTREE,
		.magic	= PSTREE_MAGIC,
	},

	/* info about which memory areas are shared */
	[CR_FD_SHMEM] = {
		.fmt	= FMT_FNAME_SHMEM,
		.magic	= SHMEM_MAGIC,
	},

	/* info about which memory areas are shared */
	[CR_FD_SIGACT] = {
		.fmt	= FMT_FNAME_SIGACTS,
		.magic	= SIGACT_MAGIC,
	},
};

struct cr_fdset *alloc_cr_fdset(pid_t pid)
{
	struct cr_fdset *cr_fdset;
	unsigned int i;

	cr_fdset = xzalloc(sizeof(*cr_fdset));
	if (!cr_fdset)
		goto err;

	for (i = 0; i < CR_FD_MAX; i++) {
		cr_fdset->desc[i].tmpl = &fdset_template[i];
		snprintf(cr_fdset->desc[i].name,
			 sizeof(cr_fdset->desc[i].name),
			 cr_fdset->desc[i].tmpl->fmt,
			 pid);
		cr_fdset->desc[i].fd = -1;
	}

err:
	return cr_fdset;
}

int prep_cr_fdset_for_dump(struct cr_fdset *cr_fdset,
			    unsigned long use_mask)
{
	unsigned int i;
	u32 magic;
	int ret = -1;

	if (!cr_fdset)
		goto err;

	cr_fdset->use_mask = use_mask;

	for (i = 0; i < CR_FD_MAX; i++) {
		if (!(use_mask & CR_FD_DESC_USE(i)))
			continue;

		ret = unlink(cr_fdset->desc[i].name);
		if (ret && errno != ENOENT) {
			pr_perror("Unable to unlink %s (%s)\n",
				 cr_fdset->desc[i].name,
				 strerror(errno));
			goto err;
		} else
			ret = -1;
		cr_fdset->desc[i].fd = open(cr_fdset->desc[i].name,
					    O_RDWR | O_CREAT | O_EXCL,
					    CR_FD_PERM);
		if (cr_fdset->desc[i].fd < 0) {
			pr_perror("Unable to open %s (%s)\n",
				 cr_fdset->desc[i].name,
				 strerror(errno));
			goto err;
		}

		pr_debug("Opened %s with %d\n",
			 cr_fdset->desc[i].name,
			 cr_fdset->desc[i].fd);

		magic = cr_fdset->desc[i].tmpl->magic;
		write_ptr_safe(cr_fdset->desc[i].fd, &magic, err);
	}
	ret = 0;
err:
	return ret;
}

int prep_cr_fdset_for_restore(struct cr_fdset *cr_fdset,
			       unsigned long use_mask)
{
	unsigned int i;
	int ret = -1;
	u32 magic;

	if (!cr_fdset)
		goto err;

	cr_fdset->use_mask = use_mask;

	for (i = 0; i < CR_FD_MAX; i++) {
		if (!(use_mask & CR_FD_DESC_USE(i)))
			continue;

		cr_fdset->desc[i].fd = open(cr_fdset->desc[i].name,
					    O_RDWR, CR_FD_PERM);
		if (cr_fdset->desc[i].fd < 0) {
			pr_perror("Unable to open %s (%s)\n",
				 cr_fdset->desc[i].name,
				 strerror(errno));
			goto err;
		}

		pr_debug("Opened %s with %d\n",
			 cr_fdset->desc[i].name,
			 cr_fdset->desc[i].fd);

		read_ptr_safe(cr_fdset->desc[i].fd, &magic, err);
		if (magic != cr_fdset->desc[i].tmpl->magic) {
			pr_err("Magic doesn't match for %s\n",
			       cr_fdset->desc[i].name);
			goto err;
		}

	}
	ret = 0;
err:
	return ret;
}

void close_cr_fdset(struct cr_fdset *cr_fdset)
{
	unsigned int i;

	if (!cr_fdset)
		return;

	for (i = 0; i < CR_FD_MAX; i++) {
		if (!(cr_fdset->use_mask & CR_FD_DESC_USE(i)))
			continue;

		if (cr_fdset->desc[i].fd >= 0) {
			pr_debug("Closed %s with %d\n",
				cr_fdset->desc[i].name,
				cr_fdset->desc[i].fd);
			close(cr_fdset->desc[i].fd);
			cr_fdset->desc[i].fd = -1;
		}
	}
}

void free_cr_fdset(struct cr_fdset **cr_fdset)
{
	if (cr_fdset && *cr_fdset) {
		free(*cr_fdset);
		*cr_fdset = NULL;
	}
}

int main(int argc, char *argv[])
{
	pid_t pid;
	int ret = -1;
	int opt, idx;
	int action = -1;

	static const char short_opts[] = "drskp:t:h";
	static const struct option long_opts[] = {
		{ "dump",	no_argument, NULL, 'd' },
		{ "restore",	no_argument, NULL, 'r' },
		{ "show",	no_argument, NULL, 's' },
		{ NULL,		no_argument, NULL, 0 }
	};

	BUILD_BUG_ON(PAGE_SIZE != PAGE_IMAGE_SIZE);

	if (argc < 3)
		goto usage;

	memzero_p(&zero_page_entry);

	/* Default options */
	opts.final_state = CR_TASK_LEAVE_RUNNING;

	for (opt = getopt_long(argc, argv, short_opts, long_opts, &idx); opt != -1;
	     opt = getopt_long(argc, argv, short_opts, long_opts, &idx)) {
		switch (opt) {
		case 'p':
			pid = atoi(optarg);
			opts.leader_only = true;
			break;
		case 't':
			pid = atoi(optarg);
			opts.leader_only = false;
			break;
		case 'd':
			action = opt;
			break;
		case 'r':
			action = opt;
			break;
		case 's':
			action = opt;
			break;
		case 'k':
			opts.final_state = CR_TASK_KILL;
			break;
		case 'h':
		default:
			goto usage;
		}
	}

	switch (action) {
	case 'd':
		ret = cr_dump_tasks(pid, &opts);
		break;
	case 'r':
		ret = cr_restore_tasks(pid, &opts);
		break;
	case 's':
		ret = cr_show(pid, &opts);
		break;
	default:
		goto usage;
		break;
	}

	return ret;

usage:
	printk("\nUsage:\n");
	printk("\tcrtools ([--dump|-d]|[--show|-s]|[--restore|-r]) [-k] (-p|-t) pid\n\n");
	return -1;
}
