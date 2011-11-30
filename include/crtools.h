#ifndef CRTOOLS_H_
#define CRTOOLS_H_

#include <sys/types.h>

#include "types.h"
#include "list.h"

#include "image.h"

extern struct page_entry zero_page_entry;

#define CR_FD_PERM		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)
#define CR_FD_PERM_DUMP		(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

enum {
	CR_FD_FDINFO,
	CR_FD_PAGES,
	CR_FD_PAGES_SHMEM,
	CR_FD_CORE,
	CR_FD_PIPES,
	CR_FD_PSTREE,
	CR_FD_SHMEM,
	CR_FD_SIGACT,

	CR_FD_MAX
};

enum cr_task_final_state {
	CR_TASK_LEAVE_STOPPED,		/* leave tasks stopped after dump/restore */
	CR_TASK_LEAVE_RUNNING,		/* leave tasks running after dump/restore */
	CR_TASK_KILL,			/* kill tasks after dump */
};

struct cr_options {
	bool				leader_only;
	enum cr_task_final_state	final_state;
};

/* file descriptors template */
struct cr_fd_desc_tmpl {
	const char	*fmt;			/* format for the name */
	u32		magic;			/* magic in the header */
};

#define FMT_FNAME_FDINFO	"fdinfo-%d.img"
#define FMT_FNAME_PAGES		"pages-%d.img"
#define FMT_FNAME_PAGES_SHMEM	"pages-shmem-%d.img"
#define FMT_FNAME_CORE		"core-%d.img"
#define FMT_FNAME_CORE_OUT	"core-%d.img.out"
#define FMT_FNAME_PIPES		"pipes-%d.img"
#define FMT_FNAME_PSTREE	"pstree-%d.img"
#define FMT_FNAME_SHMEM		"shmem-%d.img"
#define FMT_FNAME_VMAS		"vmas-%d.img"
#define FMT_FNAME_SIGACTS	"sigacts-%d.img"

/* file descriptors */
struct cr_fd_desc {
	struct cr_fd_desc_tmpl	*tmpl;		/* template we refer to */
	char			name[64];	/* the name, based on pid */
	int			fd;		/* descriptor for open/close */
};

struct cr_fdset {
	struct cr_fd_desc	desc[CR_FD_MAX];
	u32			use_mask;	/*
						 * if descriptor get used,set
						 * bit here
						 */
};

#define CR_FD_DESC_USE(type)		((1 << (type)))
#define CR_FD_DESC_ALL			(CR_FD_DESC_USE(CR_FD_MAX) - 1)
#define CR_FD_DESC_CORE			CR_FD_DESC_USE(CR_FD_CORE)
#define CR_FD_DESC_NOPSTREE		(CR_FD_DESC_ALL & ~(CR_FD_DESC_USE(CR_FD_PSTREE)))
#define CR_FD_DESC_NONE			(0)

int cr_dump_tasks(pid_t pid, struct cr_options *opts);
int cr_restore_tasks(pid_t pid, struct cr_options *opts);
int cr_show(unsigned long pid, struct cr_options *opts);
int convert_to_elf(char *elf_path, int fd_core);

struct cr_fdset *alloc_cr_fdset(pid_t pid);
int prep_cr_fdset_for_dump(struct cr_fdset *cr_fdset,
			   unsigned long use_mask);
int prep_cr_fdset_for_restore(struct cr_fdset *cr_fdset,
			      unsigned long use_mask);
void close_cr_fdset(struct cr_fdset *cr_fdset);
void free_cr_fdset(struct cr_fdset **cr_fdset);

void free_mappings(struct list_head *vma_area_list);

struct vma_area {
	struct list_head	list;
	struct vma_entry	vma;
	unsigned long		shmid;
	int			vm_file_fd;
};

#define vma_area_is(vma_area, s)	vma_entry_is(&((vma_area)->vma), s)
#define vma_area_len(vma_area)		vma_entry_len(&((vma_area)->vma))

struct pstree_item {
	struct list_head	list;
	pid_t			pid;		/* leader pid */
	u32			nr_children;	/* number of children */
	u32			nr_threads;	/* number of threads */
	u32			*threads;	/* array of threads */
	u32			*children;	/* array of children */
};

static inline int in_vma_area(struct vma_area *vma, unsigned long addr)
{
	return addr >= (unsigned long)vma->vma.start &&
		addr < (unsigned long)vma->vma.end;
}

#endif /* CRTOOLS_H_ */
