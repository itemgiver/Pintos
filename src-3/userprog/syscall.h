#include <list.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct semaphore file_sema;
struct semaphore mmaplist_sema;

void syscall_init (void);
void syscall_exit(int);
void syscall_munmap(int);

struct mmap_descriptor{
	int mapid;
	int fsize;
	void *upage;
	struct file *file_p;

	struct list_elem elem;
};

#endif /* userprog/syscall.h */
