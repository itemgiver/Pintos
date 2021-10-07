#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct semaphore file_sema;

void syscall_init (void);
void syscall_exit(int);

#endif /* userprog/syscall.h */
