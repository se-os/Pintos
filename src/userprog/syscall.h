#include <lib/kernel/list.h>
#include <filesys/file.h>
#include <threads/synch.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
typedef int pid_t;
struct lock file_lock;
void syscall_init(void);
void exit(int);
#endif /* userprog/syscall.h */
