#include <list.h>
#include <filesys/file.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#endif /* userprog/syscall.h */
struct fd{
    int count;
    struct file* file;
    struct list_elem fd_elem;

};
void exit (int);
int write(int,const void *,unsigned);
