#include <list.h>
#include <filesys/file.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

#endif /* userprog/syscall.h */
#define MAX_CALL 20
static void (*syscalls[MAX_CALL])(struct intr_frame *);//根据调用号调用syscall

void check_pointer(void *esp,int num);
void sys_halt(void);
void sys_exit(struct intr_frame *);
void sys_exec(struct intr_frame *);
void sys_wait(struct intr_frame *);
void sys_create(struct intr_frame *);
void sys_remove(struct intr_frame *);
void sys_open(struct intr_frame *);
void sys_filesize(struct intr_frame *);
void sys_read(struct intr_frame *);
void sys_write(struct intr_frame *);
void sys_seek(struct intr_frame *);
void sys_tell(struct intr_frame *);
void sys_close(struct intr_frame *);

//文件描述符
struct fd
{
    int fd_code;              //文件描述符的值
    struct file *file;        //该描述符指向的文件
    struct list_elem fd_elem; //代表fd的对象
};
//退出
void exit(int);

//写
int write(int, const void *, unsigned);
