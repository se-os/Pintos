#include <list.h>
#include <filesys/file.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);

#endif /* userprog/syscall.h */
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
