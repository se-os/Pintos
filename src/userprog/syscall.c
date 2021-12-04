#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "pagedir.h"
#include <string.h>
#include "debug.h"

static void syscall_handler(struct intr_frame *);
struct lock file_lock;
struct list file_list;
#define MAX_CALL 20
static void (*syscalls[MAX_CALL])(struct intr_frame *); //根据调用号调用syscall

void check_pointer(void *esp, int num); //检查esp指针是否合法

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
void close(int);
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  list_init(&file_list);
  //初始化系统调用列表
  //syscalls[SYS_EXEC] = &sys_exec;
  //syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
  //syscalls[SYS_WAIT] = &sys_wait;
  //syscalls[SYS_CREATE] = &sys_create;
  //syscalls[SYS_REMOVE] = &sys_remove;
  //syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  //syscalls[SYS_SEEK] = &sys_seek;
  //syscalls[SYS_TELL] = &sys_tell;
  //syscalls[SYS_CLOSE] =&sys_close;
  //syscalls[SYS_READ] = &sys_read;
  //syscalls[SYS_FILESIZE] = &sys_filesize;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  // printf("system call!\n");
  int *p = f->esp;
  check_pointer(p, 1);
  int type = *(int *)p;
  if (p == NULL || type <= 0 || type >= MAX_CALL)
    exit(-1);
  syscalls[type](f); //根据调用号调用系统调用函数
  
  //printf ("system call!\n");
  //thread_exit ();
}
void check_pointer(void *esp, int num)
{
  for (int i = 0; i < num * 4; i++)
    if (!is_user_vaddr(esp + i) || !pagedir_get_page(thread_current()->pagedir, esp + i))
      exit(-1);
  return;
}

//根据fd值获取fd
struct fd *
get_fd_by_code(int fd_code)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  struct fd *fd_tmp = NULL;
  // printf("try\n");
  //遍历当前线程的fd列表，查找符合的对象
  for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = e->prev)
  {
    // printf("try\n");
    fd_tmp = list_entry(e, struct fd, fd_elem);
    // printf("try1\n");
    // printf("%p\n", fd_tmp);
    // printf("%p\n", fd_tmp->fd_code);
    if (fd_tmp->fd_code == fd_code)
    {
      // printf("try\n");
      return fd_tmp;
    }
    // printf("try\n");
  }
  return NULL;
}
void sys_halt(void)
{
  shutdown_power_off();
}

void sys_exit(struct intr_frame *f)
{
  uint32_t *p = f->esp + 4;
  check_pointer(p, 1);
  int status = *p;
  exit(status);
}
void exit(int status)
{
  struct list_elem *e;
  // printf("try\n");
  struct thread *cur = thread_current();
  // printf("try\n");
  //将线程的所有文件关闭
   while (!list_empty(&cur->fd_list))
   {
     e = list_begin(&cur->fd_list);
     close(list_entry(e, struct fd, fd_elem)->fd_code);
   }
   // printf("try\n");
   file_close(cur->dealing_file);
  // printf("try\n");
  //设置线程退出码为指定退出码
  thread_current()->exit_code = status;
  // printf("try\n");
  thread_exit();
}

void sys_exec(struct intr_frame *f)
{
   uint32_t *p = f->esp + 4;
   check_pointer(p,1);
   char* ptr = *(char**)p;
   if(ptr == NULL)exit(-1);
   check_pointer(ptr,1);
   f->eax = process_execute(ptr);
}

void sys_write(struct intr_frame *f)
{
  // printf("start write\n");
  uint32_t *p = f->esp + 4;
  // uint32_t *user_ptr = f->esp;
  // *user_ptr++;
  // int fd_test = *user_ptr;
  // printf("finish int *p = f->esp + 4\n");
  check_pointer(p, 3);
  // printf("finish check_pointer(p, 3)\n");
  int fd = *p++;
  // int fd = *(int *)(f->esp);
  // printf("fd_code: %d\n", fd);
  // printf("fd_test: %d\n", fd_test);
  // int fd = *(int *)p;
  // printf("finish int fd = *(int *)p\n");
  void *buffer = *(char **)p++;
  // printf("finish void *buffer = *(char **)(f->esp + 8)\n");
  off_t size = *p;
  // printf("finish unsigned size = *(unsigned *)(f->esp + 12)\n");
  if (buffer == NULL)
  {
    // printf("buffer == NULL!\n");
    exit(-1);
  }
  // printf("buffer != NULL!\n");
  check_pointer(buffer, 1);
  // printf("test exit\n");
  // exit(-1);
  // printf("jump check_pointer(buffer, 1)\n");
  // printf("finish check_pointer(buffer, 1)\n");
  f->eax = write(fd, buffer, size);
}



int write(int fd_code, const void *buffer, unsigned size)
{
  // printf("get into write\n");
  if (fd_code == 1)
  {
    //输出到控制台
    putbuf(buffer, size);
    return size;
  }
  else
  {
      // printf("fd_code != 1!\n");
    struct fd *f = get_fd_by_code(fd_code);
    // printf("finish struct fd *f = get_fd_by_code(fd_code)\n");
    if (f)
    {
      // //向文件进行写，得到返回码，即实际写入的字节数
      lock_acquire(&file_lock);
      // printf("finish lock_acquire(&file_lock)\n");
      int ret = file_write(f->file, buffer, size);
      // printf("finish int ret = file_write(f->file, buffer, size)\n");
      lock_release(&file_lock);
      // printf("finish lock_release(&file_lock);\n");
      return ret;
    }
    else
    {
      return -1;
    }
  }
}

//通过文件标识符的值关闭文件
void close(int fd_code)
{
  //根据fd值获取文件标识符
  struct fd *f = get_fd_by_code(fd_code);
  if (f == NULL)
    return -1;
  //关闭文件
  file_close(f->file);
  list_remove(&f->fd_elem);
  free(f);
}