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

int fd_num = 2;
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
int open(const char *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  list_init(&file_list);
  int i = 0;
  for (i = 0; i < MAX_CALL; i++)
  {
    syscalls[i] = NULL;
  }
  //初始化系统调用列表
  syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
  syscalls[SYS_WAIT] = &sys_wait;
  syscalls[SYS_CREATE] = &sys_create;
  syscalls[SYS_REMOVE] = &sys_remove;
  syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  syscalls[SYS_SEEK] = &sys_seek;
  syscalls[SYS_TELL] = &sys_tell;
  syscalls[SYS_CLOSE] = &sys_close;
  syscalls[SYS_READ] = &sys_read;
  syscalls[SYS_FILESIZE] = &sys_filesize;
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
    if (!is_user_vaddr(esp + i) || pagedir_get_page(thread_current()->pagedir, esp + i) == NULL)
      exit(-1);
  return;
}

void check_char_pointer(char *pointer)
{
  if (pointer == NULL)
  {
    exit(-1);
  }
  check_pointer(pointer, 1);
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
  check_pointer(p, 1);
  char *ptr = *(char **)p;
  if (ptr == NULL)
    exit(-1);
  check_pointer(ptr, 1);
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
  lock_acquire(&file_lock);
  f->eax = write(fd, buffer, size);
  lock_release(&file_lock);
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

      // printf("finish lock_acquire(&file_lock)\n");
      int ret = file_write(f->file, buffer, size);
      // printf("finish int ret = file_write(f->file, buffer, size)\n");

      // printf("finish lock_release(&file_lock);\n");
      return ret;
    }
    else
    {
      return -1;
    }
  }
}

void sys_open(struct intr_frame *f)
{
  // printf("\nstart sys_open\n");
  uint32_t *p = f->esp + 4;
  check_pointer(p, 1);
  char *filename = *(char **)(f->esp + 4);
  check_char_pointer(filename);

  // printf("\ncheck complete!\n");
  lock_acquire(&file_lock);
  f->eax = open(filename);
  lock_release(&file_lock);
}

int open(const char *filename)
{
  // printf("\nopen start!\n");
  struct file *f = filesys_open(filename);
  struct thread *current = thread_current();
  if (f == NULL)
    return -1;
  struct fd *fd_tmp = malloc(sizeof(struct fd));

  if (fd_tmp == NULL)
  {
    file_close(f);
    return -1;
  }
  fd_tmp->file = f;
  fd_tmp->fd_code = fd_num;
  fd_num++;
  // printf("\nthread:%s fd_code:%d\n", current->name, fd->fd_code);
  list_push_back(&current->fd_list, &fd_tmp->fd_elem);
  // printf("\nopen\n");
  return fd_tmp->fd_code;
}

void sys_read(struct intr_frame *f)
{
  check_pointer(f->esp + 4, 3);
  int fd_code = *(int *)(f->esp + 4);
  void *buf = *(char **)(f->esp + 8);
  unsigned file_size = *(unsigned *)(f->esp + 12);
  check_char_pointer(buf);

  lock_acquire(&file_lock);
  f->eax = read(fd_code, buf, file_size);
  lock_release(&file_lock);
}

int read(int fd_code, void *buffer, unsigned file_size)
{
  if (fd_code == 0)
  {
    int i;
    for (i = 0; i < file_size; i++)
    {
      (*((char **)buffer))[i] = input_getc();
    }
    return file_size;
  }
  struct fd *fd = get_fd_by_code(fd_code);
  if (fd == NULL)
  {
    return -1;
  }
  return file_read(fd->file, buffer, file_size);
}

void sys_close(struct intr_frame *f)
{
  uint32_t *p = f->esp + 4;
  check_pointer(p, 1);
  int fd_code = *(int *)(p);

  lock_acquire(&file_lock);
  close(fd_code);
  lock_release(&file_lock);
}

//通过文件标识符的值关闭文件
void close(int fd_code)
{
  //根据fd值获取文件标识符
  struct fd *fd = get_fd_by_code(fd_code);
  if (fd == NULL)
    return -1;
  //关闭文件
  file_close(fd->file);
  list_remove(&fd->fd_elem);
  free(fd);
}

//filesize系统调用
void sys_filesize(struct intr_frame *f)
{
  //同write，获取文件描述符
  uint32_t *p = f->esp + 4;
  check_pointer(p, 1);
  int fd_code = *p++;
  struct fd *fd = get_fd_by_code(fd_code);
  if (fd != NULL)
  {
    lock_acquire(&file_lock);
    f->eax = file_length(fd->file);
    lock_release(&file_lock);
  }
  else
  {
    f->eax = -1;
  }
}

//seek系统调用
void sys_seek(struct intr_frame *f)
{
  uint32_t *p = f->esp + 4;
  //检查文件名和距离是否在用户栈内
  check_pointer(p, 2);
  int fd_code = *p++;
  unsigned int pos = *p++;
  struct fd *fd = get_fd_by_code(fd_code);
  if (fd != NULL)
  {
    //调用API
    lock_acquire(&file_lock);
    file_seek(fd->file, pos);
    lock_release(&file_lock);
  }
  else
  {
    exit(-1);
  }
}

//tell系统调用
void sys_tell(struct intr_frame *f)
{
  uint32_t *p = f->esp + 4;
  check_pointer(p, 1);
  int fd_code = *p++;
  struct fd *fd = get_fd_by_code(fd_code);
  if (fd != NULL)
  {
    lock_acquire(&file_lock);
    f->eax = file_tell(fd->file);
    lock_release(&file_lock);
  }
  else
  {
    f->eax = -1;
  }
}

//创建文件系统调用
void sys_create(struct intr_frame *f)
{
  //printf("%s syscall_create\n",thread_current()->name);
  //检查文件名和初始化大小两个参数是否合法。
  uint32_t *p = f->esp + 4;
  check_pointer(p, 2);
  char *file = *(char **)(f->esp + 4);
  //文件名不能为空
  if (file == NULL)
  {
    exit(-1);
  }
  check_pointer(file, 1);
  unsigned initial_size = *(int *)(f->esp + 8);
  //printf("%s lock acquire\n",thread_current()->name);
  //调用 filesys/filesys.c 中定义的 filesys_create
  lock_acquire(&file_lock);
  f->eax = filesys_create(file, initial_size);
  lock_release(&file_lock);
  //printf("%s lock release\n",thread_current()->name);
}

//删除文件系统调用
void sys_remove(struct intr_frame *f)
{
  uint32_t *p = f->esp + 4;
  //检查文件名参数是否合法。
  check_pointer(p, 1);
  char *file = *(char **)(f->esp + 4);
  if (file == NULL)
  {
    exit(1);
  }
  check_pointer(file, 1);
  //printf("%s lock acquire\n",thread_current()->name);
  lock_acquire(&file_lock);
  f->eax = filesys_remove(file);
  lock_release(&file_lock);
  //printf("%s lock release\n",thread_current()->name);
}

void sys_wait(struct intr_frame *f)
{
  uint32_t *p = f->esp + 4;
  //检查文件名参数是否合法。
  check_pointer(p, 1);
  pid_t pid = *(int *)(f->esp + 4);
  f->eax = process_wait(pid);
}