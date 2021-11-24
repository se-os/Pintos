#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
 
  // /* Our implementation for Task3: initialize create, remove, open, filesize, read, write, seek, tell, and close */
  syscalls[SYS_WAIT] = &sys_wait;
  syscalls[SYS_CREATE] = &sys_create;
  syscalls[SYS_REMOVE] = &sys_remove;
  syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  syscalls[SYS_SEEK] = &sys_seek;
  syscalls[SYS_TELL] = &sys_tell;
  syscalls[SYS_CLOSE] =&sys_close;
  syscalls[SYS_READ] = &sys_read;
  syscalls[SYS_FILESIZE] = &sys_filesize;
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  int *p=f->esp;
  check_pointer(p,1);
  int type=*(int *)p;
  if(p==NULL||type<=0||type>=MAX_CALL)
    exit(-1);
  syscalls[type](f);//根据调用号调用系统调用函数
  //printf ("system call!\n");
  //thread_exit ();
}
void check_pointer(void* esp,int num){
  for(int i=0;i<num*4;i++)
    if(!is_user_vaddr(esp+i)||!pagedir_get_page (thread_current()->pagedir, esp+i))
      exit(-1);
  return;
}

//根据fd值获取fd
struct fd *
get_fd_by_code(int fd_code)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  //遍历当前线程的fd列表，查找符合的对象
  for (e = list_begin(&cur->fd_list); e != list_end(&cur->fd_list); e = e->prev)
  {
    struct fd *fd = list_entry(e, struct fd, fd_elem);
    if (fd->fd_code == fd_code)
      return fd;
  }
  return NULL;
}
void 
sys_exit(struct intr_frame *f)
{
  int *p=f->esp+4;
  check_pointer(p,1);
  int status = *(int*)p;
  exit(status);
}
void 
sys_write(struct intr_frame *f)
{
  int *p=f->esp+4;
  check_pointer(p,3);
  int fd = *(int*)p;
  void *buffer = *(char**)(f->esp+8);
  unsigned size = *(unsigned*)(f->esp+12);
  if(buffer==NULL)exit(-1);
  check_pointer(buffer,1);
  f->eax = write(fd,buffer,size);
}
void exit(int status)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  //将线程的所有文件关闭
  while (!list_empty(&cur->fd_list))
  {
    e = list_begin(&cur->fd_list);
    close(list_entry(e, struct fd, fd_elem)->fd_code);
  }
  file_close(cur->dealing_file);
  //设置线程退出码为指定退出码
  thread_current()->exit_code = status;
  thread_exit();
}
int write(int fd_code, const void *buffer, unsigned size)
{

  if (fd_code == STDOUT_FILENO)
  {
    //输出到控制台
    putbuf((const char *)buffer, size);
    return size;
  }

  struct fd *f = get_fd_by_code(fd_code);
  if (f == NULL)
    return -1;
  //向文件进行写，得到返回码，即实际写入的字节数
  lock_acquire(&file_lock);
  int ret = file_write(f->file, buffer, size);
  lock_release(&file_lock);
  return ret;
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