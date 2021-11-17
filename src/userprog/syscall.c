#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
struct fd*
get_fd_by_code(int fd_code)
{
  struct list_elem *e;
  struct thread *cur = thread_current();
  for (e = list_begin (&cur->fd_list); e != list_end (&cur->fd_list); e = e->prev)
  {
    struct fd *fd = list_entry (e, struct fd, fd_elem);
    if(fd->fd_code == fd_code)return fd;
  }
  return NULL;
}

void
exit(int status){
  struct list_elem *e;
  struct thread *cur = thread_current ();
  while (!list_empty(&cur->fd_list))
  {
    e = list_begin(&cur->fd_list);
    close(list_entry(e, struct fd, fd_elem)->fd_code);
  }
  file_close(cur->opened_file);
  thread_current()->exit_code = status;
  thread_exit();
}
int
write(int fd_code,const void* buffer,unsigned size){
  
  if (fd_code == STDOUT_FILENO)
  {
    putbuf((const char *)buffer, size);
    return size;
  }

  struct fd *f = get_fd_by_code(fd_code);
  if(f==NULL)return -1;
  int ret = file_write(f->file, buffer, size);

  return ret;
}
void
close(int fd_code)
{
    struct fd *f = get_fd_by_code(fd_code);
    if(f==NULL)return -1;
    file_close(f->file);
    list_remove(&f->fd_elem);
    free(f);
}