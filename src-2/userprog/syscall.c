#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static void halt();
void syscall_exit(int);
static tid_t exec(const char *);
static int wait(tid_t);
static bool create(const char *,uint32_t);
static bool remove(const char *);
static int open(const char *);
static int filesize(int);
static int read(int,void *,uint32_t);
static int write(int,const void *,uint32_t);
static void seek(int,uint32_t);
static uint32_t tell(int);
static void close(int);

void
syscall_init (void) 
{
	sema_init(&file_sema,1);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool check_address(void *ptr){
	if(ptr < (uint32_t)0x08048000 || ptr >= PHYS_BASE) return false;
	return true;
}

static bool check_string(const char *ptr){
	while(true){
		if(!check_address(ptr)) return false;
		if(*ptr == '\0') break;
		ptr++;
	}
	return true;
}

static void pop_stack(void *esp,void **arg,int argc){
	if(!check_address(esp) || !check_address(esp+(4*argc-1))) syscall_exit(-1);
	for(int i=0; i<argc; i++){
		arg[i] = esp;
		esp = (uint32_t)esp + 4;
	}
}

static void
syscall_handler (struct intr_frame *f UNUSED) {
	int sys_num;
	void *arg[3];
	unsigned x;

	pop_stack(f->esp,arg,1);
	sys_num = *(int *)arg[0];

	switch(sys_num){
		case SYS_HALT:
			halt();
		case SYS_EXIT:
			pop_stack(f->esp+4,arg,1);
			syscall_exit(*(int *)arg[0]);
		case SYS_EXEC:
			pop_stack(f->esp+4,arg,1);
			f->eax = (tid_t)exec(*(char **)arg[0]);
			break;
		case SYS_WAIT:
			pop_stack(f->esp+4,arg,1);
			f->eax = (int)wait(*(tid_t *)arg[0]);
			break;
		case SYS_CREATE:
			pop_stack(f->esp+4,arg,2);
			f->eax = (bool)create(*(char **)arg[0],*(uint32_t *)arg[1]);
			break;
		case SYS_REMOVE:
			pop_stack(f->esp+4,arg,1);
			f->eax = (bool)remove(*(char **)arg[0]);
			break;
		case SYS_OPEN:
			pop_stack(f->esp+4,arg,1);
			f->eax = (int)open(*(char **)arg[0]);
			break;
		case SYS_FILESIZE:
			pop_stack(f->esp+4,arg,1);
			f->eax = (int)filesize(*(int *)arg[0]);
			break;
		case SYS_READ:
			pop_stack(f->esp+4,arg,3);
			f->eax = (int)read(*(int *)arg[0],*(void **)arg[1],*(uint32_t *)arg[2]);
			break;
		case SYS_WRITE:
			pop_stack(f->esp+4,arg,3);
			f->eax = (int)write(*(int *)arg[0],*(void **)arg[1],*(uint32_t *)arg[2]);
			break;
		case SYS_SEEK:
			pop_stack(f->esp+4,arg,2);
			seek(*(int *)arg[0],*(uint32_t *)arg[1]);
			break;
		case SYS_TELL:
			pop_stack(f->esp+4,arg,1);
			f->eax = (uint32_t)tell(*(int *)arg[0]);
			break;
		case SYS_CLOSE:
			pop_stack(f->esp+4,arg,1);
			close(*(int *)arg[0]);
			break;
		default:
			syscall_exit(-1);
	}
}

static void halt(){
	shutdown_power_off();
}

void syscall_exit(int status){
	set_exit_status(status);
	printf("%s: exit(%d)\n",thread_current()->name,status);
	thread_exit();
}

static tid_t exec(const char *cmd_line){
	tid_t tid;

	if(!check_string(cmd_line)) return -1;
	tid = process_execute(cmd_line);

	return tid;
}

static int wait(tid_t tid){
	return process_wait(tid);
}

static bool create(const char *file,uint32_t initial_size){
	bool ret;
	
	if(!check_string(file)) syscall_exit(-1);
	sema_down(&file_sema);
	ret = filesys_create(file,initial_size);
	sema_up(&file_sema);

	return ret;
}

static bool remove(const char *file){
	bool ret;
	
	if(!check_string(file)) return false;
	sema_down(&file_sema);
	ret = filesys_remove(file);
	sema_up(&file_sema);

	return ret;
}

static bool list_fd_less_func(const struct list_elem *a,const struct list_elem *b,void *aux){
	return list_entry(a,struct file_descriptor,elem)->fd < list_entry(b,struct file_descriptor,elem)->fd;
}

static int open(const char *file){
	struct list_elem *e;
	struct thread *cur;
	struct file *file_p;
	struct file_descriptor *file_tmp,*tmp;
	enum intr_level old_level;
	
	if(!check_string(file)) return -1;
	sema_down(&file_sema);
	file_p = filesys_open(file);
	if(file_p != NULL && check_executing(file)){
		file_deny_write(file_p);
	}
	sema_up(&file_sema);
	if(file_p == NULL) return -1;
	file_tmp = (struct file_descriptor*)malloc(sizeof(struct file_descriptor));
	file_tmp->file_p = file_p;
	file_tmp->fd = 2;

	old_level = intr_disable();
	cur = thread_current();
	for(e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
		tmp = list_entry(e,struct file_descriptor,elem);
		if(tmp->fd != file_tmp->fd) break;
		file_tmp->fd++;
	}
	list_insert_ordered(&cur->file_list,&file_tmp->elem,list_fd_less_func,NULL);
	intr_set_level(old_level);

	return file_tmp->fd;
}

static struct file* change_fd(int fd){
	struct list_elem *e;
	struct thread *cur;
	struct file_descriptor *tmp;
	enum intr_level old_level;

	old_level = intr_disable();
	cur = thread_current();
	for(e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
		tmp = list_entry(e,struct file_descriptor,elem);
		if(tmp->fd == fd){
			intr_set_level(old_level);
			return tmp->file_p;
		}
	}
	intr_set_level(old_level);
	return NULL;
}

static int filesize(int fd){
	int ret;
	struct file *file_p;

	file_p = change_fd(fd);
	if(file_p == NULL) return -1;
	sema_down(&file_sema);
	ret = file_length(file_p);
	sema_up(&file_sema);

	return ret;
}

static int read(int fd,void *buffer,uint32_t size){ // be careful with check_address(buffer+size-1)
	if(!check_address(buffer) || !check_address(buffer+size-1)) syscall_exit(-1);
	if(fd == 0){
		for(uint32_t i=0; i<size; i++){
			*(char *)(buffer+i) = input_getc();
		}
		return size;
	}else{
		int ret;
		struct file *file_p;

		file_p = change_fd(fd);
		if(file_p == NULL) return -1;
		sema_down(&file_sema);
		ret = file_read(file_p,buffer,size);
		sema_up(&file_sema);

		return ret;
	}
}

static int write(int fd,const void *buffer,uint32_t size){
	if(!check_address(buffer) || !check_address(buffer+size-1)) return 0;
	if(fd == 1){
		putbuf(buffer,size);
		return size;
	}else{
		int ret;
		struct file *file_p;

		file_p = change_fd(fd);
		if(file_p == NULL) return 0;
		sema_down(&file_sema);
		ret = file_write(file_p,buffer,size);
		sema_up(&file_sema);

		return ret;
	}
}

static void seek(int fd,uint32_t position){
	struct file *file_p;

	file_p = change_fd(fd);
	if(file_p == NULL) return;
	sema_down(&file_sema);
	file_seek(file_p,position);
	sema_up(&file_sema);
}

static uint32_t tell(int fd){
	int ret;
	struct file *file_p;

	file_p = change_fd(fd);
	if(file_p == NULL) return -1;
	sema_down(&file_sema);
	ret = file_tell(file_p);
	sema_up(&file_sema);

	return ret;
}

static void close(int fd){
	struct list_elem *e;
	struct thread *cur;
	struct file_descriptor *tmp,*file_p;
	enum intr_level old_level;

	file_p = NULL;
	old_level = intr_disable();
	cur = thread_current();
	for(e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
		tmp = list_entry(e,struct file_descriptor,elem);
		if(tmp->fd == fd){
			list_remove(e);
			file_p = tmp;
			break;
		}
	}
	intr_set_level(old_level);

	if(file_p == NULL) return;
	sema_down(&file_sema);
	file_close(file_p->file_p);
	sema_up(&file_sema);
	free(file_p);
}
