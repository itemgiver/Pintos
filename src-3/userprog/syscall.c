#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "vm/vm.h"

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
static int mmap(int,void *);
void syscall_munmap(int);

static int global_fd;
static struct semaphore global_fd_sema;
static int global_mapid;
static struct semaphore global_mapid_sema;
static struct semaphore flist_sema;

void
syscall_init (void) 
{
	sema_init(&file_sema,1);
	sema_init(&global_fd_sema,1);
	sema_init(&global_mapid_sema,1);
	sema_init(&flist_sema,1);
	sema_init(&mmaplist_sema,1);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	global_fd = 1;
	global_mapid = 0;
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

	thread_current()->esp = f->esp;
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
		case SYS_MMAP:
			pop_stack(f->esp+4,arg,2);
			f->eax = (int)mmap(*(int *)arg[0],*(void **)arg[1]);
			break;
		case SYS_MUNMAP:
			pop_stack(f->esp+4,arg,1);
			syscall_munmap(*(int *)arg[0]);
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

static int open(const char *file){
	struct list_elem *e;
	struct file *file_p;
	struct file_descriptor *file_tmp;
	
	if(!check_string(file)) return -1;
	sema_down(&file_sema);
	file_p = filesys_open(file);
	if(file_p != NULL && check_executing(file)){
		file_deny_write(file_p);
	}
	sema_up(&file_sema);
	if(file_p == NULL) return -1;
	file_tmp = (struct file_descriptor*)malloc(sizeof(struct file_descriptor));
	ASSERT(file_tmp != NULL);
	file_tmp->file_p = file_p;

	sema_down(&global_fd_sema);
	global_fd++;
	file_tmp->fd = global_fd;
	sema_up(&global_fd_sema);

	sema_down(&flist_sema);
	list_push_back(&thread_current()->file_list,&file_tmp->elem);
	sema_up(&flist_sema);

	return file_tmp->fd;
}

static struct file* change_fd(int fd){
	struct list_elem *e;
	struct thread *cur;
	struct file_descriptor *tmp;

	sema_down(&flist_sema);
	cur = thread_current();
	for(e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
		tmp = list_entry(e,struct file_descriptor,elem);
		if(tmp->fd == fd){
			sema_up(&flist_sema);
			return tmp->file_p;
		}
	}
	sema_up(&flist_sema);
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

static uint32_t max(uint32_t x,uint32_t y){
	return (x > y) ? x : y;
}

static uint32_t min(uint32_t x,uint32_t y){
	return (x < y) ? x : y;
}

static int read(int fd,void *buffer,uint32_t size){ // be careful with check_address(buffer+size-1)
	if(!check_address(buffer) || !check_address(buffer+size-1)) syscall_exit(-1);
	uint32_t *pd = thread_current()->pagedir;
	void *upage;
	uint32_t i;

	if(fd == 0){
		for(upage=pg_round_down(buffer); upage<=pg_round_down(buffer+size-1); upage+=PGSIZE){
			prevent_fault(pd,upage);
			for(i=max(upage,buffer); i<min(buffer+size,upage+PGSIZE); i++){
				*(char *)(buffer+i) = input_getc();
			}
			sptable_set_evict(pd,upage,true);
		}

		return size;
	}else{
		int ret = 0;
		struct file *file_p;

		file_p = change_fd(fd);
		if(file_p == NULL){
			return -1;
		}
		for(upage=pg_round_down(buffer); upage<=pg_round_down(buffer+size-1); upage+=PGSIZE){
			sema_down(&file_sema);
			prevent_fault(pd,upage);
			ret += file_read(file_p,max(upage,buffer),min(buffer+size,upage+PGSIZE)-max(upage,buffer));
			sema_up(&file_sema);
			sptable_set_evict(pd,upage,true);
		}

		return ret;
	}
}

static int write(int fd,const void *buffer,uint32_t size){
	if(!check_address(buffer) || !check_address(buffer+size-1)) return 0;
	uint32_t *pd = thread_current()->pagedir;
	void *upage;

	if(fd == 1){
		for(upage=pg_round_down(buffer); upage<=pg_round_down(buffer+size-1); upage+=PGSIZE){
			prevent_fault(pd,upage);
			putbuf(max(upage,buffer),min(buffer+size,upage+PGSIZE)-max(upage,buffer));
			sptable_set_evict(pd,upage,true);
		}

		return size;
	}else{
		int ret = 0;
		struct file *file_p;

		file_p = change_fd(fd);
		if(file_p == NULL) return 0;
		for(upage=pg_round_down(buffer); upage<=pg_round_down(buffer+size-1); upage+=PGSIZE){
			sema_down(&file_sema);
			prevent_fault(pd,upage);
			ret += file_write(file_p,max(upage,buffer),min(buffer+size,upage+PGSIZE)-max(upage,buffer));
			sema_up(&file_sema);
			sptable_set_evict(pd,upage,true);
		}

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

	file_p = NULL;
	sema_down(&flist_sema);
	cur = thread_current();
	for(e=list_begin(&cur->file_list); e!=list_end(&cur->file_list); e=list_next(e)){
		tmp = list_entry(e,struct file_descriptor,elem);
		if(tmp->fd == fd){
			list_remove(e);
			file_p = tmp;
			break;
		}
	}
	sema_up(&flist_sema);

	if(file_p == NULL) return;
	sema_down(&file_sema);
	file_close(file_p->file_p);
	sema_up(&file_sema);
	free(file_p);
}

static int mmap(int fd,void *addr){
	int ret,fsize;
	uint32_t *pd;
	void *upage;
	struct file *file_p;
	struct mmap_descriptor *mmap_p;

	file_p = change_fd(fd);
	if(file_p == NULL) return -1;
	fsize = filesize(fd);
	if(fsize == 0) return -1;
	if(pg_ofs(addr) != 0) return -1;
	if(addr == 0) return -1;
	pd = thread_current()->pagedir;
	for(upage=addr; upage<addr+fsize; upage+=PGSIZE){
		if(check_mapped(pd,upage)) return -1;
	}
	mmap_p = (struct mmap_descriptor *)malloc(sizeof(struct mmap_descriptor));
	sema_down(&file_sema);
	mmap_p->file_p = file_reopen(file_p);
	sema_up(&file_sema);
	mmap_p->fsize = fsize;
	mmap_p->upage = addr;

	sema_down(&global_mapid_sema);
	mmap_p->mapid = global_mapid;
	global_mapid++;
	sema_up(&global_mapid_sema);

	for(upage=addr; upage<addr+fsize; upage+=PGSIZE){
		lazy_loading(min(PGSIZE,addr+fsize-upage),PGSIZE-min(PGSIZE,addr+fsize-upage),mmap_p->file_p,upage,upage-addr,true);
	}

	sema_down(&mmaplist_sema);
	list_push_back(&thread_current()->mmap_list,&mmap_p->elem);
	sema_up(&mmaplist_sema);

	return mmap_p->mapid;
}

void syscall_munmap(int mapping){
	uint32_t *pd;
	void *upage,*kpage;
	struct list_elem *e;
	struct mmap_descriptor *mmap_p;
	struct sptable *tmp;

	sema_down(&mmaplist_sema);
	for(e=list_begin(&thread_current()->mmap_list); e!=list_end(&thread_current()->mmap_list); e=list_next(e)){
		mmap_p = list_entry(e,struct mmap_descriptor,elem);
		if(mmap_p->mapid == mapping) break;
	}
	if(e == list_end(&thread_current()->mmap_list)){
		sema_up(&mmaplist_sema);
		return;
	}
	list_remove(e);
	sema_up(&mmaplist_sema);

	pd = thread_current()->pagedir;
	for(upage=mmap_p->upage; upage<mmap_p->upage+mmap_p->fsize; upage+=PGSIZE){
		sptable_set_evict(pd,upage,false);
		check_lazy(pd,upage,true,false);
		swap_in(pd,upage,false);

		sema_down(&page_sema);
		for(e=list_begin(&page_list); e!=list_end(&page_list); e=list_next(e)){
			tmp = list_entry(e,struct sptable,elem);
			if(tmp->pd == pd && tmp->upage == upage){
				break;
			}
		}
		ASSERT(e != list_end(&page_list));
		sema_up(&page_sema);

		if(pagedir_is_dirty(pd,upage)){
			sema_down(&file_sema);
			file_seek(mmap_p->file_p,upage-mmap_p->upage);
			file_write(mmap_p->file_p,tmp->kpage,min(PGSIZE,mmap_p->upage+mmap_p->fsize-upage));
			sema_up(&file_sema);
		}
		kpage = tmp->kpage;
		pagedir_clear_page(pd,upage);
		palloc_free_page(kpage);
	}

	sema_down(&file_sema);
	file_close(mmap_p->file_p);
	sema_up(&file_sema);
	free(mmap_p);
}
