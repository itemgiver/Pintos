#include "devices/block.h"
#include "vm/vm.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"

static struct semaphore swap_sema;
static struct block *swap_disk;
static struct bitmap *swap_bitmap;
static struct list swap_list;
static struct list prevent_list;
static struct semaphore prevent_sema;
static struct list lazy_list;
static struct semaphore lazy_sema;

void vm_init(){
	swap_disk = block_get_role(BLOCK_SWAP);
	if(swap_disk != NULL){
		swap_bitmap = bitmap_create(block_size(swap_disk)/8);
	}
	sema_init(&swap_sema,1);
	sema_init(&page_sema,1);
	sema_init(&prevent_sema,1);
	sema_init(&lazy_sema,1);
	list_init(&page_list);
	list_init(&swap_list);
	list_init(&prevent_list);
	list_init(&lazy_list);
}

void swap_out(){
	bool is_mmaped;
	size_t empty_slot;
	struct sptable *victim,*tmp;
	struct mmap_descriptor *tmp2;
	struct list_elem *e;

	sema_down(&swap_sema);
	empty_slot = bitmap_scan_and_flip(swap_bitmap,0,1,false);
	sema_up(&swap_sema);
	ASSERT(empty_slot != BITMAP_ERROR);

	tmp = (struct sptable *)malloc(sizeof(struct sptable));
	ASSERT(tmp != NULL);

	sema_down(&page_sema);
	for(int i=0; i<3; i++){
		for(e=list_begin(&page_list); e!=list_end(&page_list); e=list_next(e)){
			victim = list_entry(e,struct sptable,elem);
			if(!victim->evict) continue;
			if(i <= 1 && pagedir_is_accessed(victim->pd,victim->upage)){
				pagedir_set_accessed(victim->pd,victim->upage,false);
				continue;
			}
			break;
		}
		if(e != list_end(&page_list)) break;
	}
	ASSERT(e != list_end(&page_list));
	victim->evict = false;
	sema_up(&page_sema);

	tmp->pd = victim->pd;
	tmp->upage = victim->upage;
	tmp->kpage = victim->kpage;
	tmp->writable = victim->writable;
	tmp->swap_slot = empty_slot;

	for(int i=0; i<8; i++){
		block_write(swap_disk,empty_slot*8+i,tmp->kpage+i*512);
	}

	is_mmaped = false;
	sema_down(&mmaplist_sema);
	for(e=list_begin(&victim->thread->mmap_list); e!=list_end(&victim->thread->mmap_list); e=list_next(e)){
		tmp2 = list_entry(e,struct mmap_descriptor,elem);
		if(tmp2->upage <= victim->upage && victim->upage < tmp2->upage+tmp2->fsize){
			is_mmaped = true;
			break;
		}
	}
	sema_up(&mmaplist_sema);
	if(is_mmaped && pagedir_is_dirty(victim->pd,victim->upage)){
		sema_down(&file_sema);
		file_seek(tmp2->file_p,victim->upage-tmp2->upage);
		int small = tmp2->upage+tmp2->fsize-victim->upage;
		if(small > PGSIZE) small = PGSIZE;
		file_write(tmp2->file_p,tmp->kpage,small);
		sema_up(&file_sema);
	}

	sema_down(&swap_sema);
	list_push_back(&swap_list,&tmp->elem);
	sema_up(&swap_sema);


	pagedir_clear_page(tmp->pd,tmp->upage);
	palloc_free_page(tmp->kpage);
}

bool check_lazy(uint32_t *pd,void *upage,bool sema,bool evict){
	struct list_elem *e;
	struct lazytable *tmp;
	void *kpage;

	sema_down(&lazy_sema);
	for(e=list_begin(&lazy_list); e!=list_end(&lazy_list); e=list_next(e)){
		tmp = list_entry(e,struct lazytable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
			break;
		}
	}
	if(e != list_end(&lazy_list)){
		list_remove(e);
		sema_up(&lazy_sema);
		
		kpage = palloc_get_page(PAL_USER);
		ASSERT(kpage != NULL);
		if(tmp->read_bytes != 0){
			if(sema) sema_down(&file_sema);
			file_seek(tmp->file,tmp->ofs);
			file_read(tmp->file,kpage,tmp->read_bytes);
			if(sema) sema_up(&file_sema);
		}
		memset(kpage+tmp->read_bytes,0,tmp->zero_bytes);
		pagedir_set_page2(pd,upage,kpage,tmp->writable,evict);
		free(tmp);

		return true;
	}else{
		sema_up(&lazy_sema);

		return false;
	}
}

bool swap_in(uint32_t *pd,void *upage,bool evict){
	struct list_elem *e;
	struct sptable *tmp;

	sema_down(&swap_sema);
	for(e=list_begin(&swap_list); e!=list_end(&swap_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
			break;
		}
	}
	if(e == list_end(&swap_list)){
		sema_up(&swap_sema);
		return false;
	}
	list_remove(e);
	sema_up(&swap_sema);

	tmp->kpage = palloc_get_page(PAL_USER);
	ASSERT(tmp->kpage != NULL);

	for(int i=0; i<8; i++){
		block_read(swap_disk,tmp->swap_slot*8+i,tmp->kpage+i*512);
	}
	bitmap_set(swap_bitmap,tmp->swap_slot,false);
	pagedir_set_page2(pd,tmp->upage,tmp->kpage,tmp->writable,evict);
	free(tmp);

	return true;
}

void sptable_insert(uint32_t *pd,void *upage,void *kpage,bool writable,bool evict){
	struct sptable *tmp;

	tmp = (struct sptable*)malloc(sizeof(struct sptable));
	ASSERT(tmp != NULL);
	tmp->upage = upage;
	tmp->kpage = kpage;
	tmp->writable = writable;
	tmp->pd = pd;
	tmp->evict = evict;
	tmp->thread = thread_current();
	sema_down(&page_sema);
	list_push_back(&page_list,&tmp->elem);
	sema_up(&page_sema);
}

void sptable_remove(uint32_t *pd,void *upage){
	struct list_elem *e;
	struct sptable *tmp;

	sema_down(&page_sema);
	for(e=list_begin(&page_list); e!=list_end(&page_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
			break;
		}
	}
	ASSERT(e != list_end(&page_list));
	if(e !=list_end(&page_list)){
		list_remove(e);
		free(tmp);
	}
	sema_up(&page_sema);
}

void sptable_clean(uint32_t *pd){ // this can be important for many reasons.
	struct list_elem *e;
	struct sptable *tmp;
	struct lazytable *tmp2;

	sema_down(&page_sema);
	for(e=list_begin(&page_list); e!=list_end(&page_list);){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd) e = list_remove(e);
		else e = list_next(e);
	}
	sema_up(&page_sema);

	sema_down(&swap_sema);
	for(e=list_begin(&swap_list); e!=list_end(&swap_list);){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd){
			bitmap_set(swap_bitmap,tmp->swap_slot,false);
			e = list_remove(e);
		}else{
			e = list_next(e);
		}
	}
	sema_up(&swap_sema);

	sema_down(&prevent_sema);
	for(e=list_begin(&prevent_list); e!=list_end(&prevent_list);){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd){
			e = list_remove(e);
			free(tmp);
		}else{
			e = list_next(e);
		}
	}
	sema_up(&prevent_sema);
}

void sptable_set_evict(uint32_t *pd,void *upage,bool evict){
	struct list_elem *e;
	struct sptable *tmp;

	sema_down(&page_sema);
	for(e=list_begin(&page_list); e!=list_end(&page_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
				break;
		}
	}
	if(e != list_end(&page_list)){
		tmp->evict = evict;
	}
	sema_up(&page_sema);
}

void prevent_fault(uint32_t *pd,void *upage){
	struct list_elem *e;
	struct sptable *tmp;

	check_lazy(pd,upage,false,true);
	sema_down(&page_sema);
	for(e=list_begin(&page_list); e!=list_end(&page_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage) break;
	}
	if(e == list_end(&page_list)) tmp = NULL;
	else{
		tmp->evict = false;
	}
	sema_up(&page_sema);

	if(tmp != NULL) return;
	if(swap_in(pd,upage,false)) return;
	// future stack growth

	sema_down(&prevent_sema);
	tmp = (struct sptable *)malloc(sizeof(struct sptable));
	tmp->pd = pd;
	tmp->upage = upage;
	//list_push_back(&prevent_list,&tmp->elem);
	sema_up(&prevent_sema);
}

bool check_evict(uint32_t *pd,void *upage){
	struct list_elem *e;
	struct sptable *tmp;

	sema_down(&prevent_sema);
	for(e=list_begin(&prevent_list); e!=list_end(&prevent_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
			list_remove(e);
			free(tmp);
			sema_up(&prevent_sema);
			return false;
		}
	}
	sema_up(&prevent_sema);

	return true;
}

void lazy_loading(size_t page_read_bytes,size_t page_zero_bytes,struct file *file,void *upage,off_t ofs,bool writable){
	struct list_elem *e;
	struct lazytable *tmp;

	tmp = (struct lazytable *)malloc(sizeof(struct lazytable));
	ASSERT(tmp != NULL);
	tmp->pd = thread_current()->pagedir;
	tmp->read_bytes = page_read_bytes;
	tmp->zero_bytes = page_zero_bytes;
	tmp->file = file;
	tmp->upage = upage;
	tmp->ofs = ofs;
	tmp->writable = writable;
	sema_down(&lazy_sema);
	list_push_back(&lazy_list,&tmp->elem);
	sema_up(&lazy_sema);	
}

bool check_mapped(uint32_t *pd,void *upage){
	struct list_elem *e;
	struct sptable *tmp;
	struct lazytable *lazy_tmp;

	sema_down(&lazy_sema);
	for(e=list_begin(&lazy_list); e!=list_end(&lazy_list); e=list_next(e)){
		lazy_tmp = list_entry(e,struct lazytable,elem);
		if(lazy_tmp->pd == pd && lazy_tmp->upage == upage){
			sema_up(&lazy_sema);
			return true;
		}
	}
	sema_up(&lazy_sema);

	sema_down(&page_sema);
	for(e=list_begin(&page_list); e!=list_end(&page_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
			sema_up(&page_sema);
			return true;
		}
	}
	sema_up(&page_sema);

	sema_down(&swap_sema);
	for(e=list_begin(&swap_list); e!=list_end(&swap_list); e=list_next(e)){
		tmp = list_entry(e,struct sptable,elem);
		if(tmp->pd == pd && tmp->upage == upage){
			sema_up(&swap_sema);
			return true;
		}
	}
	sema_up(&swap_sema);

	return false;
}
