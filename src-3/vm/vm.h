#include "list.h"
#include "bitmap.h"
#include "filesys/off_t.h"

void vm_init();
void swap_out();
bool check_lazy(uint32_t *,void *,bool,bool);
bool swap_in(uint32_t *,void *,bool);
void sptable_insert(uint32_t *,void *,void *,bool,bool);
void sptable_remove(uint32_t *,void *);
void sptable_clean(uint32_t *);
void sptable_set_evict(uint32_t *,void *,bool);
void prevent_fault(uint32_t *,void *);
bool check_evict(uint32_t *,void *);
void lazy_loading(size_t,size_t,struct file *,void *,off_t,bool);
bool check_mapped(uint32_t *,void *);

struct list page_list;
struct semaphore page_sema;

struct sptable{
	void *upage;
	void *kpage;
	bool writable;
	int swap_slot;
	uint32_t *pd;
	bool evict;
	struct thread *thread;

	struct list_elem elem;
};

struct lazytable{
	uint32_t *pd;
	size_t read_bytes;
	size_t zero_bytes;
	struct file *file;
	void *upage;
	off_t ofs;
	bool writable;

	struct list_elem elem;
};
