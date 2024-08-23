#ifndef VM_SUPPLEMENTALPAGETABLE_H
#define VM_SUPPLEMENTALPAGETABLE_H
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "lib/kernel/hash.h"


enum location{
    DISK,
    SWAP,
    FRAME
};

struct supplemental_page{
    
    uint8_t *upage;
    uint8_t *kpage;
    struct hash_elem elem;
    struct thread *thread;
    enum location loc;
    bool writable;
    struct file *file;
    size_t page_read_bytes;
    size_t page_zero_bytes;

};

struct supplemental_page_table{
    struct hash sup_page_table;
};

void supplemental_page_table_init(struct supplemental_page_table *table);
void supplemental_page_table_add_page(struct supplemental_page_table *table, uint8_t *upage, enum location loc, bool writable);
void supplemental_page_table_add_page_to_disk(struct supplemental_page_table *table, uint8_t *upage, bool writable, struct file *file, size_t page_read_bytes, size_t page_zero_bytes);

unsigned page_hash_func (const struct hash_elem *e, void *aux);
bool page_hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);


#endif