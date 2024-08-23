#include "supp_page_table.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/kernel/hash.h"


unsigned page_hash_func (const struct hash_elem *e, void *aux){
    struct supplemental_page *sp = hash_entry(e, struct supplemental_page, elem);

    return hash_int(sp->upage);
}

bool page_hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux){
    struct supplemental_page *spa = hash_entry(a, struct supplemental_page, elem);
    struct supplemental_page *spb = hash_entry(b, struct supplemental_page, elem);


    return spa->upage < spb->upage;
}


void supplemental_page_table_init(struct supplemental_page_table *table){
    hash_init(&table->sup_page_table, page_hash_func, page_hash_less_func, NULL);

}

void supplemental_page_table_add_page(struct supplemental_page_table *table, uint8_t *upage, enum location loc, bool writable){
    
    struct supplemental_page *page = malloc(sizeof(struct supplemental_page));
    page->upage = upage;
    page->loc = loc;
    page->writable = writable;
    hash_insert(&table, &page->elem);

}

void supplemental_page_table_add_page_to_disk(struct supplemental_page_table *table, uint8_t *upage, bool writable, struct file *file, size_t page_read_bytes, size_t page_zero_bytes){


    struct supplemental_page *page = malloc(sizeof(struct supplemental_page));
    page->upage = upage;
    page->loc = DISK;
    page->writable = writable;
    page->file = file;
    page->page_read_bytes = page_zero_bytes;
    hash_insert(&table, &page->elem);

}


