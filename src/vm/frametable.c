#include "frametable.h"
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

struct hash frame_table;

struct frame{
    uint8_t *upage;
    uint8_t *kpage;
    struct hash_elem elem;
    struct thread *thread;

};

unsigned frame_hash_func (const struct hash_elem *e, void *aux){
    struct frame *sp = hash_entry(e, struct frame, elem);

    return hash_int(sp->kpage);
}

bool frame_hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux){
    struct frame *frameA = hash_entry(a, struct frame, elem);
    struct frame *frameB = hash_entry(b, struct frame, elem);


    return frameA->kpage < frameB->kpage;
}


void framtable_init(){
    hash_init(&frame_table, frame_hash_func, frame_hash_less_func, NULL);

}

void frametable_add_frame( uint8_t *upage, uint8_t *kpage, struct thread *thread){
    struct frame *frame = malloc(sizeof(struct frame));
    frame->upage = upage;
    frame->kpage = kpage;
    frame->thread = thread;
    hash_insert(&frame_table, &frame->elem);
}