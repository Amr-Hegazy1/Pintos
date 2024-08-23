#ifndef VM_FRAMETABLE_H
#define VM_FRAMETABLE_H


void frametable_init(void);

void frametable_add_frame(uint8_t *, uint8_t *, struct thread *);


#endif