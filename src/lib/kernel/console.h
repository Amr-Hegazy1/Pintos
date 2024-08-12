#ifndef __LIB_KERNEL_CONSOLE_H
#define __LIB_KERNEL_CONSOLE_H
#include <stdarg.h>
#include <stdio.h>

void console_init (void);
void console_panic (void);
void console_print_stats (void);


#endif /* lib/kernel/console.h */
