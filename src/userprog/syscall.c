#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "string.h"
#include <filesys/file.h>
#include <devices/input.h>
#include <kernel/stdio.h>
#include <filesys/filesys.h>
#include "pagedir.h"
#define ARGUMENT_OFFSET 4

static void syscall_handler (struct intr_frame *);
static bool validate_address(void *vaddr);
static void handle_exit (struct intr_frame *);
static void handle_exec (struct intr_frame *);
static void handle_wait (struct intr_frame *);
static void handle_file_create(struct intr_frame *);
static void handle_file_remove(struct intr_frame *);
static void handle_file_open(struct intr_frame *);
static void handle_file_size(struct intr_frame *);
static void handle_file_read(struct intr_frame *);
static void handle_file_write(struct intr_frame *);
static void handle_file_seek(struct intr_frame *);
static void handle_file_tell(struct intr_frame *);
static void handle_file_close(struct intr_frame *);


static bool validate_address(void *vaddr){
    return is_kernel_vaddr(vaddr)
    || pagedir_get_page(thread_current()->pagedir, vaddr) == NULL
    || is_kernel_vaddr(vaddr + sizeof(uint32_t*))
    || pagedir_get_page(thread_current()->pagedir, vaddr + sizeof(uint32_t *)) == NULL
    || !is_user_vaddr(vaddr)
    || !is_user_vaddr(vaddr + sizeof(uint32_t *));

}
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
handle_exit (struct intr_frame *f){
    if(validate_address((int *)((f->esp + ARGUMENT_OFFSET)))){
        thread_exit_with_status(-1);
    }
    int status = *( (int *) ((f->esp + ARGUMENT_OFFSET)));

    
    thread_exit_with_status(status);



}

static void
handle_exec (struct intr_frame *f){
    if(validate_address((int *)((f->esp + ARGUMENT_OFFSET)))){
        thread_exit_with_status(-1);
    }



    char *file_name = *( (char **) ((f->esp + ARGUMENT_OFFSET)));

    if(file_name == NULL || validate_address(file_name)){
        thread_exit_with_status(-1);
    }

    f->eax = process_execute(file_name);





}

static void handle_wait (struct intr_frame *f){
    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    tid_t child_pid = *( (tid_t *) ((f->esp + ARGUMENT_OFFSET)));
    int exit_status = process_wait(child_pid);

    
    
    f->eax = exit_status;
}

static void handle_file_create(struct intr_frame *f){
    if(validate_address((int *)(f->esp + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    char *file_name = *( (char **) ((f->esp + ARGUMENT_OFFSET)));

    if (file_name == NULL || validate_address(file_name)){
        thread_exit_with_status(-1);
    }

    if(validate_address((int *) ((f->esp) + ARGUMENT_OFFSET * 2))){
        thread_exit_with_status(-1);
    }



    uint32_t initial_size = *( (int *) ((f->esp) + ARGUMENT_OFFSET * 2));

    f->eax = filesys_create(file_name, initial_size);
}

static void handle_file_remove(struct intr_frame *f){
    if(validate_address((int *)((f->esp + ARGUMENT_OFFSET)))){
        thread_exit_with_status(-1);
    }

    char *file_name = *( (char **) (f->esp + ARGUMENT_OFFSET));

    if (file_name == NULL || validate_address(file_name)){
        thread_exit_with_status(-1);
    }
    
    f->eax = filesys_remove(file_name);
}

static void handle_file_open(struct intr_frame *f){

    if(validate_address((int *)((f->esp + ARGUMENT_OFFSET)))){
        thread_exit_with_status(-1);
    }

    char *file_name = *( (char **) ((f->esp + ARGUMENT_OFFSET)));
    if (file_name == NULL || validate_address(file_name)){
        thread_exit_with_status(-1);
    }

    struct file *file = filesys_open(file_name);

    

    if(file == NULL){
        (f->eax) = -1;
        return;
    }


    thread_current()->file_counter++;
    uint32_t fd = thread_current()->file_counter;

    file->fd = fd;
    file->file_name = file_name;

    list_push_back(&thread_current()->file_descriptors, &file->fd_elem);

    if(strcmp(file_name, thread_current()->name) == 0){
        file_deny_write(file);
    }

    (f->eax) = fd;
}

static void handle_file_size(struct intr_frame *f){
    if(validate_address((int *)((f->esp + ARGUMENT_OFFSET)))){
        thread_exit_with_status(-1);
    }

    int fd = *( (int *) ((f->esp + ARGUMENT_OFFSET)));

    struct file *file = get_file_by_fd(fd, thread_current());

    f->eax = file_length(file);
}

static void handle_file_read(struct intr_frame *f){
    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    int fd = *( (int*) ((f->esp + ARGUMENT_OFFSET)));

    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET * 2))){
        thread_exit_with_status(-1);
    }
    void *buffer = *( (void **) ((f->esp + ARGUMENT_OFFSET * 2)));

    if(buffer == NULL || validate_address(buffer))
        thread_exit_with_status(-1);

    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET * 3))){
        thread_exit_with_status(-1);
    }
    uint32_t size = *( (uint32_t *) ((f->esp + ARGUMENT_OFFSET * 3)));


    if(fd == 0){
        uint32_t read_size = 0;
        uint8_t c = input_getc();
        while(1){
            if(c == '\0' || read_size >= size) break;
            read_size++;
        }
        f->eax = read_size;
    }else{
        struct file *file = get_file_by_fd(fd, thread_current());
        if(file == NULL)
            thread_exit_with_status(-1);
        f->eax = file_read(file, buffer, size);
    }
}

static void handle_file_write(struct intr_frame *f){
    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    int fd = *( (int*) ((f->esp + ARGUMENT_OFFSET)));


    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET * 2)) ){
        thread_exit_with_status(-1);
    }
    void *buffer = *( (void **) ((f->esp + ARGUMENT_OFFSET * 2)));
    if(buffer == NULL || validate_address(buffer))
        thread_exit_with_status(-1);

    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET * 3))){
        thread_exit_with_status(-1);
    }
    uint32_t size = *( (uint32_t *) ((f->esp + ARGUMENT_OFFSET * 3)));
    char *name = thread_current()->name;
    // split by space to get the name


    char *save_ptr;
    name = strtok_r(name, " ", &save_ptr);


    
    if(fd == 1){
        putbuf((char *)buffer, size);
        f->eax = size;
    }else{
        struct file *file = get_file_by_fd(fd, thread_current());

        if(file == NULL)
            thread_exit_with_status(-1);
        if (file->deny_write || strcmp(file->file_name, name) == 0){
            
            f->eax = 0;
        }else{

            f->eax = file_write(file, buffer, size);
        }
    }
}

static void handle_file_seek(struct intr_frame *f){
    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    int fd = *( (int *) ((f->esp + ARGUMENT_OFFSET)));
    struct file *file = get_file_by_fd(fd, thread_current());

    if(file == NULL)
        thread_exit_with_status(-1);

    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET * 2))){
        thread_exit_with_status(-1);
    }

    uint32_t position = *( (uint32_t *) ((f->esp + ARGUMENT_OFFSET * 2)));

    file_seek(file, position);
}

static void handle_file_tell(struct intr_frame *f){
    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    int fd = *( (int *) ((f->esp + ARGUMENT_OFFSET)));
    struct file *file = get_file_by_fd(fd, thread_current());

    if(file == NULL)
        thread_exit_with_status(-1);

    f->eax = file_tell(file);
}


static void handle_file_close(struct intr_frame *f){
    if(validate_address((int *)((f->esp) + ARGUMENT_OFFSET))){
        thread_exit_with_status(-1);
    }

    int fd = *( (int *) ((f->esp + ARGUMENT_OFFSET)));
    struct file *file = get_file_by_fd(fd, thread_current());
    if(file == NULL || fd == 1 || fd == 0){
        thread_exit_with_status(-1);
    }
    list_remove(&file->fd_elem);
    // file_allow_write(file);
    file_close(file);
}




static void
syscall_handler (struct intr_frame *f)
{



    if(validate_address(f->esp)){
        thread_exit_with_status(-1);
    }

    int syscall_num = *(int *)f->esp;
    switch(syscall_num){
        case SYS_HALT: shutdown_power_off();break;
        case SYS_EXIT: handle_exit(f);break;
        case SYS_EXEC: handle_exec(f);break;
        case SYS_WAIT: handle_wait(f);break;
        case SYS_CREATE: handle_file_create(f);break;
        case SYS_REMOVE: handle_file_remove(f);break;
        case SYS_OPEN: handle_file_open(f);break;
        case SYS_FILESIZE: handle_file_size(f);break;
        case SYS_READ: handle_file_read(f);break;
        case SYS_WRITE: handle_file_write(f);break;
        case SYS_SEEK: handle_file_seek(f);break;
        case SYS_TELL: handle_file_tell(f);break;
        case SYS_CLOSE: handle_file_close(f);break;


        default: printf ("system call: %i\n", syscall_num);
    }


}
