#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/syscall.h>


#define _write(fd, buf, size)              \
    ({                                     \
       int64_t __ret;                      \
                                           \
       __asm__ volatile                    \
       (                                   \
        "movq %0, %%rdi  \n\t"             \
        "movq %1, %%rsi  \n\t"             \
        "movq %2, %%rdx  \n\t"             \
        "movq %3, %%rax  \n\t"             \
        "syscall"                          \
        :                                  \
        : "g" (fd), "g" (buf), "g" (size), \
          "g" ((uint64_t)SYS_write)        \
        );                                 \
                                           \
       __asm__ volatile                    \
       (                                   \
        "movq %%rax, %0  \n\t"             \
        : "=g" (__ret)                     \
       );                                  \
                                           \
       __ret;                              \
    })

void evilprnt()
{
    __asm__ volatile
    (
     "pushq %rdi \n\t"
     "pushq %rsi \n\t"
     "pushq %rdx \n\t"
     "pushq %rcx \n\t"
     "pushq %r8  \n\t"
     "pushq %r9  \n\t"
    );


    char buf[4];
    buf[0] = '\x34';
    buf[1] = '\x32';
    buf[2] = '\x0a';
    buf[3] = '\x00';
    
    
    _write((uint64_t)STDIN_FILENO, buf, (uint64_t)sizeof(buf));

    
    __asm__ volatile
    (
     "popq %r9  \n\t" 
     "popq %r8  \n\t"
     "popq %rcx \n\t"
     "popq %rdx \n\t"
     "popq %rsi \n\t"
     "popq %rdi \n\t"
    );
    
    __asm__ volatile
    (
     "movq $0xbadf00ddeadbabe, %rax \n\t"
     "jmp  *%rax                    \n\t"
    );

    __asm__ volatile
    (
     ".byte 0xbe, 0xba, 0xfe, 0xca \n\t"
     ".byte 0xef, 0xbe, 0xad, 0xde \n\t"
    );
}
