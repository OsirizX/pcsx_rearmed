/*
 * Simple test of using an alternate buffer for the code.
 */

#include <lightning.h>
#include <stdio.h>
#include <assert.h>
#include <sys/mman.h>
#if defined(__sgi)
#  include <fcntl.h>
#endif

#ifndef MAP_ANON
#  define MAP_ANON			MAP_ANONYMOUS
#  ifndef MAP_ANONYMOUS
#    define MAP_ANONYMOUS		0
#  endif
#endif

#if !defined(__sgi)
#define  mmap_fd			-1
#endif

int
main(int argc, char *argv[])
{
    jit_uint8_t		 *ptr;
    jit_state_t		 *_jit;
    jit_word_t		  length;
#if defined(__sgi)
    int			  mmap_fd;
#endif
    void		(*function)(void);
    int			  mmap_prot, mmap_flags;

#if defined(__sgi)
    mmap_fd = open("/dev/zero", O_RDWR);
#endif

    mmap_prot = PROT_READ | PROT_WRITE;
#if !__OpenBSD__
    mmap_prot |= PROT_EXEC;
#endif
#if __NetBSD__
    mmap_prot = PROT_MPROTECT(mmap_prot);
    mmap_flags = 0;
#else
    mmap_flags = MAP_PRIVATE;
#endif
    mmap_flags |= MAP_ANON;
    ptr = mmap(NULL, 1024 * 1024,  mmap_prot, mmap_flags, mmap_fd, 0);
    assert(ptr != MAP_FAILED);
#if defined(__sgi)
    close(mmap_fd);
#endif

    init_jit(argv[0]);
    _jit = jit_new_state();

    jit_prolog();
    jit_prepare();
    jit_pushargi((jit_word_t)"%s\n");
    jit_ellipsis();
    jit_pushargi((jit_word_t)"ok");
    jit_finishi(printf);

    /* call to jit_realize() is only required when using an alternate
     * code buffer. Note that not using mmap'ed memory may not work
     * on several ports and/or operating system versions */
    jit_realize();

    length = 0;
    if (jit_get_code(&length) != NULL)
	abort();

    if (length <= 4)
	abort();

    /* check that a too small buffer fails */
    jit_set_code(ptr, 4);
    function = jit_emit();
    if (function != NULL)
	abort();

#if __NetBSD__
    assert(mprotect(ptr, 1024 * 1024, PROT_READ | PROT_WRITE) == 0);
#endif
    /* and calling again with enough space works */
    jit_set_code(ptr, 1024 * 1024);
    function = jit_emit();
    if (function == NULL)
	abort();

    jit_clear_state();
#if __NetBSD__ ||  __OpenBSD__
    assert(mprotect(ptr, 1024 * 1024, PROT_READ | PROT_EXEC) == 0);
#endif
    (*function)();
    jit_destroy_state();
    finish_jit();

    munmap(ptr, 1024 * 1024);

    return (0);
}
