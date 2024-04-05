// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__
#include <errno.h>
#include <linux/elf.h>
#include <linux/futex.h>
#include <time.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <setjmp.h>
#include <linux/types.h>
#include "../kselftest.h"

/*
 * need those definition for manually build using gcc.
 * gcc -mxsave  -o sig_overrite_sp -O2 -g -std=gnu99 -pthread -Wall ./sig_overwrite_sp.c -lrt -ldl -lm
 */
#define FAIL_TEST_IF_FALSE(c) do {\
                if (!(c)) {\
                        ksft_test_result_fail("%s, line:%d\n", __func__, __LINE__);\
                        goto test_end;\
                } \
        } \
        while (0)

#define SKIP_TEST_IF_FALSE(c) do {\
                if (!(c)) {\
                        ksft_test_result_skip("%s, line:%d\n", __func__, __LINE__);\
                        goto test_end;\
                } \
        } \
        while (0)


#define TEST_END_CHECK() {\
                ksft_test_result_pass("%s\n", __func__);\
                return;\
test_end:\
                return;\
}

#ifndef u16
#define u16 __u16
#endif

#ifndef u32
#define u32 __u32
#endif

#ifndef u64
#define u64 __u64
#endif


int sigaltstack_size = 2 * 1024 * 1024;
void *addr1 = (void *)0x5000000;
void *addr2;

void asm_handler(int);

__asm__(
	".global asm_handle\n"
	"asm_handler:\n"
	"	xor %eax, %eax\n"
	"	xor %ecx, %ecx\n"
	"	xor %edx, %edx\n"
	"	wrpkru\n"
	"	call inner\n"
	"	ret\n"
);

static inline u32 read_pkru(void)
{
	unsigned int eax, edx;
	unsigned int ecx = 0;
	unsigned pkey_reg;

	asm volatile(".byte 0x0f,0x01,0xee\n\t"
		     : "=a" (eax), "=d" (edx)
		     : "c" (ecx));
	pkey_reg = eax;
	return pkey_reg;
}

static inline void write_pkru(u64 pkey_reg)
{
	unsigned int eax = pkey_reg;
	unsigned int ecx = 0;
	unsigned int edx = 0;

	asm volatile(".byte 0x0f,0x01,0xef\n\t"
		     : : "a" (eax), "c" (ecx), "d" (edx));
	assert(pkey_reg == read_pkru());
}

int g_pkey;
void inner()
{
        void *ptr;
    	unsigned long sp;

        __asm__ volatile (
            "mov %%rsp, %0"
            : "=r"(sp)
        );

	/*
	 * the uc.uc_stack offset,
	 * it is unclear if this change according to CPU config.
	 * in 5.15, it is f390,
	 * in 6.8.0 (with shadow stack, it is 1ff390.
	 * search for restore_altstack in rt_sigreturn
	 * printk(KERN_DEBUG "restore_altstack, uc_stack=%px pid=%d", &frame->uc.uc_stack, task_pid_nr(current));
	 */
	unsigned long uc_stack_offset = 0x1ff390;
	stack_t *stack = (stack_t *) ((char*) addr1 + uc_stack_offset);
	printf("uc.uc_stack=%p, ss_sp=%p size=%lx\n", stack, stack->ss_sp, stack->ss_size);

	printf("inner:sp=%lx, ", sp);
	if (sp >= (unsigned long ) addr1 && sp < (unsigned long) addr1 + sigaltstack_size) {
		printf("in first altstack\n");
		/*
		 * allocate a new memory
		 */
		ptr = mmap(0, sigaltstack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		addr2 = ptr;

		/*
		 * overwrite the sigframe.
		 */
		stack->ss_sp = ptr;
		stack->ss_size = sigaltstack_size;
		printf("change sigaltstack address to addr2=%lx\n", (unsigned long) addr2);
	}
	else if (sp >= (unsigned long ) addr2 && sp < (unsigned long) addr2 + sigaltstack_size) {
		printf("in the second altstack\n");
		assert(stack->ss_size == sigaltstack_size);
		assert(stack->ss_sp == addr2);
	}
	else {
		printf("something went wrong\n");
		assert(0);
	}
}

void setup_fixed_address_with_pkey(int size, void *addr, int *pkeyOut,
					  void **ptrOut)
{
	int pkey;
	void *ptr;
	int ret;

	pkey = pkey_alloc(0, 0);
	assert(pkey > 0);

	ptr = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	assert(ptr == addr);

	ret = pkey_mprotect((void *)ptr, size, PROT_READ | PROT_WRITE, pkey);
	assert(!ret);

	*pkeyOut = pkey;
	*ptrOut = ptr;
}

void setup_sigusr1()
{
	void * ptr;
	stack_t altstack;

	setup_fixed_address_with_pkey(sigaltstack_size, addr1, &g_pkey, &ptr);
	printf("use pkey=%x\n", g_pkey);

	altstack.ss_sp = ptr;
	assert(altstack.ss_sp != 0);
	altstack.ss_flags = 0;
	altstack.ss_size = sigaltstack_size;

	int ret = sigaltstack(&altstack, NULL);
	assert(ret == 0);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = asm_handler;
	sa.sa_flags = SA_ONSTACK | SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR1, &sa, NULL);
	assert(ret == 0);
}

/*
 * The sigaltstack is stored inside sigframe, and rt_sigreturn
 * calls restore_altstack.
 * So user provided signal handler can modify the ss_stack and ss_size
 * directly if they knows the offset, and the new ss_stack ss_size will
 * be saved to the current task_struct during rt_sigreturn. The next
 * signal handled by this thread will use  the new ss_stack.
 */
void test_sigaltstack_pkey_overwrite_altstack()
{
	int pkru_orig, pkru;
	int status;

	setup_sigusr1();

	status = pkey_set(g_pkey, 0);
	assert(!status);

	pkru_orig = read_pkru();
	printf("PKRU(before):%x, pid:%d\n", pkru_orig, getpid());

	int ret = raise(SIGUSR1);
        FAIL_TEST_IF_FALSE(ret == 0);

	pkru = read_pkru();
	printf("PKRU(after):%x, pid:%d\n", pkru, getpid());

        FAIL_TEST_IF_FALSE(pkru_orig == pkru);

	ret = raise(SIGUSR1);
        FAIL_TEST_IF_FALSE(ret == 0);

        TEST_END_CHECK();
}

int main(void)
{
        ksft_print_header();
        ksft_print_msg("pid=%d\n", getpid());

	if (pkey_alloc(0, 0) <= 0)
                ksft_exit_skip("pkey not supported \n");

        ksft_set_plan(1);

	test_sigaltstack_pkey_overwrite_altstack();

	return 0;
}
