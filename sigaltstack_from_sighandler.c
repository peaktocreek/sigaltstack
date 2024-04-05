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
 * gcc -mxsave  -o sigaltstack_from_sighandler -O2 -g -std=gnu99 -pthread -Wall ./sigaltstack_from_sighandler.c -lrt -ldl -lm
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
bool sigaltstack_called = false;


void inner()
{
	stack_t altstack;
	void * ptr;
	ptr = mmap(addr1, sigaltstack_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE |MAP_FIXED, -1, 0);
	assert(ptr == addr1);

	altstack.ss_sp = addr1;
	altstack.ss_size = sigaltstack_size;
	altstack.ss_flags = SS_ONSTACK;
	int ret = sigaltstack(&altstack, NULL);
	if (ret != 0)
	    printf("sigaltstack(%lx) failed inside signal_handler\n", (unsigned long) addr1);
	else
	    printf("sigaltstack(%lx) succeed inside signal handler\n", (unsigned long) addr1);
}

static void usr1_handler(int sig, siginfo_t *siginfo, void *ptr) 
{ 
    	unsigned long sp;
	int ret;

        __asm__ volatile (
            "mov %%rsp, %0"
            : "=r"(sp)
        );


	if (sp > addr1 && sp <= addr1 + sigaltstack_size) {
		printf("usr1_handler:sp (%lx) on altstack\n", sp);
		assert(0);
	}
	else {
		printf("usr1_handler:sp (%lx) on normal stack\n", sp);
	}

	if (sigaltstack_called == false) {

		sigaltstack_called = true;
		inner();

		/*
		 * USR2 will be handled inside altstack
		 * this is because usr2_handler is called inside raise, or before
		 * current handler return, note: this is different han USR1 below
		 */
		printf("raise USR2\n");
		ret = raise(SIGUSR2);
		assert(ret == 0);

		/*
		 * raise USR1, this will cause a endless loop
		 * the sigaltstack_called is not enough protection for reentry.
		 * this means the raise just put signal to some queue, then
		 * next usr1_handler will be called after current function return.
		 */
		//printf("raise USR1\n");
		//ret = raise(SIGUSR1);
		//assert(ret == 0);

		sigaltstack_called = false;
	}
	printf("return from usr1_handler\n", sp);
}

static void usr2_handler(int sig, siginfo_t *siginfo, void *ptr) 
{ 
    	unsigned long sp;

        __asm__ volatile (
            "mov %%rsp, %0"
            : "=r"(sp)
        );


	if (sp > addr1 && sp <= addr1 + sigaltstack_size) {
		printf("usr2_handler:sp (%lx) on altstack\n", sp);
		assert(sigaltstack_called == true);
	}
	else {
		printf("usr2_handler:sp (%lx) on normal stack\n", sp);
		assert(sigaltstack_called == false);
	}

	printf("return from usr2_handler\n", sp);
}

void setup_fixed_address(int size, void *addr, void **ptrOut)
{
	void *ptr;
	stack_t altstack;

	ptr = mmap(addr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	assert(ptr == addr);

	*ptrOut = ptr;
}

void setup_sigusr1()
{
	struct sigaction sa;
	int ret;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = usr1_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR1, &sa, NULL);
	assert(ret == 0);
}

void setup_sigusr2()
{
	struct sigaction sa;
	int ret;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = usr2_handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&sa.sa_mask);
	ret = sigaction(SIGUSR2, &sa, NULL);
	assert(ret == 0);
}

/*
 * this test is used to observe how sigaltstack is used.
 * usr1 is without SA_ONSTACK, this means usr1 is always handled by normal stack.
 * usr2 is with SA_ONSTACK, so
 *    a> if sigaltstack is available, then use altstack
 *    b> if sigaltstack is not available, use normal stack.
 * in usr1_handler, call sigaltstack to setup altstack to addr1
 */

void test_sigaltstack_from_sighandler()
{
	setup_sigusr1();
	setup_sigusr2();

	/* USR2 will be handled in normal stack, since no sigaltstack yet */
	printf("raise USR2\n");
	int ret = raise(SIGUSR2);
        FAIL_TEST_IF_FALSE(ret == 0);

	/* USR1 will be handled in normal stack, call sigaltstack 
	 * usr1_handler will raise SIGUSR2, SIGUSR2 will be handled in altstack
	 */
	printf("raise USR1\n");
	ret = raise(SIGUSR1);
        FAIL_TEST_IF_FALSE(ret == 0);

	/* USR1 will be handled in normal stack, because sigaction for USR1 is not registered with SA_ONSTACK */
	printf("raise USR1\n");
	ret = raise(SIGUSR1);
        FAIL_TEST_IF_FALSE(ret == 0);

	/*
	 * USR2 will be handled in normal stack,
	 * even sigaltstack is called inside usr1_handler, however, the scope is only limited in-side usr1_handler,
         * i.e restore_altstack during rt_sigreturn will restore the thread's altstack when usr1_handler returns.
         */
	printf("raise USR2\n");
	ret = raise(SIGUSR2);
        FAIL_TEST_IF_FALSE(ret == 0);

        TEST_END_CHECK();
}

int main(void)
{
        ksft_print_header();
        ksft_print_msg("pid=%d\n", getpid());

        ksft_set_plan(1);

	test_sigaltstack_from_sighandler();

	return 0;
}
