#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>

static void action(int sig, siginfo_t *si, void *context)
{
	ucontext_t *uc = context;
	struct sigcontext *sc = &uc->uc_mcontext;

	printf("pc: %#lx\n", sc->arm_pc);
	sc->arm_pc += 4;
	sc->arm_r1 = 555;
}

int main(void)
{
	struct sigaction sa = { .sa_sigaction = action, };
	int a;

	sa.sa_flags = SA_ONESHOT | SA_SIGINFO;

	sigaction(SIGILL, &sa, NULL);

	asm volatile (" mov %0, #1\r\n"
			".word 0xe7f001fb\r\n"
			: "=r"(a));
	printf("Hello world: %d\n", a);

	return 0;
}

