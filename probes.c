#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/mman.h>

#include "userspace.h"

static LIST_HEAD(kprobes);

static void patch_text(unsigned int *addr, unsigned int insn)
{
	void *aligned  = (void *) ((uintptr_t) addr & ~4095);

	mprotect(aligned, 4,
		 PROT_READ | PROT_WRITE | PROT_EXEC);

	*addr = insn;

	__builtin___clear_cache(aligned, aligned + 4);

	mprotect(aligned, 4,
		 PROT_READ | PROT_EXEC);
}

int register_kprobe(struct kprobe *kprobe)
{
	unsigned int *pinsn = (unsigned int *)kprobe->addr;

	kprobe->originsn = *pinsn;

	patch_text(pinsn, 0xe7f001fb);

	list_add_tail(&kprobe->list, &kprobes);

	return 0;
}

void unregister_kprobe(struct kprobe *kprobe)
{
	unsigned int *pinsn = (unsigned int *)kprobe->addr;
	
	list_del_init(&kprobe->list);
	patch_text(pinsn, kprobe->originsn);
}

#define S2P(x, y) x = y
#define P2S(x, y) y = x

void sig2pt(struct sigcontext *sc, struct pt_regs *regs)
{
	S2P(regs->uregs[0], sc->arm_r0);
	S2P(regs->uregs[1], sc->arm_r1);
	S2P(regs->uregs[2], sc->arm_r2);
	S2P(regs->uregs[3], sc->arm_r3);
	S2P(regs->uregs[4], sc->arm_r4);
	S2P(regs->uregs[5], sc->arm_r5);
	S2P(regs->uregs[6], sc->arm_r6);
	S2P(regs->uregs[7], sc->arm_r7);
	S2P(regs->uregs[8], sc->arm_r8);
	S2P(regs->uregs[9], sc->arm_r9);
	S2P(regs->uregs[10], sc->arm_r10);
	S2P(regs->uregs[11], sc->arm_fp);
	S2P(regs->uregs[12], sc->arm_ip);
	S2P(regs->uregs[13], sc->arm_sp);
	S2P(regs->uregs[14], sc->arm_lr);
	S2P(regs->uregs[15], sc->arm_pc);
	S2P(regs->uregs[16], sc->arm_cpsr);
}

void pt2sig(struct pt_regs *regs, struct sigcontext *sc)
{
	P2S(regs->uregs[0], sc->arm_r0);
	P2S(regs->uregs[1], sc->arm_r1);
	P2S(regs->uregs[2], sc->arm_r2);
	P2S(regs->uregs[3], sc->arm_r3);
	P2S(regs->uregs[4], sc->arm_r4);
	P2S(regs->uregs[5], sc->arm_r5);
	P2S(regs->uregs[6], sc->arm_r6);
	P2S(regs->uregs[7], sc->arm_r7);
	P2S(regs->uregs[8], sc->arm_r8);
	P2S(regs->uregs[9], sc->arm_r9);
	P2S(regs->uregs[10], sc->arm_r10);
	P2S(regs->uregs[11], sc->arm_fp);
	P2S(regs->uregs[12], sc->arm_ip);
	P2S(regs->uregs[13], sc->arm_sp);
	P2S(regs->uregs[14], sc->arm_lr);
	P2S(regs->uregs[15], sc->arm_pc);
	P2S(regs->uregs[16], sc->arm_cpsr);
}

static void action(int sig, siginfo_t *si, void *context)
{
	ucontext_t *uc = context;
	struct sigcontext *sc = &uc->uc_mcontext;
	struct pt_regs regs = {{0}};
	struct kprobe *kprobe;
	bool found = false;
	void *pc = (void *) sc->arm_pc;

	sig2pt(sc, &regs);

	list_for_each_entry(kprobe, &kprobes, list) {
		if (kprobe->addr != pc)
			continue;

		if (kprobe->pre_handler)
			kprobe->pre_handler(kprobe, &regs);

		if (kprobe->post_handler)
			kprobe->post_handler(kprobe, &regs, 0);
		
		found = true;
		break;
	}

	if (!found)
		kill(getpid(), SIGABRT);

	pt2sig(&regs, sc);
	sc->arm_pc += 4;
}

void probes_init(void)
{
	struct sigaction sa = { .sa_sigaction = action, };

	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGILL, &sa, NULL);
}
