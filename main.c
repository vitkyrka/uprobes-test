#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <linux/ptrace.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "userspace.h"

#define DEBUGFS	"/debug"
#define TRACEBUFSZ	8192

const char *filename;
struct pt_regs regs;

static void __trace_start(bool start)
{
	char c = start ? '1' : '0';
	size_t wrote;
	FILE *f;
	int ret;

	f = fopen(DEBUGFS "/tracing/events/uprobes/enable", "w+");
	if (!f) {
		warn("fopen uprobes/events");
		return;
	}

	wrote = fwrite(&c, 1, 1, f);
	if (wrote != 1)
		err(1, "fwrite");

	ret = fclose(f);
	if (ret == EOF)
		err(1, "fclose");
}

static void trace_start(void)
{
	__trace_start(true);
}

static void trace_stop(void)
{
	__trace_start(false);
}

static void trace_function(const char *name, void *func)
{
	unsigned int addr;
	char buf[200];
	size_t wrote;
	FILE *f;
	int ret;

	addr = (intptr_t) func - 0x8000;

	f = fopen(DEBUGFS "/tracing/uprobe_events", "a");
	if (!f)
		err(1, "fopen");

	ret = snprintf(buf, sizeof(buf), "p:%s %s:%#x R0=%%r0 R1=%%r1 R2=%%r2 R3=%%r3 R4=%%r4 R5=%%r5 R6=%%r6 R7=%%r7 R8=%%r8 R9=%%r9 R10=%%r10 R11=%%fp R12=%%ip R13=%%sp R14=%%lr R15=%%pc CPSR=%%cpsr",
		 name,
		 filename,
		 addr);

	wrote = fwrite(buf, 1, ret, f);
	if (wrote != ret)
		err(1, "fwrite");

	ret = fclose(f);
	if (ret == EOF)
		err(1, "fclose");
}

static void trace_clear(void)
{
	FILE *f;
	int ret;

	f = fopen(DEBUGFS "/tracing/trace", "w+");
	if (!f)
		err(1, "fopen");

	ret = fclose(f);
	if (ret == EOF)
		err(1, "fclose");
}

static void trace_nothing(void)
{
	FILE *f;
	int ret;

	f = fopen(DEBUGFS "/tracing/uprobe_events", "w+");
	if (!f)
		err(1, "fopen");

	ret = fclose(f);
	if (ret == EOF)
		err(1, "fclose");
}

static int __trace_process(char *buf, char *name, struct pt_regs *regs)
{
	char *p = buf;
	unsigned int addr;
	int ret;

	p = strstr(buf, name);
	if (!p) {
		errno = ENOENT;
		return -1;
	}

#define REGFMT " %*[^=]=%lx"

	ret = sscanf(p,"%*s (%x)"
			REGFMT REGFMT REGFMT REGFMT REGFMT REGFMT REGFMT
			REGFMT REGFMT REGFMT REGFMT REGFMT REGFMT REGFMT
			REGFMT REGFMT,
		       &addr,
		       &(regs->uregs[0]), &(regs->uregs[1]),
		       &(regs->uregs[2]), &(regs->uregs[3]),
		       &(regs->uregs[4]), &(regs->uregs[5]),
		       &(regs->uregs[6]), &(regs->uregs[7]),
		       &(regs->uregs[8]), &(regs->uregs[9]),
		       &(regs->uregs[10]), &(regs->uregs[11]),
		       &(regs->uregs[12]), &(regs->uregs[13]),
		       &(regs->uregs[14]), &(regs->uregs[15]));
	if (ret != 17) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

static struct kprobe *testcase_kprobe;

#include <fcntl.h>

void trace_process(void)
{
	char buf[TRACEBUFSZ];
	size_t bytes;
	FILE *f;
	int ret;

	if (!testcase_kprobe)
		return;
	
	f = fopen(DEBUGFS "/tracing/trace_pipe", "r");
	if (!f)
		err(1, "fopen");

	fcntl(fileno(f), F_SETFL, O_NONBLOCK);

	bytes = fread(buf, 1, sizeof(buf) - 1, f);
	if (bytes == 0 && errno != EAGAIN)
		err(1, "fread");

	buf[bytes] = '\0';

	fclose(f);

	ret = __trace_process(buf, "testcase", &regs);
	if (ret) {
		// warn("test_before");
	} else {
		testcase_kprobe->pre_handler(testcase_kprobe, &regs);
	}
}

int register_uprobe(struct kprobe *kprobe)
{
	testcase_kprobe = kprobe;

	trace_function("testcase", kprobe->addr);
	trace_start();

	return 0;
}

void unregister_uprobe(struct kprobe *kprobe)
{
	testcase_kprobe = NULL;
	trace_stop();
	trace_nothing();
	// trace_clear();
}


void __attribute__((noinline)) hello(void)
{
	asm volatile ("nop");
}

extern void kprobe_arm_test_cases(void);

int main(int argc, char *argv[])
{
	filename = argv[0];

	trace_stop();
	trace_nothing();
	trace_clear();

#if 0
	trace_function("hello", &hello);
	trace_function("trace_stop", &trace_stop);

	trace_start();
	hello();
	trace_stop();
#endif

	probes_init();
	kprobe_arm_test_cases();

//	trace_process();

	return 0;
}
