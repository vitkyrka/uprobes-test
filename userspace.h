#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <err.h>
#include <linux/ptrace.h>
#include "list.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef u32 kprobe_opcode_t;

struct kprobe {
	unsigned int flags;
	void *addr;
	struct list_head list;
	unsigned int originsn;
	int (*pre_handler)(struct kprobe *p, struct pt_regs *regs);
	void (*post_handler)(struct kprobe *p, struct pt_regs *regs,
							unsigned long flags);
};

int register_kprobe(struct kprobe *kprobe);
int register_uprobe(struct kprobe *kprobe);

void unregister_kprobe(struct kprobe *kprobe);
void unregister_uprobe(struct kprobe *kprobe);

union decode_item {
	int a;
};
union decode_item a;
#define kprobe_decode_arm_table NULL

#define pr_err(x...) printf("ERROR:" x)
#define pr_info(x...) printf(x)

#define BUG()	*(volatile int *)0x1=0


#define __used __attribute__((used))
#define __naked __attribute__((naked))
#define __kprobes
#define __init
#define late_initcall(x)

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ALIGN(x, a)		__ALIGN_KERNEL((x), (a))
#define __ALIGN_MASK(x, mask)	__ALIGN_KERNEL_MASK((x), (mask))
#define PTR_ALIGN(p, a)		((typeof(p))ALIGN((unsigned long)(p), (a)))

#define ARM_OPCODE_CONDTEST_FAIL   0
#define ARM_OPCODE_CONDTEST_PASS   1
#define ARM_OPCODE_CONDTEST_UNCOND 2

#define __LINUX_ARM_ARCH__ 7

unsigned int arm_check_condition(u32 opcode, u32 psr);

/*
 *  * ARMv7 groups of PSR bits
 *   */
#define APSR_MASK	0xf80f0000	/* N, Z, C, V, Q and GE flags */
#define PSR_ISET_MASK	0x01000010	/* ISA state (J, T) mask */
#define PSR_IT_MASK	0x0600fc00	/* If-Then execution state mask */
#define PSR_ENDIAN_MASK	0x00000200	/* Endianness state mask */

void probes_init(void);
