/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Zkl (KLE, Cryptographic Lockers) task context support (prototype).
 */

#ifndef _ASM_RISCV_KLE_H
#define _ASM_RISCV_KLE_H

#include <linux/sched.h>
#include <asm/cpufeature.h>
#include <asm/csr.h>
#include <asm/ptrace.h>

#ifdef CONFIG_RISCV_ISA_ZKL

static __always_inline bool has_kle(void)
{
	return riscv_has_extension_unlikely(RISCV_ISA_EXT_ZKL);
}

void riscv_kle_switch(struct task_struct *prev, struct task_struct *next);
bool riscv_kle_first_use_handler(struct pt_regs *regs);
bool riscv_kle_off_handler(struct pt_regs *regs);
void riscv_kle_flush_thread(void);
void riscv_kle_thread_free(struct task_struct *tsk);

static inline void riscv_kle_off(struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_KLS) | SR_KLS_OFF;
}

#else

static __always_inline bool has_kle(void) { return false; }
static inline void riscv_kle_switch(struct task_struct *prev,
				     struct task_struct *next) { }
static inline bool riscv_kle_first_use_handler(struct pt_regs *regs)
{
	return false;
}
static inline bool riscv_kle_off_handler(struct pt_regs *regs)
{
	return false;
}
static inline void riscv_kle_flush_thread(void) { }
static inline void riscv_kle_thread_free(struct task_struct *tsk) { }
static inline void riscv_kle_off(struct pt_regs *regs) { }

#endif

#endif /* _ASM_RISCV_KLE_H */
