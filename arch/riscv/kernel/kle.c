// SPDX-License-Identifier: GPL-2.0-only
/*
 * Zkl (KLE, Cryptographic Lockers) task context support (prototype).
 *
 * The 32 lockers, klstart, klnamedlocker and the SIV/IMPQUAL/SIV2
 * registers are per-hart state.  Each user task that uses KLE owns them
 * while it runs: on a context switch the outgoing task's lockers are
 * exported (as SCCs, or as PCCCs for lockers under management) into its
 * thread context and the hart is cleared; the incoming task's images are
 * imported again.  The save and restore orders are those of "Context
 * Switching, KLE State Save and Restore Order" in Zkl-ISA-unpriv.adoc.
 *
 * Tasks start with sstatus.KLS = Off; the first KLE instruction traps
 * and enables KLE for the task, as for the V extension.  A new thread or
 * a forked child starts without lockers: Sealed Cryptographic Contexts are
 * the handle that software passes between threads.
 *
 * Every process has a random SLocality (Locality entry 10), inherited by
 * fork and regenerated at exec.  CCs that name it can only be imported
 * by threads of the process that exported them.
 *
 * Lockers are named through klnamedlocker, as KLNL, as the specification's
 * management routines do: kl.load and kl.store act on that locker anyway,
 * and the opening kl.mgmt leaves it set.  A task may name KLNL in any
 * instruction that takes a locker but kl.clearall (GR8).
 *
 * With Ssklstatus, sllockerstatus says per locker what a task did with it
 * since it was switched in (Zkl-ISA-priv.adoc, "mllockerstatus,
 * sllockerstatus, and vsllockerstatus"), so a switch moves only what it
 * must.  The task's image of a locker stays valid until the locker turns
 * Dirty: a switch-out exports only the Dirty lockers.  A switch-in imports
 * nothing: it marks every locker with an image Off, and the first access
 * to one raises the KLE locker-Off exception, which M-mode forwards; the
 * handler imports that locker alone.  A locker the task keeps using is
 * imported at the switch-in instead, which costs no exception (see
 * kle_track).  kle.status= selects how much of this is used (see
 * kle_status).
 */

#include <linux/debugfs.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <asm/csr.h>
#include <asm/kle.h>

#define KLE_LOCKERS		32
/* Largest image saved per locker, MDH included: AES-256 SCC is 64 bytes. */
#define KLE_SLOT		128

#define KL_ST(mdh_lo)		(((mdh_lo) >> 18) & 0x3f)
#define KL_ST_ERROR(st)		((st) >= 48 && (st) <= 55)
#define KL_CFG_EXPORTING	57
#define KL_CFG_IMPORTING	58
#define KL_CFG_MANAGEMENT_END	63
#define KL_CFG_CLEARALL		65

/* sllockerstatus: two bits per locker */
#define KL_LS_OFF		0
#define KL_LS_INITIAL		1
#define KL_LS_CLEAN		2
#define KL_LS_DIRTY		3
#define KL_LS_ALL_INITIAL	0x5555555555555555ULL
#define KL_LS(ls, i)		(((ls) >> (2 * (i))) & 3)

static u64 kl_ls_set(u64 ls, int i, u64 f)
{
	return (ls & ~(3ULL << (2 * i))) | f << (2 * i);
}

/*
 * How much of Ssklstatus a context switch uses (kle.status=, boot only):
 *   0: none: with KLS Dirty every locker is exported, and every saved one
 *      is imported at each switch-in;
 *   1: only Dirty lockers are exported, every saved one is imported;
 *   2: also lazy loading: a switch-in leaves the saved lockers Off and the
 *      locker-Off handler imports each on its first access;
 *   3: lazy loading only of the lockers the task does not keep using; the
 *      others are imported at the switch-in (kle_track).
 * Without Ssklstatus it is 0.
 */
#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "kle."
static int kle_status_param = 3;
module_param_named(status, kle_status_param, int, 0444);

static int kle_status(void)
{
	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SSKLSTATUS))
		return 0;
	return clamp(kle_status_param, 0, 3);
}

/*
 * What the context switches moved, in /sys/kernel/debug/riscv_kle/stats;
 * a write there resets the counters.
 */
static struct {
	atomic64_t switch_out;		/* a KLE task switched out */
	atomic64_t switch_out_dirty;	/*   with KLS Dirty */
	atomic64_t switch_in;		/* a KLE task with lockers switched in */
	atomic64_t exported;		/* lockers saved at switch-out */
	atomic64_t kept;		/* images kept at a Dirty switch-out */
	atomic64_t imported;		/* lockers imported at switch-in */
	atomic64_t deferred;		/* lockers left Off at switch-in */
	atomic64_t off_trap;		/* KLE locker-Off exceptions */
	atomic64_t loaded;		/* lockers imported by the handler */
	atomic64_t moved_aside;		/* SR11: a named locker moved aside */
} kle_stats;

#define kle_count(f, n)	atomic64_add(n, &kle_stats.f)

struct riscv_kle_ctx {
	u64 klstart;
	u64 klnamedlocker;
	u32 saved;			/* bitmap of lockers with an image */
	u32 off;			/* lockers left Off at the switch-in */
	u32 seen;			/* kle.status=3, see kle_track() */
	u8 hot[KLE_LOCKERS];
	u8 len[KLE_LOCKERS];		/* image length, MDH included */
	u8 img[KLE_LOCKERS][KLE_SLOT] __aligned(16);
};

/*
 * Encodings (Zkl-ISA-unpriv.adoc; provisional opcode allocation).  Every
 * locker operand below is KLNL, the named locker (r = 1 with locker 0):
 * kl.setnl names a run-time locker number in klnamedlocker, and no
 * instruction needs an immediate one.
 */
#define SETST(imm, f, r, rs1, rd) \
	(((imm) << 25) | ((f) << 21) | ((r) << 20) | ((rs1) << 15) | \
	 (3 << 12) | ((rd) << 7) | 0x0f)
#define R4(f7, rs2, rs1, rd) \
	(((f7) << 25) | ((rs2) << 20) | ((rs1) << 15) | (4 << 12) | \
	 ((rd) << 7) | 0x0f)
#define F7_KLNL			0x02
/* kl.load 0(rs1), x0 and kl.store 0(rs1), x0: on the named locker */
#define KL_LOAD(rs1)		(((rs1) << 15) | (7 << 12) | 0x03)
#define KL_STORE(rs1)		(((rs1) << 15) | (5 << 12) | 0x23)
#define X_A0			10
#define X_A2			12

/* kl.setnl a0 */
static __always_inline void kl_setnl(u64 v)
{
	register u64 _a0 asm("a0") = v;

	asm volatile(".4byte %1" :: "r"(_a0),
		     "i"(SETST(0, 1, 0, X_A0, 0) | (1 << 24)) : "memory");
}

/* kl.getmd a1:a0, KLNL */
static __always_inline void kl_getmd(u64 *m)
{
	register u64 _a0 asm("a0");
	register u64 _a1 asm("a1");

	asm volatile(".4byte %2" : "=r"(_a0), "=r"(_a1)
		     : "i"(R4(0x68 | F7_KLNL, 0, 0, X_A0)));
	m[0] = _a0;
	m[1] = _a1;
}

/* kl.size a0, KLNL (Form A) */
static __always_inline u64 kl_size(void)
{
	register u64 _a0 asm("a0");

	asm volatile(".4byte %1" : "=r"(_a0)
		     : "i"(R4(0x04 | F7_KLNL, 0, 0, X_A0)));
	return _a0;
}

/* kl.mgmt KLNL, #imm, a1:a0 (Form D) */
#define KL_MGMT_D(imm, m) do {						\
	register u64 _a0 asm("a0") = (m)[0];				\
	register u64 _a1 asm("a1") = (m)[1];				\
	asm volatile(".4byte %2" :: "r"(_a0), "r"(_a1),			\
		     "i"(SETST(imm, 3, 1, X_A0, 0)) : "memory");		\
} while (0)

/* kl.mgmt KLNL, #imm (Form A, no MDH needed) */
#define KL_MGMT_A(imm) \
	asm volatile(".4byte %0" :: "i"(SETST(imm, 0, 1, 0, 0)) : "memory")

static __always_inline void kl_load(const void *p)
{
	register const void *_a2 asm("a2") = p;

	asm volatile(".4byte %1" :: "r"(_a2), "i"(KL_LOAD(X_A2)) : "memory");
}

static __always_inline void kl_store(void *p)
{
	register void *_a2 asm("a2") = p;

	asm volatile(".4byte %1" :: "r"(_a2), "i"(KL_STORE(X_A2)) : "memory");
}

static __always_inline void kl_clearall(void)
{
	asm volatile(".4byte %0" :: "i"(SETST(KL_CFG_CLEARALL, 0, 0, 0, 0))
		     : "memory");
}

/*
 * Export locker i into img: an Error-State locker as its MDH alone, any
 * other one by an export (a nested one for a locker under management).
 * Returns the image length, 0 for an Unconfigured locker.
 */
static unsigned int kle_export(int i, u8 *img)
{
	u64 m[2], sz;
	int st;

	kl_setnl(i);
	kl_getmd(m);
	st = KL_ST(m[0]);
	if (!st)
		return 0;
	memcpy(img, m, 16);
	if (KL_ST_ERROR(st))
		return 16;	/* Error State: the MDH alone, no kl.mgmt. */
	sz = kl_size();
	if (WARN_ONCE(sz > KLE_SLOT, "kle: %llu byte image of K%d lost\n",
		      sz, i))
		return 0;
	KL_MGMT_A(KL_CFG_EXPORTING);
	kl_store(img + 16);
	KL_MGMT_D(KL_CFG_MANAGEMENT_END, m);
	return sz;
}

/* Import an image of len bytes into locker i: an MDH alone takes one kl.mgmt. */
static void kle_import(int i, const u8 *img, unsigned int len)
{
	u64 m[2];

	memcpy(m, img, 16);
	kl_setnl(i);
	KL_MGMT_D(KL_CFG_IMPORTING, m);
	if (len > 16) {
		kl_load(img + 16);
		KL_MGMT_D(KL_CFG_MANAGEMENT_END, m);
	}
}

/* Save locker i, or forget its image if it is now Unconfigured. */
static void kle_save_one(struct riscv_kle_ctx *c, int i)
{
	c->len[i] = kle_export(i, c->img[i]);
	if (c->len[i]) {
		c->saved |= BIT(i);
		kle_count(exported, 1);
	} else {
		c->saved &= ~BIT(i);
	}
}

static void kle_restore_one(struct riscv_kle_ctx *c, int i)
{
	kle_import(i, c->img[i], c->len[i]);
}

/*
 * "Context Save Order" of Zkl-ISA-unpriv.adoc, for the lockers whose
 * sllockerstatus field is Dirty; the image of an Off or Clean one is still
 * that of the locker.  Without Ssklstatus every locker counts as Dirty.
 */
static void kle_save(struct riscv_kle_ctx *c, u64 ls)
{
	u64 named;
	int i;

	c->klstart = csr_read(CSR_KLSTART);
	named = csr_read(CSR_KLNAMEDLOCKER);
	c->klnamedlocker = named;

	/* The named locker first: its export reuses SIV/IMPQUAL/SIV2. */
	if (named < KLE_LOCKERS && KL_LS(ls, named) == KL_LS_DIRTY)
		kle_save_one(c, named);
	for (i = 0; i < KLE_LOCKERS; i++) {
		if (i == named || KL_LS(ls, i) != KL_LS_DIRTY)
			continue;
		kle_save_one(c, i);
	}
	for (i = 0; i < KLE_LOCKERS; i++)
		if ((c->saved & BIT(i)) && KL_LS(ls, i) != KL_LS_DIRTY)
			kle_count(kept, 1);
	kl_clearall();
}

/*
 * kle.status=3: at a switch-out, which saved lockers the next switch-ins
 * import.  The fields record changes, not uses: a locker imported at a
 * switch-in stays Clean whether the task uses it or not.  So the kernel
 * sees a use only of a locker it left Off, which the handler then
 * imported, or of one that turned Dirty (seen).  A locker seen used in two
 * time slices in a row is imported at the next KLE_HOT switch-ins (hot);
 * then a switch-in leaves it Off again, to see whether the task still uses
 * it.  One use seen there is not enough to import it again: a key used in
 * one time slice of every KLE_HOT + 1 would then be imported at every
 * switch-in, once that slice fell on a use.
 */
#define KLE_HOT	16

static void kle_track(struct riscv_kle_ctx *c, u64 ls)
{
	u32 seen = 0;
	int i;

	for (i = 0; i < KLE_LOCKERS; i++) {
		u32 f = KL_LS(ls, i), b = BIT(i);

		if (!(c->saved & b))
			c->hot[i] = 0;
		else if (f == KL_LS_DIRTY || (f != KL_LS_OFF && (c->off & b)))
			seen |= b;
		else if (c->hot[i])
			c->hot[i]--;	/* imported at the switch-in, Clean */
		if (seen & c->seen & b)
			c->hot[i] = KLE_HOT;
	}
	c->seen = seen;
}

/* Restore saved locker i at switch-in, or leave it Off; its new field. */
static u64 kle_restore_locker(struct riscv_kle_ctx *c, int i, u64 ls,
			       int status)
{
	if (status == 2 || (status == 3 && !c->hot[i])) {
		c->off |= BIT(i);
		kle_count(deferred, 1);
		return kl_ls_set(ls, i, KL_LS_OFF);
	}
	kle_restore_one(c, i);
	kle_count(imported, 1);
	return kl_ls_set(ls, i, KL_LS_CLEAN);
}

/*
 * "Context Restore Order": the named locker last, then klstart.  With
 * lazy loading, a saved locker may be left Off instead.
 */
static void kle_restore(struct riscv_kle_ctx *c)
{
	u64 named = c->klnamedlocker, ls = KL_LS_ALL_INITIAL;
	int status = kle_status();
	int i;

	c->off = 0;
	for (i = 0; i < KLE_LOCKERS; i++)
		if (i != named && (c->saved & BIT(i)))
			ls = kle_restore_locker(c, i, ls, status);
	if (named < KLE_LOCKERS && (c->saved & BIT(named)))
		ls = kle_restore_locker(c, named, ls, status);
	if (status)
		csr_write(CSR_SLLOCKERSTATUS, ls);
	csr_write(CSR_KLNAMEDLOCKER, named);
	csr_write(CSR_KLSTART, c->klstart);
}

static void kle_write_slocality(struct task_struct *t)
{
	if (!t->mm)
		return;
	csr_write(CSR_SKLLOCALITY0, t->mm->context.kle_slocality[0]);
	csr_write(CSR_SKLLOCALITY1, t->mm->context.kle_slocality[1]);
}

static bool kle_on(struct task_struct *t)
{
	return t->thread.kle &&
	       (task_pt_regs(t)->status & SR_KLS) != SR_KLS_OFF;
}

/*
 * Called with interrupts disabled from switch_to().  Invariant: the hart's
 * lockers are all Unconfigured unless they belong to the running task and
 * its KLS is not Off.
 */
void riscv_kle_switch(struct task_struct *prev, struct task_struct *next)
{
	struct pt_regs *pregs = task_pt_regs(prev);
	struct pt_regs *nregs = task_pt_regs(next);
	bool prev_on = kle_on(prev), next_on = kle_on(next);

	if (!prev_on && !next_on)
		return;

	csr_set(CSR_STATUS, SR_KLS_DIRTY);
	if (prev_on) {
		struct riscv_kle_ctx *c = prev->thread.kle;
		u64 ls = kle_status() ? csr_read(CSR_SLLOCKERSTATUS) : ~0ULL;

		kle_count(switch_out, 1);
		if ((pregs->status & SR_KLS) == SR_KLS_DIRTY) {
			kle_count(switch_out_dirty, 1);
			kle_save(c, ls);
			pregs->status = (pregs->status & ~SR_KLS) | SR_KLS_CLEAN;
		} else {
			kl_clearall();
		}
		if (kle_status() == 3)
			kle_track(c, ls);
	}
	if (next_on) {
		kle_write_slocality(next);
		if ((nregs->status & SR_KLS) != SR_KLS_INITIAL) {
			kle_count(switch_in, 1);
			kle_restore(next->thread.kle);
		} else if (kle_status()) {
			/* No locker of the previous task may stay Off. */
			csr_write(CSR_SLLOCKERSTATUS, KL_LS_ALL_INITIAL);
		}
	}
	csr_clear(CSR_STATUS, SR_KLS);
}

/*
 * The locker that an instruction accesses (Zkl-ISA-priv.adoc), or -1: its
 * immediate locker operand, or the named locker @named for KLNL (r = 1 with
 * locker field 0, which kl.exec may name too since 9e4dc5b0ebfc, GR8) and
 * for kl.load, kl.store, kl.mvin and kl.mvout.  Any other r = 1 is
 * reserved (GR3), so it raises illegal-instruction before locker-Off.
 */
static int kle_insn_locker(u32 insn, u64 named)
{
	u32 opcode = insn & 0x7f, funct3 = (insn >> 12) & 7, f7 = insn >> 25;
	int rd = (insn >> 7) & 0x1f, rs1 = (insn >> 15) & 0x1f;
	int nl = named < KLE_LOCKERS ? named : -1;
	bool r = f7 & 2;		/* bit 26: KLNL with locker field 0 */
	int k = r ? (rs1 ? -1 : nl) : rs1;	/* in the funct3 = 4 group */

	switch (opcode) {
	case 0x03:			/* kl.load */
		return funct3 == 7 ? nl : -1;
	case 0x23:			/* kl.store */
		return funct3 == 5 ? nl : -1;
	case 0x0f:
		if (funct3 == 3) {	/* kl.setst, kl.mgmt; not kl.setnl */
			if (insn & BIT(24))
				return -1;
			if (insn & BIT(20))
				return rd ? -1 : nl;
			return rd;
		}
		if (funct3 != 4)
			return -1;
		switch (f7 >> 5) {
		case 0:
			if (f7 & 4) {	/* kl.size, kl.avail: Form A only */
				if ((f7 >> 3) & 3)
					return -1;
				return k;
			}
			if (((f7 >> 3) & 3) == 3 && rd)	/* kl.mvin, kl.mvout */
				return nl;
			return k;		/* kl.exec */
		case 3:			/* kl.getmd*; not kl.getnl */
			if ((f7 & 0x18) == 0x18)
				return -1;
			return k;
		}
	}
	return -1;
}

/*
 * Import locker i, which a switch-in left Off.  The import would overwrite
 * SIV/IMPQUAL/SIV2 of an export or import under way on the named locker,
 * if the task has loaded it: move that locker aside by a nested export and
 * bring it back afterwards (SR11).  klstart and klnamedlocker are the
 * task's again when done (SR3).
 */
static void kle_load(struct riscv_kle_ctx *c, int i, u64 *ls)
{
	u8 aside[KLE_SLOT] __aligned(16);
	u64 klstart = csr_read(CSR_KLSTART);
	u64 named = csr_read(CSR_KLNAMEDLOCKER), m[2];
	unsigned int len = 0;

	if (named < KLE_LOCKERS && named != i && KL_LS(*ls, named) != KL_LS_OFF) {
		kl_setnl(named);
		kl_getmd(m);
		if (KL_ST(m[0]) == KL_CFG_EXPORTING ||
		    KL_ST(m[0]) == KL_CFG_IMPORTING)
			len = kle_export(named, aside);
	}
	if (c->saved & BIT(i)) {
		kle_restore_one(c, i);
		*ls = kl_ls_set(*ls, i, KL_LS_CLEAN);
		kle_count(loaded, 1);
	} else {
		*ls = kl_ls_set(*ls, i, KL_LS_INITIAL);
	}
	if (len) {
		kle_import(named, aside, len);
		kle_count(moved_aside, 1);
	}
	csr_write(CSR_KLNAMEDLOCKER, named);
	csr_write(CSR_KLSTART, klstart);
}

/*
 * KLE locker-Off exception: import the locker the instruction accesses,
 * and return to it.  If it cannot be told, import every Off locker.
 */
bool riscv_kle_off_handler(struct pt_regs *regs)
{
	struct riscv_kle_ctx *c = current->thread.kle;
	u32 insn = 0;
	u64 ls;
	int i, n = 0;

	if (!c || !kle_status() || (regs->status & SR_KLS) == SR_KLS_OFF)
		return false;
	if (__get_user(insn, (u32 __user *)regs->epc))
		insn = 0;

	preempt_disable();
	csr_set(CSR_STATUS, SR_KLS_DIRTY);
	kle_count(off_trap, 1);
	ls = csr_read(CSR_SLLOCKERSTATUS);
	i = kle_insn_locker(insn, csr_read(CSR_KLNAMEDLOCKER));
	if (i >= 0 && KL_LS(ls, i) == KL_LS_OFF) {
		kle_load(c, i, &ls);
		n = 1;
	} else {
		for (i = 0; i < KLE_LOCKERS; i++) {
			if (KL_LS(ls, i) == KL_LS_OFF) {
				kle_load(c, i, &ls);
				n++;
			}
		}
	}
	csr_write(CSR_SLLOCKERSTATUS, ls);
	csr_clear(CSR_STATUS, SR_KLS);
	preempt_enable();
	return n > 0;
}

static bool insn_is_kle(u32 insn)
{
	u32 opcode = insn & 0x7f, funct3 = (insn >> 12) & 7, csr = insn >> 20;

	switch (opcode) {
	case 0x0f:			/* kl.setst/kl.mgmt, kl.exec group */
		return funct3 == 3 || funct3 == 4;
	case 0x03:			/* kl.load */
		return funct3 == 7;
	case 0x23:			/* kl.store */
		return funct3 == 5;
	case 0x73:			/* KLE CSRs other than the ID CSRs */
		return (funct3 & 3) && (csr == CSR_KLSTART ||
					csr == CSR_KLNAMEDLOCKER ||
					csr == CSR_SKLLOCALITY0 ||
					csr == CSR_SKLLOCALITY1);
	}
	return false;
}

/* First-use trap: a KLE instruction issued while the task's KLS is Off. */
bool riscv_kle_first_use_handler(struct pt_regs *regs)
{
	u32 insn = (u32)regs->badaddr;

	if (!has_kle() || (regs->status & SR_KLS) != SR_KLS_OFF)
		return false;
	if (!insn && __get_user(insn, (u32 __user *)regs->epc))
		return false;
	if (!insn_is_kle(insn))
		return false;

	if (!current->thread.kle) {
		current->thread.kle = kzalloc(sizeof(*current->thread.kle),
					       GFP_KERNEL);
		if (!current->thread.kle) {
			force_sig(SIGBUS);
			return true;
		}
	}

	preempt_disable();
	csr_set(CSR_STATUS, SR_KLS_DIRTY);
	kle_write_slocality(current);
	if (kle_status())
		csr_write(CSR_SLLOCKERSTATUS, KL_LS_ALL_INITIAL);
	csr_clear(CSR_STATUS, SR_KLS);
	regs->status = (regs->status & ~SR_KLS) | SR_KLS_INITIAL;
	preempt_enable();
	return true;
}

/* exec: drop the KLE context and give the new image a new SLocality. */
void riscv_kle_flush_thread(void)
{
	struct pt_regs *regs = task_pt_regs(current);

	if (!has_kle())
		return;

	preempt_disable();
	if ((regs->status & SR_KLS) != SR_KLS_OFF) {
		csr_set(CSR_STATUS, SR_KLS_DIRTY);
		kl_clearall();
		csr_clear(CSR_STATUS, SR_KLS);
	}
	riscv_kle_off(regs);
	preempt_enable();

	kfree(current->thread.kle);
	current->thread.kle = NULL;

	if (current->mm) {
		u64 *s = current->mm->context.kle_slocality;

		do {
			get_random_bytes(s, 2 * sizeof(*s));
		} while (!(s[0] | s[1]));
	}
}

void riscv_kle_thread_free(struct task_struct *tsk)
{
	kfree(tsk->thread.kle);
	tsk->thread.kle = NULL;
}

static int kle_stats_show(struct seq_file *m, void *v)
{
	seq_printf(m, "status %d\n", kle_status());
#define SHOW(f) seq_printf(m, #f " %lld\n", atomic64_read(&kle_stats.f))
	SHOW(switch_out);
	SHOW(switch_out_dirty);
	SHOW(switch_in);
	SHOW(exported);
	SHOW(kept);
	SHOW(imported);
	SHOW(deferred);
	SHOW(off_trap);
	SHOW(loaded);
	SHOW(moved_aside);
#undef SHOW
	return 0;
}

static int kle_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, kle_stats_show, NULL);
}

static ssize_t kle_stats_write(struct file *file, const char __user *buf,
				size_t len, loff_t *ppos)
{
	atomic64_t *a = (atomic64_t *)&kle_stats;
	size_t i;

	for (i = 0; i < sizeof(kle_stats) / sizeof(*a); i++)
		atomic64_set(&a[i], 0);
	return len;
}

static const struct file_operations kle_stats_fops = {
	.open = kle_stats_open,
	.read = seq_read,
	.write = kle_stats_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init kle_debugfs_init(void)
{
	if (has_kle())
		debugfs_create_file("stats", 0644,
				    debugfs_create_dir("riscv_kle", NULL),
				    NULL, &kle_stats_fops);
	return 0;
}
late_initcall(kle_debugfs_init);
