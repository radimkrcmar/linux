/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * User-space wrappers for the Zkl (KLE) prototype instructions.
 * Encodings follow Zkl-ISA-unpriv.adoc and are provisional.  Lockers are
 * addressed by immediates, so the locker number must be a compile-time
 * constant, or as KLNL, the locker that klnamedlocker names.  kl.load and
 * kl.store act on that locker: the opening kl.mgmt sets it, and the
 * management macros write 32 back once they are done.
 */
#ifndef KLE_H
#define KLE_H

#include <stdint.h>

#define KL_SETST(imm, f, r, rs1, rd) \
	(((imm) << 25) | ((f) << 21) | ((r) << 20) | ((rs1) << 15) | \
	 (3 << 12) | ((rd) << 7) | 0x0f)
#define KL_R4(f7, rs2, rs1, rd) \
	(((f7) << 25) | ((rs2) << 20) | ((rs1) << 15) | (4 << 12) | \
	 ((rd) << 7) | 0x0f)
/* kl.load 0(rs1), x0; kl.store 0(rs1), x0 */
#define KL_LOAD_W(rs1)		(((rs1) << 15) | (7 << 12) | 0x03)
#define KL_STORE_W(rs1)		(((rs1) << 15) | (5 << 12) | 0x23)

enum {
	KL_ST_UNCONFIGURED = 0, KL_ST_READY = 1, KL_ST_ENCRYPT = 7,
	KL_ST_DECRYPT = 8, KL_ST_INVALID = 49, KL_ST_MGMT_AUTH = 51,
	KL_CFG_PROVISIONING = 56, KL_CFG_EXPORTING = 57,
	KL_CFG_IMPORTING = 58, KL_CFG_MANAGEMENT_END = 63,
};

#define KL_M_AES128_ECB	0x000
#define KL_M_AES192_ECB	0x010
#define KL_M_AES256_ECB	0x020

/* MDH[63:0] and MDH[127:64] */
#define KL_MDH_LO(machine, policy, state, keytype) \
	((uint64_t)(machine) | (uint64_t)(policy) << 12 | \
	 (uint64_t)(state) << 18 | (uint64_t)(keytype) << 28)
#define KL_MDH_HI(usage, locality) \
	((uint64_t)(usage) | (uint64_t)(locality) << 5)
#define KL_LOC_SLOCALITY	(1 << 8)
#define KL_USAGE_DENY_U		1
#define KL_USAGE_DENY_HS	4
#define KL_USAGE_DENY_M		8

/* kl.mgmt Kk, #imm, a1:a0 (Form D) */
#define kl_mgmt(k, imm, lo, hi) do {					\
	register uint64_t _a0 asm("a0") = (lo);				\
	register uint64_t _a1 asm("a1") = (hi);				\
	__asm__ volatile(".4byte %2" :: "r"(_a0), "r"(_a1),		\
			 "i"(KL_SETST(imm, 3, 0, 10, k)) : "memory");	\
} while (0)

/* kl.setst Kk, #imm (Form A); kl.mgmt Form A */
#define kl_setst(k, imm) \
	__asm__ volatile(".4byte %0" :: "i"(KL_SETST(imm, 0, 0, 0, k)) : "memory")
#define kl_clear(k)	kl_setst(k, 0)
#define kl_clearall() \
	__asm__ volatile(".4byte %0" :: "i"(KL_SETST(65, 0, 0, 0, 0)) : "memory")

#define kl_getmdl(k) ({							\
	register uint64_t _a0 asm("a0");				\
	__asm__ volatile(".4byte %1" : "=r"(_a0) : "i"(KL_R4(0x60, 0, k, 10))); \
	_a0; })
#define kl_getst(k)	((int)((kl_getmdl(k) >> 18) & 0x3f))
/* kl.getmdl a0, KLNL */
#define kl_getst_nl() ({						\
	register uint64_t _a0 asm("a0");				\
	__asm__ volatile(".4byte %1" : "=r"(_a0) : "i"(KL_R4(0x62, 0, 0, 10))); \
	(int)((_a0 >> 18) & 0x3f); })

/* kl.getnl a0; kl.setnli #v */
#define kl_getnl() ({							\
	register uint64_t _a0 asm("a0");				\
	__asm__ volatile(".4byte %1" : "=r"(_a0) : "i"(KL_R4(0x78, 0, 0, 10))); \
	_a0; })
#define kl_setnli(v) \
	__asm__ volatile(".4byte %0" :: "i"(KL_SETST(v, 0, 0, 0, 0) | (1 << 24)) \
			 : "memory")

#define kl_getmd(k, m) do {						\
	register uint64_t _a0 asm("a0");				\
	register uint64_t _a1 asm("a1");				\
	__asm__ volatile(".4byte %2" : "=r"(_a0), "=r"(_a1)		\
			 : "i"(KL_R4(0x68, 0, k, 10)));			\
	(m)[0] = _a0;							\
	(m)[1] = _a1;							\
} while (0)

#define kl_size(k) ({							\
	register uint64_t _a0 asm("a0");				\
	__asm__ volatile(".4byte %1" : "=r"(_a0) : "i"(KL_R4(0x04, 0, k, 10))); \
	_a0; })

#define kl_load(p) do {							\
	register const void *_a2 asm("a2") = (p);			\
	__asm__ volatile(".4byte %1" :: "r"(_a2), "i"(KL_LOAD_W(12))	\
			 : "memory");					\
} while (0)

#define kl_store(p) do {						\
	register void *_a2 asm("a2") = (p);				\
	__asm__ volatile(".4byte %1" :: "r"(_a2), "i"(KL_STORE_W(12))	\
			 : "memory");					\
} while (0)

/*
 * kl.exec v8, Kk, v8 (Form A, in place) over n bytes (a multiple of 16,
 * at most VLEN bytes with LMUL = 8), from in to out.
 */
#define kl_exec(k, in, out, n) do {					\
	uint64_t _vl;							\
	__asm__ volatile(".option push\n.option arch, +v\n"		\
			 "vsetvli %0, %1, e8, m8, ta, ma\n"		\
			 "vle8.v v8, (%2)\n"				\
			 ".4byte %4\n"					\
			 "vse8.v v8, (%3)\n"				\
			 ".option pop\n"				\
			 : "=&r"(_vl) : "r"((uint64_t)(n)), "r"(in), "r"(out), \
			   "i"(KL_R4(0, 8, k, 8))				\
			 : "memory", "v8", "v9", "v10", "v11", "v12", "v13", \
			   "v14", "v15");					\
} while (0)

/* The same on KLNL (r = 1 with locker field 0, GR8) */
#define kl_exec_nl(in, out, n) do {					\
	uint64_t _vl;							\
	__asm__ volatile(".option push\n.option arch, +v\n"		\
			 "vsetvli %0, %1, e8, m8, ta, ma\n"		\
			 "vle8.v v8, (%2)\n"				\
			 ".4byte %4\n"					\
			 "vse8.v v8, (%3)\n"				\
			 ".option pop\n"				\
			 : "=&r"(_vl) : "r"((uint64_t)(n)), "r"(in), "r"(out), \
			   "i"(KL_R4(2, 8, 0, 8))				\
			 : "memory", "v8", "v9", "v10", "v11", "v12", "v13", \
			   "v14", "v15");					\
} while (0)

/* Provision Kk from MDH and a PI Content (16-byte aligned) with kl.load. */
#define kl_provision(k, lo, hi, content) do {				\
	kl_mgmt(k, KL_CFG_PROVISIONING, lo, hi);			\
	kl_load(content);						\
	kl_setst(k, KL_CFG_MANAGEMENT_END);				\
	kl_setnli(32);							\
} while (0)

/* Export Kk to an image (MDH first, 16-byte aligned); kl.size bytes. */
#define kl_export(k, img) do {						\
	uint64_t _m[2];							\
	kl_getmd(k, _m);						\
	((uint64_t *)(img))[0] = _m[0];					\
	((uint64_t *)(img))[1] = _m[1];					\
	kl_setst(k, KL_CFG_EXPORTING);					\
	kl_store((uint8_t *)(img) + 16);				\
	kl_mgmt(k, KL_CFG_MANAGEMENT_END, _m[0], _m[1]);		\
	kl_setnli(32);							\
} while (0)

/* Import an SCC image (MDH first, 16-byte aligned) into Kk. */
#define kl_import(k, img) do {						\
	uint64_t _lo = ((const uint64_t *)(img))[0];			\
	uint64_t _hi = ((const uint64_t *)(img))[1];			\
	kl_mgmt(k, KL_CFG_IMPORTING, _lo, _hi);				\
	kl_load((const uint8_t *)(img) + 16);				\
	kl_mgmt(k, KL_CFG_MANAGEMENT_END, _lo, _hi);			\
	kl_setnli(32);							\
} while (0)

#endif
