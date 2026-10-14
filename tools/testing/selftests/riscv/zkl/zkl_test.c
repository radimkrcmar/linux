// SPDX-License-Identifier: GPL-2.0-only
/*
 * Zkl (KLE) prototype: lockers as per-task state.
 *
 *   zkl_test               run all tests
 *   zkl_test --import HEX  (internal) import an SCC after exec, print State
 *   zkl_test --bench N M   hold N lockers through a context switch per round
 *                          (see do_bench)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <asm/hwprobe.h>

#include "kle.h"

#ifndef RISCV_HWPROBE_KEY_IMA_EXT_1
#define RISCV_HWPROBE_KEY_IMA_EXT_1	16
#endif
#ifndef RISCV_HWPROBE_EXT_ZKL
#define RISCV_HWPROBE_EXT_ZKL	(1ULL << 6)
#endif

static int failures;

#define CHECK(what, cond) do {						\
	if (cond) {							\
		printf("ok     %s\n", what);				\
	} else {							\
		printf("FAIL   %s (%s:%d)\n", what, __FILE__, __LINE__);	\
		failures++;						\
	}								\
} while (0)

static const uint8_t pt[16] __attribute__((aligned(16))) = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
static const uint8_t ct128[16] = {
	0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
	0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
static const uint8_t k128[16] __attribute__((aligned(16))) = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

static void hex(char *out, const uint8_t *b, int n)
{
	for (int i = 0; i < n; i++)
		sprintf(out + 2 * i, "%02x", b[i]);
}

static void unhex(uint8_t *b, const char *s, int n)
{
	for (int i = 0; i < n; i++)
		sscanf(s + 2 * i, "%2hhx", &b[i]);
}

/* ---------------------------------------------------------------- */

static void test_hwprobe(void)
{
	struct riscv_hwprobe p = { .key = RISCV_HWPROBE_KEY_IMA_EXT_1 };

	CHECK("hwprobe syscall", syscall(__NR_riscv_hwprobe, &p, 1, 0, NULL, 0) == 0);
	CHECK("hwprobe reports Zkl", p.value & RISCV_HWPROBE_EXT_ZKL);
}

static void test_basic(void)
{
	uint8_t out[16] __attribute__((aligned(16)));

	/* The first KLE instruction traps and enables KLS for the task. */
	CHECK("first use: locker 0 Unconfigured", kl_getst(0) == 0);
	kl_provision(0, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0), 0, k128);
	CHECK("provisioned", kl_getst(0) == KL_ST_READY);
	kl_setst(0, KL_ST_ENCRYPT);
	kl_exec(0, pt, out, 16);
	CHECK("AES-128 FIPS-197 C.1", !memcmp(out, ct128, 16));
	kl_clear(0);
}

/* ---------------------------------------------------------------- */

static uint8_t shared_scc[64] __attribute__((aligned(16)));
static uint8_t shared_ct[16];
static volatile int stop;

struct worker {
	pthread_t t;
	int id, pinned;
	long iters, errors;
	int start_state;
};

static void *worker(void *arg)
{
	struct worker *w = arg;
	uint8_t key[32] __attribute__((aligned(16)));
	uint8_t ref[16], out[16] __attribute__((aligned(16)));

	/*
	 * All workers share one hart, so the scheduler must switch between
	 * KLE-using threads whose K3 hold different keys.
	 */
	if (w->pinned) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(0, &set);
		sched_setaffinity(0, sizeof(set), &set);
	}

	/* A new thread starts with no lockers. */
	w->start_state = kl_getst(3);

	/* Its own key in K3, and the shared SCC imported into K4. */
	for (int i = 0; i < 32; i++)
		key[i] = i * 7 + w->id;
	kl_provision(3, KL_MDH_LO(KL_M_AES256_ECB, 1, 0, 0), 0, key);
	kl_setst(3, KL_ST_ENCRYPT);
	kl_exec(3, pt, ref, 16);
	kl_import(4, shared_scc);

	while (!stop) {
		kl_exec(3, pt, out, 16);
		if (memcmp(out, ref, 16))
			w->errors++;
		kl_exec(4, pt, out, 16);
		if (memcmp(out, shared_ct, 16))
			w->errors++;
		if (kl_getst(3) != KL_ST_ENCRYPT || kl_getst(4) != KL_ST_ENCRYPT)
			w->errors++;
		w->iters++;
		if (!(w->iters & 7))
			sched_yield();
	}
	return NULL;
}

static void run_workers(int pinned, long *iters, long *errors, int *fresh)
{
	struct worker w[6];

	stop = 0;
	for (int i = 0; i < 6; i++) {
		w[i] = (struct worker){ .id = i, .pinned = pinned };
		pthread_create(&w[i].t, NULL, worker, &w[i]);
	}
	sleep(3);
	stop = 1;
	for (int i = 0; i < 6; i++) {
		pthread_join(w[i].t, NULL);
		*iters += w[i].iters;
		*errors += w[i].errors;
		*fresh &= w[i].start_state == KL_ST_UNCONFIGURED;
	}
}

static void test_threads(void)
{
	long iters = 0, errors = 0;
	int fresh = 1;

	/* An SCC bound to this process (SLocality) for the threads to share. */
	kl_provision(1, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0),
		     KL_MDH_HI(0, KL_LOC_SLOCALITY), k128);
	kl_setst(1, KL_ST_ENCRYPT);
	CHECK("SCC size 48", kl_size(1) == 48);
	kl_export(1, shared_scc);
	kl_exec(1, pt, shared_ct, 16);
	CHECK("shared key still usable after export", !memcmp(shared_ct, ct128, 16));

	run_workers(0, &iters, &errors, &fresh);
	run_workers(1, &iters, &errors, &fresh);
	printf("       %ld iterations over 2 x 6 threads (spread, then on one hart)\n",
	       iters);
	CHECK("new threads start without lockers", fresh);
	CHECK("SCC imported by sibling threads", iters > 0);
	CHECK("no locker corruption across context switches", errors == 0);
	CHECK("main thread locker intact", kl_getst(1) == KL_ST_ENCRYPT);
}

/* ---------------------------------------------------------------- */

static void test_fork_exec(const char *self)
{
	char arg[200];
	int status;
	pid_t pid;
	int pipefd[2];
	char buf[16] = { 0 };

	pid = fork();
	if (!pid) {
		uint8_t out[16];
		int ok = kl_getst(1) == KL_ST_UNCONFIGURED;

		/* fork inherits SLocality: the parent's SCC imports. */
		kl_import(1, shared_scc);
		kl_exec(1, pt, out, 16);
		_exit(ok && kl_getst(1) == KL_ST_ENCRYPT && !memcmp(out, ct128, 16) ? 0 : 1);
	}
	waitpid(pid, &status, 0);
	CHECK("fork: child has no lockers, imports parent's SCC",
	      WIFEXITED(status) && WEXITSTATUS(status) == 0);

	/* exec gives a new SLocality: the SCC no longer authenticates. */
	hex(arg, shared_scc, 48);
	pipe(pipefd);
	pid = fork();
	if (!pid) {
		dup2(pipefd[1], 1);
		execl(self, self, "--import", arg, NULL);
		_exit(127);
	}
	close(pipefd[1]);
	read(pipefd[0], buf, sizeof(buf) - 1);
	waitpid(pid, &status, 0);
	CHECK("exec: SCC bound to the old SLocality -> Authentication Failed",
	      atoi(buf) == KL_ST_MGMT_AUTH);
}

static int do_import(const char *h)
{
	uint8_t scc[64] __attribute__((aligned(16)));

	unhex(scc, h, 48);
	kl_import(2, scc);
	printf("%d\n", kl_getst(2));
	return 0;
}

/* ---------------------------------------------------------------- */

static sigjmp_buf jb;
static volatile int sig_code;

static void on_sigill(int sig, siginfo_t *si, void *uc)
{
	sig_code = si->si_code;
	siglongjmp(jb, 1);
}

static void test_usage_policy(void)
{
	struct sigaction sa = { .sa_sigaction = on_sigill, .sa_flags = SA_SIGINFO };
	uint8_t out[16];

	sigaction(SIGILL, &sa, NULL);
	kl_provision(5, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0),
		     KL_MDH_HI(KL_USAGE_DENY_U, 0), k128);
	sig_code = 0;
	if (!sigsetjmp(jb, 1))
		kl_setst(5, KL_ST_ENCRYPT);
	CHECK("UsagePolicy denies U-mode: SIGILL/ILL_ILLOPN", sig_code == ILL_ILLOPN);
	CHECK("locker unchanged", kl_getst(5) == KL_ST_READY);
	/* Any other SIGILL kills the test, rather than jump back here. */
	signal(SIGILL, SIG_DFL);

	/* A locker the kernel may not use is still saved and restored. */
	kl_provision(6, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0),
		     KL_MDH_HI(KL_USAGE_DENY_HS | KL_USAGE_DENY_M, 0), k128);
	kl_setst(6, KL_ST_ENCRYPT);
	for (int i = 0; i < 50; i++)
		sched_yield();
	usleep(10000);
	kl_exec(6, pt, out, 16);
	CHECK("HS/M-denied locker survives context switches",
	      !memcmp(out, ct128, 16));
}

/* A management operation preempted between its instructions. */
static void test_preempted_management(void)
{
	uint8_t out[16] __attribute__((aligned(16)));
	uint64_t m[2];

	kl_mgmt(7, KL_CFG_PROVISIONING, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0), 0);
	for (int i = 0; i < 20; i++)
		sched_yield();
	usleep(20000);
	CHECK("partial provisioning survives a switch",
	      kl_getst(7) == KL_CFG_PROVISIONING && kl_getnl() == 7);
	kl_load(k128);		/* on the named locker */
	kl_setst(7, KL_CFG_MANAGEMENT_END);

	/* Completion leaves klnamedlocker naming K7 until software resets it. */
	usleep(20000);
	CHECK("klnamedlocker kept after completion, across a switch",
	      kl_getnl() == 7);
	kl_setnli(32);
	kl_setst(7, KL_ST_ENCRYPT);

	/* Export interrupted by the scheduler between kl.mgmt and kl.store. */
	kl_getmd(7, m);
	kl_setst(7, KL_CFG_EXPORTING);
	usleep(20000);
	kl_store(shared_scc);		/* reuses the buffer: SIV | Content */
	kl_mgmt(7, KL_CFG_MANAGEMENT_END, m[0], m[1]);
	kl_setnli(32);
	kl_exec(7, pt, out, 16);
	CHECK("export across a switch completes", kl_getst(7) == KL_ST_ENCRYPT &&
	      !memcmp(out, ct128, 16));
}

/* ---------------------------------------------------------------- */

/* A counter of the kernel's KLE context switches, if debugfs has them. */
static int kle_stat(const char *name, long *v)
{
	FILE *f = fopen("/sys/kernel/debug/riscv_kle/stats", "r");
	char k[32];
	long x;
	int found = 0;

	if (!f)
		return 0;
	while (fscanf(f, "%31s %ld", k, &x) == 2) {
		if (!strcmp(k, name)) {
			*v = x;
			found = 1;
		}
	}
	fclose(f);
	return found;
}

/* Sleep, so that the next KLE instruction follows a switch-in. */
static void switch_out(void)
{
	usleep(20000);
}

static uint8_t lazy_keys[8][16] __attribute__((aligned(16)));
static uint8_t lazy_ref[8][16];

#define EACH8(OP) OP(0, 8) OP(1, 9) OP(2, 10) OP(3, 11) OP(4, 12) OP(5, 13) \
		  OP(6, 14) OP(7, 15)
#define LAZY_PROV(i, k)							\
	kl_provision(k, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0), 0, lazy_keys[i]); \
	kl_setst(k, KL_ST_ENCRYPT);					\
	kl_exec(k, pt, lazy_ref[i], 16);
#define LAZY_USE(i, k)							\
	kl_exec(k, pt, out, 16);					\
	ok &= kl_getst(k) == KL_ST_ENCRYPT && !memcmp(out, lazy_ref[i], 16);
#define LAZY_GONE(i, k)	ok &= kl_getst(k) == KL_ST_UNCONFIGURED;

/*
 * With Ssklstatus a switch-in leaves the task's lockers Off, and the first
 * access to one imports it (kle.status=2, and 3 for the lockers the task
 * has not kept using).  These hold whatever the kernel does; the counters
 * say whether it loads lazily.
 */
static void test_lazy(void)
{
	uint8_t out[16] __attribute__((aligned(16)));
	uint8_t scc[64] __attribute__((aligned(16)));
	uint64_t lo, hi, m[2];
	long status = 0, l0 = 0, l1 = 0, a0 = 0, a1 = 0;
	int ok = 1, have;

	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 16; j++)
			lazy_keys[i][j] = 17 * i + j;
	EACH8(LAZY_PROV)
	switch_out();
	have = kle_stat("status", &status) && status >= 2 &&
	       kle_stat("loaded", &l0) && kle_stat("moved_aside", &a0);
	kl_exec(10, pt, out, 16);
	ok &= !memcmp(out, lazy_ref[2], 16);
	if (have) {
		kle_stat("loaded", &l1);
		printf("       using 1 of 8 lockers after a switch-in imported %ld\n",
		       l1 - l0);
		CHECK("lazy loading: a switch-in imports only what is used",
		      l1 - l0 >= 1 && l1 - l0 < 8);
	}
	switch_out();
	kl_setnli(9);
	ok &= kl_getst_nl() == KL_ST_ENCRYPT;
	kl_setnli(32);
	EACH8(LAZY_USE)
	CHECK("lockers left Off keep their keys", ok);

	/*
	 * A kl.exec on KLNL (GR8): the handler finds the locker in
	 * klnamedlocker, not in the field, K0, which holds nothing here, so
	 * a handler that took it would import every Off locker.  K14 is Off
	 * here at kle.status=3 too.  Alone in its time slice: the checks
	 * below need K8, K11 and K12 left Off, which status 3 does not do
	 * after uses in two time slices in a row.
	 */
	switch_out();
	kle_stat("loaded", &l0);
	kl_setnli(14);
	kl_exec_nl(pt, out, 16);
	kl_setnli(32);
	if (have) {
		kle_stat("loaded", &l1);
		printf("       using 1 of 8 through KLNL imported %ld\n",
		       l1 - l0);
		CHECK("lazy loading: also of a locker named by KLNL",
		      l1 - l0 == 1 && !memcmp(out, lazy_ref[6], 16));
	}
	switch_out();

	/*
	 * An import under way on K20, then an access to another Off locker:
	 * the import of K9 must not take K20's SIV and IMPQUAL (SR11).
	 */
	kl_export(8, scc);
	lo = ((uint64_t *)scc)[0];
	hi = ((uint64_t *)scc)[1];
	kl_mgmt(20, KL_CFG_IMPORTING, lo, hi);
	kl_load(scc + 16);
	switch_out();
	ok = kl_getst(20) == KL_CFG_IMPORTING && kl_getst(9) == KL_ST_ENCRYPT;
	kl_mgmt(20, KL_CFG_MANAGEMENT_END, lo, hi);
	kl_setnli(32);
	kl_exec(20, pt, out, 16);
	CHECK("an import under way survives the import of an Off locker",
	      ok && kl_getst(20) == KL_ST_ENCRYPT &&
	      !memcmp(out, lazy_ref[0], 16));

	/* The same for an export under way on K11. */
	kl_getmd(11, m);
	kl_setst(11, KL_CFG_EXPORTING);
	switch_out();
	ok = kl_getst(11) == KL_CFG_EXPORTING && kl_getst(12) == KL_ST_ENCRYPT;
	((uint64_t *)scc)[0] = m[0];
	((uint64_t *)scc)[1] = m[1];
	kl_store(scc + 16);
	kl_mgmt(11, KL_CFG_MANAGEMENT_END, m[0], m[1]);
	kl_setnli(32);
	kl_import(21, scc);
	kl_exec(21, pt, out, 16);
	CHECK("an export under way survives the import of an Off locker",
	      ok && kl_getst(11) == KL_ST_ENCRYPT && kl_getst(21) == KL_ST_ENCRYPT &&
	      !memcmp(out, lazy_ref[3], 16));
	if (have && kle_stat("moved_aside", &a1))
		printf("       named lockers moved aside: %ld\n", a1 - a0);

	/*
	 * Clearing a locker left Off, alone in its time slice: nothing else
	 * makes KLS Dirty, so the kernel would keep the image unless the clear
	 * does.
	 */
	switch_out();
	kl_clear(8);
	switch_out();
	CHECK("kl.clear of an Off locker holds across a switch",
	      kl_getst(8) == KL_ST_UNCONFIGURED);
	/* K13, never used in two time slices in a row, is Off at status 3 too. */
	switch_out();
	kl_provision(13, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0), 0, lazy_keys[1]);
	kl_setst(13, KL_ST_ENCRYPT);
	switch_out();
	kl_exec(13, pt, out, 16);
	CHECK("provisioning over an Off locker holds across a switch",
	      !memcmp(out, lazy_ref[1], 16));

	switch_out();
	kl_clearall();
	switch_out();
	ok = kl_getst(20) == KL_ST_UNCONFIGURED &&
	     kl_getst(21) == KL_ST_UNCONFIGURED;
	EACH8(LAZY_GONE)
	CHECK("kl.clearall of Off lockers holds across a switch", ok);
}

/*
 * kle.status=3: a locker the task uses in every time slice is soon
 * imported at the switch-in, without a locker-Off exception, and one it
 * stops using is left Off again.
 */
static void test_hot(void)
{
	uint8_t out[16] __attribute__((aligned(16)));
	long status = 0, t0 = 0, t1 = 0, i0 = 0, i1 = 0;
	int ok = 1;

	if (!kle_stat("status", &status) || status != 3)
		return;
	kl_provision(22, KL_MDH_LO(KL_M_AES128_ECB, 1, 0, 0), 0, k128);
	kl_setst(22, KL_ST_ENCRYPT);
	for (int i = 0; i < 4; i++) {
		switch_out();
		kl_exec(22, pt, out, 16);
		ok &= !memcmp(out, ct128, 16);
	}
	kle_stat("off_trap", &t0);
	switch_out();
	kl_exec(22, pt, out, 16);
	kle_stat("off_trap", &t1);
	CHECK("a locker used in every time slice is imported at the switch-in",
	      ok && !memcmp(out, ct128, 16) && t1 == t0);

	/* Unused for more than 16 time slices, the kernel's KLE_HOT. */
	for (int i = 0; i < 20; i++)
		switch_out();
	kle_stat("imported", &i0);
	switch_out();
	kle_stat("imported", &i1);
	kl_exec(22, pt, out, 16);
	CHECK("a locker no longer used is left Off at the switch-in",
	      i1 == i0 && !memcmp(out, ct128, 16));
	kl_clear(22);
}

/* ---------------------------------------------------------------- */

/* Locker numbers are immediates: OP(k) for k = i. */
#define KL_ANY(i, OP)	switch (i) { \
	case 0: OP(0); break; \
	case 1: OP(1); break; \
	case 2: OP(2); break; \
	case 3: OP(3); break; \
	case 4: OP(4); break; \
	case 5: OP(5); break; \
	case 6: OP(6); break; \
	case 7: OP(7); break; \
	case 8: OP(8); break; \
	case 9: OP(9); break; \
	case 10: OP(10); break; \
	case 11: OP(11); break; \
	case 12: OP(12); break; \
	case 13: OP(13); break; \
	case 14: OP(14); break; \
	case 15: OP(15); break; \
	case 16: OP(16); break; \
	case 17: OP(17); break; \
	case 18: OP(18); break; \
	case 19: OP(19); break; \
	case 20: OP(20); break; \
	case 21: OP(21); break; \
	case 22: OP(22); break; \
	case 23: OP(23); break; \
	case 24: OP(24); break; \
	case 25: OP(25); break; \
	case 26: OP(26); break; \
	case 27: OP(27); break; \
	case 28: OP(28); break; \
	case 29: OP(29); break; \
	case 30: OP(30); break; \
	case 31: OP(31); break; \
	}

/*
 * Hold n lockers (1-32) for two seconds, sleeping 1 ms per round so that
 * every round follows a context switch.  Per round, mode "idle" touches
 * none of them, "use" encrypts with one, the next in each round, "change"
 * first switches that one between Encrypt and Decrypt (a change of the
 * locker), "first" encrypts with the first one in every round, and "all"
 * with every one.  "allnl" is "all" through KLNL, as a library names a
 * locker chosen at run time: kl.setnl before each use and a restoring one
 * after, which changes klnamedlocker and so sets KLS Dirty.  The kernel's
 * riscv_kle/stats say what the switches moved.
 */
static int do_bench(int n, const char *mode)
{
	uint8_t key[16] __attribute__((aligned(16))) = { 0 };
	uint8_t out[16] __attribute__((aligned(16)));
	int change = !strcmp(mode, "change"), all = !strcmp(mode, "all");
	int first = !strcmp(mode, "first"), allnl = !strcmp(mode, "allnl");
	int use = change || all || first || allnl || !strcmp(mode, "use");
	struct timespec t0, t;
	long rounds = 0;

	if (n < 1 || n > 32 || (!use && strcmp(mode, "idle")))
		return 2;
	for (int i = 0; i < n; i++) {
		key[0] = i;
#define PROV(k)	kl_provision(k, KL_MDH_LO(KL_M_AES128_ECB, 3, 0, 0), 0, key); \
		kl_setst(k, KL_ST_ENCRYPT)
		KL_ANY(i, PROV)
#undef PROV
	}
	clock_gettime(CLOCK_MONOTONIC, &t0);
	do {
		int j = first ? 0 : rounds % n;

		usleep(1000);
#define ENC(k)	kl_setst(k, KL_ST_ENCRYPT)
#define DEC(k)	kl_setst(k, KL_ST_DECRYPT)
#define USE(k)	kl_exec(k, pt, out, 16)
#define NLUSE(k)	kl_setnli(k); kl_exec_nl(pt, out, 16); kl_setnli(32)
		if (change && (rounds & 1))
			KL_ANY(j, DEC)
		else if (change)
			KL_ANY(j, ENC)
		if (all) {
			for (int i = 0; i < n; i++)
				KL_ANY(i, USE)
		} else if (allnl) {
			for (int i = 0; i < n; i++)
				KL_ANY(i, NLUSE)
		} else if (use) {
			KL_ANY(j, USE)
		}
		rounds++;
		clock_gettime(CLOCK_MONOTONIC, &t);
	} while (t.tv_sec - t0.tv_sec < 2);
	printf("%ld rounds\n", rounds);
	return 0;
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc == 3 && !strcmp(argv[1], "--import"))
		return do_import(argv[2]);
	if (argc == 4 && !strcmp(argv[1], "--bench"))
		return do_bench(atoi(argv[2]), argv[3]);

	test_hwprobe();
	test_basic();
	test_threads();
	test_fork_exec(argv[0]);
	test_usage_policy();
	test_preempted_management();
	mount("none", "/sys/kernel/debug", "debugfs", 0, NULL);
	test_lazy();
	test_hot();

	printf("%s: %s\n", argv[0], failures ? "FAIL" : "PASS");
	return failures ? 1 : 0;
}
