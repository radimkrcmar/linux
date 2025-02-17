#include <asm/csr.h> // csr_*
#include <linux/compiler.h> // unreachable()
#include <linux/kvm_host.h> // riscv_pkvm_split()

struct pkvm_execution_environment {
	long pc;
	long base_registers[31]; // TODO: use a better XLEN-sided type and use 15/31
	                         // based on target architecture if H can run with 15
	// TODO: store floating/vector/... registers that are cloberred by pKVM
	void * stack;
};

#define PKVM_STACK_SIZE 4096
static char pkvm_stack[PKVM_STACK_SIZE] = {0}; // TODO: allocate nice and safe stack

static struct pkvm_execution_environment pkvm_ee = {
	.base_registers = {0},
	.stack = &pkvm_stack[PKVM_STACK_SIZE - 1], // stack grows downwards
};

static int __init pkvm_setup_isolation(void)
{
	// TODO: Isolate HS from VS: remove pkvm pages from guest physical and
	// keep everything else identity mapped.
	return 0;
}

static void __init pkvm_hart_setup_environment(void)
{
	// Each hart should be able to use the same page tables.
	csr_write(CSR_HGATP, HGATP_MODE_OFF); // Bare mode (VS physical = HS virtual)

	csr_write(CSR_HSTATUS, 0xa000000a2 | HSTATUS_SPVP | HSTATUS_SPV | HSTATUS_VTW); // TODO: use a proper value, not just copy-paste from gdb :)

	// TODO: decide what to expose, the current code tries to do a much as possible
	csr_write(CSR_HENVCFG,
			   ENVCFG_STCE
			 | ENVCFG_PBMTE
			 | ENVCFG_ADUE // TODO: really?
			 | ENVCFG_DTE
			 // TODO: read ENVCFG_PMM from the SBI interface
			 // hypervisor will need to emulate writes to menvcfg
			 | ENVCFG_CBZE
			 | ENVCFG_CBCFE
			 | ENVCFG_CBIE_INV
			 | ENVCFG_SSE
			 | ENVCFG_LPE
			 // TODO: ENVCFG_FIOM should not be needed
			 );

	csr_write(CSR_SSTATUS, csr_read(CSR_SSTATUS) | SR_SPP);

	csr_write(CSR_SSCRATCH, &pkvm_ee);
}

static void __init pkvm_hart_setup_passthrough(void)
{
	/*
	 * This function is executed just once, so there is no point in using
	 * the SBI CSR acceleration even if we are nested.
	 */
	csr_write(CSR_HEDELEG, ~0UL );

	// hvip, hie, sie -- ignored?
	csr_write(CSR_HCOUNTEREN, ~0UL);

	csr_write(CSR_HTIMEDELTA, 0UL);
	csr_write(CSR_VSSTATUS, csr_read(CSR_SSTATUS));
	csr_write(CSR_VSIE, csr_read(CSR_SIE));
	csr_write(CSR_VSIP, csr_read(CSR_SIP));

	csr_write(CSR_VSTVEC, csr_read(CSR_STVEC));
	csr_write(CSR_VSSCRATCH, csr_read(CSR_SSCRATCH));
	csr_write(CSR_VSEPC, csr_read(CSR_SEPC));

	csr_write(CSR_VSATP, csr_read(CSR_SATP));

	// vscause
	// vstval
	// ???

#if defined(CONFIG_32BIT)  // Who is going to test 32 bit?
	csr_write(CSR_HTIMEDELTAH, 0UL);
	csr_write(CSR_VSIEH, csr_read(CSR_SIEH));
	csr_write(CSR_VSIPH, csr_read(CSR_SIPH));
#endif
}


/*
static void __noreturn __init __aligned(4) pkvm_hypervisor_init(void)
{
	// guest trapped
//	printk("[REMOVE] HS mode reached.");

	for(;;);
	unreachable();
	// TODO: setup stack for the hypervisor and enter the hypervisor loop
}
*/

static void __init pkvm_hart_execute_split(void)
{
//	printk("[REMOVE] Split imminent. %p %p", &&virtualized_linux, pkvm_hypervisor_init);

	/* First hypervisor trap is taken to pkvm_hypervisor_init */
	asm volatile (
			"la t0, vs_mode_linux\n"
			"csrw sepc, t0\n"
			"la t0, hs_mode_pkvm\n"
			"csrw stvec, t0\n"

			"sret\n"

			".align 2\n"
			"hs_mode_pkvm:\n"
			"csrrw a0, sscratch, a0\n" /* a0 contains pointer to pkvm_ee */
			// seq 1 31 | while read i; do echo "\"sd x$i, ($i * 8)(a0)\\\\n\""; done
			"sd x1, (1 * 8)(a0)\n"
			"sd x2, (2 * 8)(a0)\n"
			"sd x3, (3 * 8)(a0)\n"
			"sd x4, (4 * 8)(a0)\n"
			"sd x5, (5 * 8)(a0)\n"
			"sd x6, (6 * 8)(a0)\n"
			"sd x7, (7 * 8)(a0)\n"
			"sd x8, (8 * 8)(a0)\n"
			"sd x9, (9 * 8)(a0)\n"
			//"sd x10, (10 * 8)(a0)\n" // x10 is a0 (who the hell allowed two names for the same thing...)
			"sd x11, (11 * 8)(a0)\n"
			"sd x12, (12 * 8)(a0)\n"
			"sd x13, (13 * 8)(a0)\n"
			"sd x14, (14 * 8)(a0)\n"
			"sd x15, (15 * 8)(a0)\n"
			"sd x16, (16 * 8)(a0)\n"
			"sd x17, (17 * 8)(a0)\n"
			"sd x18, (18 * 8)(a0)\n"
			"sd x19, (19 * 8)(a0)\n"
			"sd x20, (20 * 8)(a0)\n"
			"sd x21, (21 * 8)(a0)\n"
			"sd x22, (22 * 8)(a0)\n"
			"sd x23, (23 * 8)(a0)\n"
			"sd x24, (24 * 8)(a0)\n"
			"sd x25, (25 * 8)(a0)\n"
			"sd x26, (26 * 8)(a0)\n"
			"sd x27, (27 * 8)(a0)\n"
			"sd x28, (28 * 8)(a0)\n"
			"sd x29, (29 * 8)(a0)\n"
			"sd x30, (30 * 8)(a0)\n"
			"sd x31, (31 * 8)(a0)\n"
			// TODO: setup stack
			"j hs_mode_pkvm\n"
			/* HS mode pKVM never returns from this function. */

			"vs_mode_linux:\n"
			/* Linux continues in VS mode. */
			::: "t0");

	printk("[REMOVE] VS mode reporting in.");
	return;
}

static void __init pkvm_hart_split(void *arg)
{
	pkvm_hart_setup_passthrough();

	// TODO: disable passed through features that pkvm doesn't use

	pkvm_hart_setup_environment();

	/* Linux+pkvm enters in HS */
	pkvm_hart_execute_split();
	/* Linux continues in VS, pkvm executes other function in HS. */
}

int __init riscv_pkvm_split(void)
{
	int ret;

	printk("[REMOVE] The schism begins.");

	// TODO: add both Kconfig and runtime toggle

	if ((ret = pkvm_setup_isolation()))
		return ret;

	pkvm_hart_split(&ret);
//	on_each_cpu(pkvm_hart_split, &ret, 1); // TODO: smp

	return ret;
}
