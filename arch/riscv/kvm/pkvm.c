#include <asm/csr.h> // csr_*
#include <linux/compiler.h> // unreachable()
#include <linux/kvm_host.h> // riscv_pkvm_split()

static int pkvm_setup_isolation(void)
{
	// TODO: Isolate HS from VS: remove pkvm pages from guest physical and
	// keep everything else identity mapped.
	csr_write(CSR_HGATP, HGATP_MODE_OFF); // Bare mode (VS physical = HS physical)

	return 0;
}

static void pkvm_setup_environment(void)
{
	// TODO: decide what to expose, the current code tries to do a much as
	// possible
	csr_write(CSR_HENVCFG,
			 ENVCFG_STCE |
			 ENVCFG_PBMTE |
			 ENVCFG_ADUE | // TODO: really?
			 ENVCFG_DTE |
			 // TODO: read ENVCFG_PMM from the SBI interface
			 // hypervisor will need to emulate writes to menvcfg
			 ENVCFG_CBZE |
			 ENVCFG_CBCFE |
			 ENVCFG_CBIE_INV | // TODO: Is invalidate the right one?
			 ENVCFG_SSE |
			 ENVCFG_LPE |
			 ENVCFG_FIOM); // TODO: what is this?
}

static void pkvm_setup_passthrough(void)
{
	/* No point in using the SBI acceleration even if we are nested. */
	csr_write(CSR_HEDELEG, ~0UL);

	// hvip, hie, sie -- ignored?
	csr_write(CSR_HCOUNTEREN, ~0UL);

	csr_write(CSR_HTIMEDELTA, 0UL);
	csr_write(CSR_VSSTATUS, csr_read(CSR_SSTATUS));
	csr_write(CSR_VSIE, csr_read(CSR_SIE));
	csr_write(CSR_VSIP, csr_read(CSR_SIP));

	csr_write(CSR_VSTVEC, csr_read(CSR_STVEC));
	csr_write(CSR_VSSCRATCH, csr_read(CSR_SSCRATCH));
	csr_write(CSR_VSEPC, csr_read(CSR_SEPC));

	// vscause
	// vstval
	// vsatp
	// ???

#if defined(CONFIG_32BIT)  // Who is going to test 32 bit?
	csr_write(CSR_HTIMEDELTAH, 0UL);
	csr_write(CSR_VSIEH, csr_read(CSR_SIEH));
	csr_write(CSR_VSIPH, csr_read(CSR_SIPH));
#endif
}

static void __noreturn pkvm_hypervisor_init(void)
{
	printk("[REMOVE] Trap to HS mode!");
	// guest trapped
	BUG();
	// TODO: setup stack for the hypervisor and enter the hypervisor loop
}

static void pkvm_execute_split(void)
{
	csr_write(CSR_SEPC, &&virtualized_linux); // TODO: rewrite using standard asm goto
	csr_write(CSR_STVEC, pkvm_hypervisor_init);

	printk("[REMOVE] Split imminent.");

	/* First hypervisor trap is taken to pkvm_hypervisor_init */
	asm volatile ("sret");
	unreachable();

virtualized_linux:
	/* Linux continues in VS from this point. */
	printk("[REMOVE] VS mode reporting in.");
	return;
}

int riscv_pkvm_split(void)
{
	int r;

	printk("[REMOVE] The schism begins.");

	// TODO: add both Kconfig and runtime toggle

	// TODO: execute on all harts

	pkvm_setup_passthrough();
	
	// TODO: disable passed through features that pkvm doesn't use

	pkvm_setup_environment();

	if ((r = pkvm_setup_isolation()))
		return r;

	/* Linux+pkvm enters in HS */
	pkvm_execute_split();
	/* Linux continues in VS, pkvm executes other code in HS. */

	return 0;
}
