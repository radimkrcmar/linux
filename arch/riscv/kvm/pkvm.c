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

#define PKVM_STACK_SIZE (4096 * 8)
static char pkvm_stack[PKVM_STACK_SIZE] = {0}; // TODO: allocate nice and safe stack
static char pkvm_thread[PKVM_STACK_SIZE] = {0}; // TODO: what should thread pointer be?

static struct kvm_vcpu_arch pkvm_ee = {
	.host_context.sp = (ulong) &pkvm_stack[PKVM_STACK_SIZE - 1],
	.host_context.tp = (ulong) &pkvm_thread,
};

static int __init pkvm_setup_isolation(struct kvm_vcpu_arch *pkvm)
{
	// TODO: Isolate HS from VS: remove pkvm pages from guest physical and
	// keep everything else identity mapped.
	return 0;
}

static void __init pkvm_hart_setup_environment(struct kvm_vcpu_arch *pkvm)
{
	// Each hart should be able to use the same page tables.
	csr_write(CSR_HGATP, HGATP_MODE_OFF); // Bare mode (VS physical = HS virtual)

	// TODO: use a proper value, not just copy-paste from gdb :)
	pkvm->host_context.hstatus = 0xa000000a2 | HSTATUS_SPVP | HSTATUS_SPV | HSTATUS_VTW;
	csr_write(CSR_HSTATUS, pkvm->host_context.hstatus);

	// TODO: decide what to expose, the current code tries to do a much as possible
	pkvm->cfg.henvcfg = ENVCFG_STCE
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
			  ;
	csr_write(CSR_HENVCFG, pkvm->cfg.henvcfg);

	// TODO: the register placement in kvm_vcpu_arch makes no sense
	pkvm->host_context.sstatus = (csr_read(CSR_SSTATUS) | SR_SPP) & ~SR_SIE;
	csr_write(CSR_SSTATUS, pkvm->host_context.sstatus);

	pkvm->host_sscratch = (long) pkvm;
	csr_write(CSR_SSCRATCH, pkvm->host_sscratch);

	pkvm->host_stvec = (long) pkvm_handle_exception; // TODO: reuse linux exception handling?
	/* This is the pKVM loop */
	csr_write(CSR_STVEC, (long) pkvm_trap_entry);

	asm volatile (REG_S " gp, (%0)":: "r" (&pkvm->host_context.gp) : "memory"); // TODO: see what should be done about GP
}

static void __init pkvm_hart_setup_passthrough(struct kvm_vcpu_arch *pkvm)
{
	long sie = 0, sip = 0;

	// TODO: could this be in a common function?
	pkvm->cfg.hedeleg = ~0UL;
	csr_write(CSR_HEDELEG, pkvm->cfg.hedeleg);

	// pkvm->cfg.hideleg = ~0UL; // why no hideleg?
	csr_write(CSR_HIDELEG, ~0UL);

	// hvip, hie, sie -- ignored?
	csr_write(CSR_HCOUNTEREN, ~0UL);

	csr_write(CSR_HTIMEDELTA, 0UL);
	csr_write(CSR_VSSTATUS, csr_read(CSR_SSTATUS));


	// TODO: double check race conditions with sie/sip
	csr_swap(CSR_SIE, &sie);
	csr_write(CSR_VSIE, sie);

	csr_swap(CSR_SIP, &sip);
	csr_write(CSR_VSIP, sip);

	csr_write(CSR_VSTVEC, csr_read(CSR_STVEC));
	csr_write(CSR_VSSCRATCH, csr_read(CSR_SSCRATCH));
	csr_write(CSR_VSEPC, csr_read(CSR_SEPC));

	csr_write(CSR_VSATP, csr_read(CSR_SATP));

	csr_write(CSR_VSTIMECMP, csr_read(CSR_STIMECMP));

	// vscause
	// vstval
	// ???

#if defined(CONFIG_32BIT)  // Who is going to test 32 bit?
	csr_write(CSR_HTIMEDELTAH, 0UL);
	csr_write(CSR_VSIEH, csr_read(CSR_SIEH));
	csr_write(CSR_VSIPH, csr_read(CSR_SIPH));
#endif
}

static void __init pkvm_hart_execute_split(struct kvm_vcpu_arch *pkvm)
{
//	printk("[REMOVE] Split imminent. %p %p", &&virtualized_linux, pkvm_hypervisor_init);

	asm volatile (
			"la t0, vs_mode_linux\n"
			"csrw sepc, t0\n"

			"sret\n"
			/* pKVM never returns to this function. */

			"vs_mode_linux:\n"
			/* Linux continues in VS mode. */
			::: "t0");

	printk("[REMOVE] VS mode reporting in.");
	return;
}

static void __init pkvm_hart_split(struct kvm_vcpu_arch *pkvm)
{
	pkvm_hart_setup_passthrough(pkvm);

	// TODO: disable passed through features that pkvm doesn't use

	pkvm_hart_setup_environment(pkvm);

	/* Linux+pkvm enters in HS */
	pkvm_hart_execute_split(pkvm);
	/* Linux continues in VS, pkvm executes other function in HS. */
}

int __init riscv_pkvm_split(void)
{
	int ret;

	printk("[REMOVE] The schism begins.");

	// TODO: add both Kconfig and runtime toggle

	if ((ret = pkvm_setup_isolation(&pkvm_ee)))
		return ret;

	pkvm_hart_split(&pkvm_ee);
//	on_each_cpu(pkvm_hart_split, &ret, 1); // TODO: smp

	return ret;
}

struct kvm_vcpu_arch *pkvm_trap(struct kvm_vcpu_arch *vcpu_arch)
{
	struct kvm_cpu_trap trap;
	struct sbiret sbiret;

	// TODO: refactor this disgusting shit
	static struct kvm_vcpu vcpu_on_stack;
	static struct kvm_vcpu *vcpu = &vcpu_on_stack;

	// TODO TODO TODO: optimize this
	memcpy(&vcpu->arch, vcpu_arch, sizeof(*vcpu_arch));

	trap.scause = csr_read(CSR_SCAUSE);
	trap.stval = csr_read(CSR_STVAL);  // TODO: only read the rest on demand
	trap.sepc = csr_read(CSR_SEPC);
	trap.htval = csr_read(CSR_HTVAL);
	trap.htinst = csr_read(CSR_HTINST);

	switch (trap.scause) {
		case EXC_SUPERVISOR_SYSCALL:
			sbiret = sbi_ecall(vcpu->arch.guest_context.a7,
			                   vcpu->arch.guest_context.a6,
			                   vcpu->arch.guest_context.a0,
			                   vcpu->arch.guest_context.a1,
			                   vcpu->arch.guest_context.a2,
			                   vcpu->arch.guest_context.a3,
			                   vcpu->arch.guest_context.a4,
			                   vcpu->arch.guest_context.a5);

			vcpu->arch.guest_context.a0 = sbiret.error;
			vcpu->arch.guest_context.a1 = sbiret.value;
			vcpu->arch.guest_context.sepc += 4; // TODO: compressed ecall?
			break;
		case EXC_VIRTUAL_INST_FAULT:
			kvm_riscv_vcpu_virtual_insn(vcpu, NULL, &trap);
			// TODO: return value?
			break;
		default:
			for(;;);
	}
	
	memcpy(vcpu_arch, &vcpu->arch, sizeof(*vcpu_arch));
	return vcpu_arch;
}
