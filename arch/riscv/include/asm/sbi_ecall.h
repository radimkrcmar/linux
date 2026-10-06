/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Thin wrappers for the functions of the RISC-V SBI specification.
 *
 * Every wrapper is named ecall_<SBI function name> and takes the arguments
 * of the SBI function as listed in the specification.  The wrappers only
 * perform the ecall and return the raw struct sbiret; mapping errors and
 * checking for the presence of an extension is up to the caller.
 */

#ifndef _ASM_RISCV_SBI_ECALL_H
#define _ASM_RISCV_SBI_ECALL_H

#include <linux/wordpart.h>
#include <asm/sbi.h>

#ifdef CONFIG_RISCV_SBI

/*
 * Parameters that are 2*XLEN bits wide are passed in a pair of registers,
 * with the low-order XLEN bits in the lower-numbered register.
 */
#ifdef CONFIG_32BIT
#define __sbi_u64(x)	lower_32_bits(x), upper_32_bits(x)
#else
#define __sbi_u64(x)	(x)
#endif

/* Base extension */
static inline struct sbiret ecall_sbi_get_spec_version(void)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_SPEC_VERSION);
}

static inline struct sbiret ecall_sbi_get_impl_id(void)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_ID);
}

static inline struct sbiret ecall_sbi_get_impl_version(void)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_IMP_VERSION);
}

static inline struct sbiret ecall_sbi_probe_extension(long extension_id)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extension_id);
}

static inline struct sbiret ecall_sbi_get_mvendorid(void)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MVENDORID);
}

static inline struct sbiret ecall_sbi_get_marchid(void)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MARCHID);
}

static inline struct sbiret ecall_sbi_get_mimpid(void)
{
	return sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_GET_MIMPID);
}

#ifdef CONFIG_RISCV_SBI_V01
/*
 * Legacy extensions: the function ID is ignored and only a0 is returned.
 */
static inline long ecall_sbi_legacy_set_timer(u64 stime_value)
{
	return sbi_ecall(SBI_EXT_0_1_SET_TIMER, 0,
			 __sbi_u64(stime_value)).error;
}

static inline long ecall_sbi_legacy_console_putchar(int ch)
{
	return sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch).error;
}

static inline long ecall_sbi_legacy_console_getchar(void)
{
	return sbi_ecall(SBI_EXT_0_1_CONSOLE_GETCHAR, 0).error;
}

static inline long ecall_sbi_legacy_send_ipi(const unsigned long *hart_mask)
{
	return sbi_ecall(SBI_EXT_0_1_SEND_IPI, 0, hart_mask).error;
}

static inline long
ecall_sbi_legacy_remote_fence_i(const unsigned long *hart_mask)
{
	return sbi_ecall(SBI_EXT_0_1_REMOTE_FENCE_I, 0, hart_mask).error;
}

static inline long
ecall_sbi_legacy_remote_sfence_vma(const unsigned long *hart_mask,
				   unsigned long start, unsigned long size)
{
	return sbi_ecall(SBI_EXT_0_1_REMOTE_SFENCE_VMA, 0,
			 hart_mask, start, size).error;
}

static inline long
ecall_sbi_legacy_remote_sfence_vma_asid(const unsigned long *hart_mask,
					unsigned long start, unsigned long size,
					unsigned long asid)
{
	return sbi_ecall(SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID, 0,
			 hart_mask, start, size, asid).error;
}

static inline void ecall_sbi_legacy_shutdown(void)
{
	sbi_ecall(SBI_EXT_0_1_SHUTDOWN, 0);
}
#endif /* CONFIG_RISCV_SBI_V01 */

/* Timer extension */
static inline struct sbiret ecall_sbi_set_timer(u64 stime_value)
{
	return sbi_ecall(SBI_EXT_TIME, SBI_EXT_TIME_SET_TIMER,
			 __sbi_u64(stime_value));
}

/* IPI extension */
static inline struct sbiret ecall_sbi_send_ipi(unsigned long hart_mask,
					       unsigned long hart_mask_base)
{
	return sbi_ecall(SBI_EXT_IPI, SBI_EXT_IPI_SEND_IPI,
			 hart_mask, hart_mask_base);
}

/* RFENCE extension */
static inline struct sbiret
ecall_sbi_remote_fence_i(unsigned long hart_mask, unsigned long hart_mask_base)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_FENCE_I,
			 hart_mask, hart_mask_base);
}

static inline struct sbiret
ecall_sbi_remote_sfence_vma(unsigned long hart_mask,
			    unsigned long hart_mask_base,
			    unsigned long start_addr, unsigned long size)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
			 hart_mask, hart_mask_base, start_addr, size);
}

static inline struct sbiret
ecall_sbi_remote_sfence_vma_asid(unsigned long hart_mask,
				 unsigned long hart_mask_base,
				 unsigned long start_addr, unsigned long size,
				 unsigned long asid)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID,
			 hart_mask, hart_mask_base, start_addr, size, asid);
}

static inline struct sbiret
ecall_sbi_remote_hfence_gvma_vmid(unsigned long hart_mask,
				  unsigned long hart_mask_base,
				  unsigned long start_addr, unsigned long size,
				  unsigned long vmid)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID,
			 hart_mask, hart_mask_base, start_addr, size, vmid);
}

static inline struct sbiret
ecall_sbi_remote_hfence_gvma(unsigned long hart_mask,
			     unsigned long hart_mask_base,
			     unsigned long start_addr, unsigned long size)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA,
			 hart_mask, hart_mask_base, start_addr, size);
}

static inline struct sbiret
ecall_sbi_remote_hfence_vvma_asid(unsigned long hart_mask,
				  unsigned long hart_mask_base,
				  unsigned long start_addr, unsigned long size,
				  unsigned long asid)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID,
			 hart_mask, hart_mask_base, start_addr, size, asid);
}

static inline struct sbiret
ecall_sbi_remote_hfence_vvma(unsigned long hart_mask,
			     unsigned long hart_mask_base,
			     unsigned long start_addr, unsigned long size)
{
	return sbi_ecall(SBI_EXT_RFENCE, SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA,
			 hart_mask, hart_mask_base, start_addr, size);
}

/* Hart State Management extension */
static inline struct sbiret ecall_sbi_hart_start(unsigned long hartid,
						 unsigned long start_addr,
						 unsigned long opaque)
{
	return sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START,
			 hartid, start_addr, opaque);
}

static inline struct sbiret ecall_sbi_hart_stop(void)
{
	return sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STOP);
}

static inline struct sbiret ecall_sbi_hart_get_status(unsigned long hartid)
{
	return sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_STATUS, hartid);
}

static inline struct sbiret ecall_sbi_hart_suspend(u32 suspend_type,
						   unsigned long resume_addr,
						   unsigned long opaque)
{
	return sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_SUSPEND,
			 suspend_type, resume_addr, opaque);
}

/* System Reset extension */
static inline struct sbiret ecall_sbi_system_reset(u32 reset_type,
						   u32 reset_reason)
{
	return sbi_ecall(SBI_EXT_SRST, SBI_EXT_SRST_RESET,
			 reset_type, reset_reason);
}

/* Performance Monitoring Unit extension */
static inline struct sbiret ecall_sbi_pmu_num_counters(void)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_NUM_COUNTERS);
}

static inline struct sbiret
ecall_sbi_pmu_counter_get_info(unsigned long counter_idx)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_COUNTER_GET_INFO,
			 counter_idx);
}

static inline struct sbiret
ecall_sbi_pmu_counter_config_matching(unsigned long counter_idx_base,
				      unsigned long counter_idx_mask,
				      unsigned long config_flags,
				      unsigned long event_idx, u64 event_data)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_COUNTER_CFG_MATCH,
			 counter_idx_base, counter_idx_mask, config_flags,
			 event_idx, __sbi_u64(event_data));
}

static inline struct sbiret
ecall_sbi_pmu_counter_start(unsigned long counter_idx_base,
			    unsigned long counter_idx_mask,
			    unsigned long start_flags, u64 initial_value)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_COUNTER_START,
			 counter_idx_base, counter_idx_mask, start_flags,
			 __sbi_u64(initial_value));
}

static inline struct sbiret
ecall_sbi_pmu_counter_stop(unsigned long counter_idx_base,
			   unsigned long counter_idx_mask,
			   unsigned long stop_flags)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_COUNTER_STOP,
			 counter_idx_base, counter_idx_mask, stop_flags);
}

static inline struct sbiret
ecall_sbi_pmu_counter_fw_read(unsigned long counter_idx)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_COUNTER_FW_READ,
			 counter_idx);
}

static inline struct sbiret
ecall_sbi_pmu_counter_fw_read_hi(unsigned long counter_idx)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_COUNTER_FW_READ_HI,
			 counter_idx);
}

static inline struct sbiret
ecall_sbi_pmu_snapshot_set_shmem(unsigned long shmem_phys_lo,
				 unsigned long shmem_phys_hi,
				 unsigned long flags)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_SNAPSHOT_SET_SHMEM,
			 shmem_phys_lo, shmem_phys_hi, flags);
}

static inline struct sbiret
ecall_sbi_pmu_event_get_info(unsigned long shmem_phys_lo,
			     unsigned long shmem_phys_hi,
			     unsigned long num_entries, unsigned long flags)
{
	return sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_EVENT_GET_INFO,
			 shmem_phys_lo, shmem_phys_hi, num_entries, flags);
}

/* Debug Console extension */
static inline struct sbiret
ecall_sbi_debug_console_write(unsigned long num_bytes,
			      unsigned long base_addr_lo,
			      unsigned long base_addr_hi)
{
	return sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE,
			 num_bytes, base_addr_lo, base_addr_hi);
}

static inline struct sbiret
ecall_sbi_debug_console_read(unsigned long num_bytes,
			     unsigned long base_addr_lo,
			     unsigned long base_addr_hi)
{
	return sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_READ,
			 num_bytes, base_addr_lo, base_addr_hi);
}

/* System Suspend extension */
static inline struct sbiret ecall_sbi_system_suspend(u32 sleep_type,
						     unsigned long resume_addr,
						     unsigned long opaque)
{
	return sbi_ecall(SBI_EXT_SUSP, SBI_EXT_SUSP_SYSTEM_SUSPEND,
			 sleep_type, resume_addr, opaque);
}

/* CPPC extension */
static inline struct sbiret ecall_sbi_cppc_read(u32 cppc_reg_id)
{
	return sbi_ecall(SBI_EXT_CPPC, SBI_EXT_CPPC_READ, cppc_reg_id);
}

static inline struct sbiret ecall_sbi_cppc_write(u32 cppc_reg_id, u64 val)
{
	return sbi_ecall(SBI_EXT_CPPC, SBI_EXT_CPPC_WRITE,
			 cppc_reg_id, __sbi_u64(val));
}

/* Nested Acceleration extension */
static inline struct sbiret ecall_sbi_nacl_probe_feature(u32 feature_id)
{
	return sbi_ecall(SBI_EXT_NACL, SBI_EXT_NACL_PROBE_FEATURE, feature_id);
}

static inline struct sbiret
ecall_sbi_nacl_set_shmem(unsigned long shmem_phys_lo,
			 unsigned long shmem_phys_hi,
			 unsigned long flags)
{
	return sbi_ecall(SBI_EXT_NACL, SBI_EXT_NACL_SET_SHMEM,
			 shmem_phys_lo, shmem_phys_hi, flags);
}

static inline struct sbiret ecall_sbi_nacl_sync_csr(unsigned long csr_num)
{
	return sbi_ecall(SBI_EXT_NACL, SBI_EXT_NACL_SYNC_CSR, csr_num);
}

static inline struct sbiret
ecall_sbi_nacl_sync_hfence(unsigned long entry_index)
{
	return sbi_ecall(SBI_EXT_NACL, SBI_EXT_NACL_SYNC_HFENCE, entry_index);
}

/* Steal-time Accounting extension */
static inline struct sbiret
ecall_sbi_steal_time_set_shmem(unsigned long shmem_phys_lo,
			       unsigned long shmem_phys_hi,
			       unsigned long flags)
{
	return sbi_ecall(SBI_EXT_STA, SBI_EXT_STA_STEAL_TIME_SET_SHMEM,
			 shmem_phys_lo, shmem_phys_hi, flags);
}

/* Firmware Features extension */
static inline struct sbiret ecall_sbi_fwft_set(u32 feature,
					       unsigned long value,
					       unsigned long flags)
{
	return sbi_ecall(SBI_EXT_FWFT, SBI_EXT_FWFT_SET, feature, value, flags);
}

/* Message Proxy extension */
static inline struct sbiret ecall_sbi_mpxy_get_shmem_size(void)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_SHMEM_SIZE);
}

static inline struct sbiret
ecall_sbi_mpxy_set_shmem(unsigned long shmem_phys_lo,
			 unsigned long shmem_phys_hi,
			 unsigned long flags)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SET_SHMEM,
			 shmem_phys_lo, shmem_phys_hi, flags);
}

static inline struct sbiret ecall_sbi_mpxy_get_channel_ids(u32 start_index)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_CHANNEL_IDS,
			 start_index);
}

static inline struct sbiret
ecall_sbi_mpxy_read_attributes(u32 channel_id, u32 base_attribute_id,
			       u32 attribute_count)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_READ_ATTRS,
			 channel_id, base_attribute_id, attribute_count);
}

static inline struct sbiret
ecall_sbi_mpxy_write_attributes(u32 channel_id, u32 base_attribute_id,
				u32 attribute_count)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_WRITE_ATTRS,
			 channel_id, base_attribute_id, attribute_count);
}

static inline struct sbiret
ecall_sbi_mpxy_send_message_with_response(u32 channel_id, u32 message_id,
					  unsigned long message_data_len)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITH_RESP,
			 channel_id, message_id, message_data_len);
}

static inline struct sbiret
ecall_sbi_mpxy_send_message_without_response(u32 channel_id, u32 message_id,
					     unsigned long message_data_len)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_SEND_MSG_WITHOUT_RESP,
			 channel_id, message_id, message_data_len);
}

static inline struct sbiret
ecall_sbi_mpxy_get_notification_events(u32 channel_id)
{
	return sbi_ecall(SBI_EXT_MPXY, SBI_EXT_MPXY_GET_NOTIFICATION_EVENTS,
			 channel_id);
}

#endif /* CONFIG_RISCV_SBI */

#endif /* _ASM_RISCV_SBI_ECALL_H */
