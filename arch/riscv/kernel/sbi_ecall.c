// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Rivos Inc. */

#include <asm/sbi.h>
#include <asm/sbi_ecall.h>

long sbi_get_mvendorid(void)
{
	struct sbiret ret = ecall_sbi_get_mvendorid();

	return ret.error ? sbi_err_map_linux_errno(ret.error) : ret.value;
}
EXPORT_SYMBOL_GPL(sbi_get_mvendorid);

long sbi_get_marchid(void)
{
	struct sbiret ret = ecall_sbi_get_marchid();

	return ret.error ? sbi_err_map_linux_errno(ret.error) : ret.value;
}
EXPORT_SYMBOL_GPL(sbi_get_marchid);

long sbi_get_mimpid(void)
{
	struct sbiret ret = ecall_sbi_get_mimpid();

	return ret.error ? sbi_err_map_linux_errno(ret.error) : ret.value;
}
EXPORT_SYMBOL_GPL(sbi_get_mimpid);
