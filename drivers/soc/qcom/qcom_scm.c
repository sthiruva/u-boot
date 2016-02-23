/* Copyright (c) 2010,2015, The Linux Foundation. All rights reserved.
 * Copyright (C) 2015 Linaro Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//#include <linux/platform_device.h>
//#include <linux/cpumask.h>
//#include <linux/export.h>
//#include <linux/types.h>
//#include <linux/qcom_scm.h>

#include "qcom_scm.h"

/**
 * qcom_scm_set_cold_boot_addr() - Set the cold boot address for cpus
 * @entry: Entry point function for the cpus
 * @cpus: The cpumask of cpus that will use the entry point
 *
 * Set the cold boot address of the cpus. Any cpu outside the supported
 * range would be removed from the cpu present mask.
 */
int qcom_scm_set_cold_boot_addr(void *entry, const uint64_t cpus)
{

	return __qcom_scm_set_cold_boot_addr(entry, cpus);
}

/**
 * qcom_scm_set_warm_boot_addr() - Set the warm boot address for cpus
 * @entry: Entry point function for the cpus
 * @cpus: The cpumask of cpus that will use the entry point
 *
 * Set the Linux entry point for the SCM to transfer control to when coming
 * out of a power down. CPU power down may be executed on cpuidle or hotplug.
 */
int qcom_scm_set_warm_boot_addr(void *entry, const uint64_t cpus)
{
	return __qcom_scm_set_warm_boot_addr(entry, cpus);
}

/**
 * qcom_scm_cpu_power_down() - Power down the cpu
 * @flags - Flags to flush cache
 *
 * This is an end point to power down cpu. If there was a pending interrupt,
 * the control would return from this function, otherwise, the cpu jumps to the
 * warm boot entry point set for this cpu upon reset.
 */
void qcom_scm_cpu_power_down(uint32_t flags)
{
	__qcom_scm_cpu_power_down(flags);
}

/**
 * qcom_scm_hdcp_available() - Check if secure environment supports HDCP.
 *
 * Return true if HDCP is supported, false if not.
 */
int qcom_scm_hdcp_available(void)
{
	int ret;

	ret = __qcom_scm_is_call_available(QCOM_SCM_SVC_HDCP,
		QCOM_SCM_CMD_HDCP);

	return (ret > 0) ? 1 : 0;
}

/**
 * qcom_scm_hdcp_req() - Send HDCP request.
 * @req: HDCP request array
 * @req_cnt: HDCP request array count
 * @resp: response buffer passed to SCM
 *
 * Write HDCP register(s) through SCM.
 */
int qcom_scm_hdcp_req(struct qcom_scm_hdcp_req *req, uint32_t req_cnt, uint32_t *resp)
{
	return __qcom_scm_hdcp_req(req, req_cnt, resp);
}

int qcom_scm_restart_proc(uint32_t pid, int restart, uint32_t *resp)
{
	return __qcom_scm_restart_proc(pid, restart, resp);
}
/**
 * qcom_scm_pas_supported() - Check if the peripheral authentication service is
 *			      available for the given peripherial
 * @peripheral:	peripheral id
 *
 * Returns true if PAS is supported for this peripheral, otherwise false.
 */
int qcom_scm_pas_supported(uint32_t peripheral)
{
	int ret;

	ret = __qcom_scm_is_call_available(QCOM_SCM_SVC_PIL,
					   QCOM_SCM_PAS_IS_SUPPORTED_CMD);
	if (ret <= 0)
		return 0;

	return __qcom_scm_pas_supported(peripheral);
}

/**
 * qcom_scm_pas_init_image() - Initialize peripheral authentication service
 *			       state machine for a given peripheral, using the
 *			       metadata
 * @peripheral: peripheral id
 * @metadata:	pointer to memory containing ELF header, program header table
 *		and optional blob of data used for authenticating the metadata
 *		and the rest of the firmware
 * @size:	size of the metadata
 *
 * Returns 0 on success.
 */
int qcom_scm_pas_init_image(struct device *dev, uint32_t peripheral, const void *metadata, size_t size)
{
	return __qcom_scm_pas_init_image(dev, peripheral, metadata, size);
}

/**
 * qcom_scm_pas_mem_setup() - Prepare the memory related to a given peripheral
 *			      for firmware loading
 * @peripheral:	peripheral id
 * @addr:	start address of memory area to prepare
 * @size:	size of the memory area to prepare
 *
 * Returns 0 on success.
 */
int qcom_scm_pas_mem_setup(uint32_t peripheral, phys_addr_t addr, phys_addr_t size)
{
	return __qcom_scm_pas_mem_setup(peripheral, addr, size);
}

/**
 * qcom_scm_pas_auth_and_reset() - Authenticate the given peripheral firmware
 *				   and reset the remote processor
 * @peripheral:	peripheral id
 *
 * Return 0 on success.
 */
int qcom_scm_pas_auth_and_reset(uint32_t peripheral)
{
	return __qcom_scm_pas_auth_and_reset(peripheral);
}

/**
 * qcom_scm_pas_shutdown() - Shut down the remote processor
 * @peripheral: peripheral id
 *
 * Returns 0 on success.
 */
int qcom_scm_pas_shutdown(uint32_t peripheral)
{
	return __qcom_scm_pas_shutdown(peripheral);
}

int qcom_scm_pil_init_image_cmd(uint32_t proc, uint64_t image_addr)
{
	return __qcom_scm_pil_init_image_cmd(proc, image_addr);
}

int qcom_scm_pil_mem_setup_cmd(uint32_t proc, uint64_t start_addr, uint32_t len)
{
	return __qcom_scm_pil_mem_setup_cmd(proc, start_addr, len);
}

int qcom_scm_pil_auth_and_reset_cmd(uint32_t proc)
{
	return __qcom_scm_pil_auth_and_reset_cmd(proc);
}

int qcom_scm_pil_shutdown_cmd(uint32_t proc)
{
	return __qcom_scm_pil_shutdown_cmd(proc);
}

int qcom_scm_iommu_dump_fault_regs(uint32_t id, uint32_t context, uint64_t addr, uint32_t len)
{
	return __qcom_scm_iommu_dump_fault_regs(id, context, addr, len);
}

int qcom_scm_iommu_set_cp_pool_size(uint32_t size, uint32_t spare)
{
	return __qcom_scm_iommu_set_cp_pool_size(size, spare);
}

int qcom_scm_iommu_secure_ptbl_size(uint32_t spare, int psize[2])
{
	return __qcom_scm_iommu_secure_ptbl_size(spare, psize);
}

int qcom_scm_iommu_secure_ptbl_init(uint64_t addr, uint32_t size, uint32_t spare)
{
	return __qcom_scm_iommu_secure_ptbl_init(addr, size, spare);
}

int qcom_scm_iommu_secure_map(uint64_t list, uint32_t list_size, uint32_t size,
			      uint32_t id, uint32_t ctx_id, uint64_t va, uint32_t info_size,
			      uint32_t flags)
{
	return __qcom_scm_iommu_secure_map(list, list_size, size, id,
					   ctx_id, va, info_size, flags);
}

int qcom_scm_iommu_secure_unmap(uint32_t id, uint32_t ctx_id, uint64_t va, uint32_t size, uint32_t flags)
{
	return __qcom_scm_iommu_secure_unmap(id, ctx_id, va, size, flags);
}

int qcom_scm_is_call_available(uint32_t svc_id, uint32_t cmd_id)
{
	return __qcom_scm_is_call_available(svc_id, cmd_id);
}

int qcom_scm_get_feat_version(uint32_t feat)
{
	return __qcom_scm_get_feat_version(feat);
}

int qcom_scm_restore_sec_cfg(uint32_t device_id, uint32_t spare)
{
	return __qcom_scm_restore_sec_cfg(device_id, spare);
}

int qcom_scm_set_video_state(uint32_t state, uint32_t spare)
{
	return __qcom_scm_set_video_state(state, spare);
}

int qcom_scm_mem_protect_video_var(uint32_t start, uint32_t size,
				   uint32_t nonpixel_start,
				   uint32_t nonpixel_size)
{
	return __qcom_scm_mem_protect_video_var(start, size, nonpixel_start,
						nonpixel_size);
}
