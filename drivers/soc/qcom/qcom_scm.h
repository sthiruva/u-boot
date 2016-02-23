/* Copyright (c) 2010-2015, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef __QCOM_SCM_INT_H
#define __QCOM_SCM_INT_H

#include "common.h"

struct qcom_scm_hdcp_req;
// struct device *dev;
typedef uint64_t phys_addr_t;

#define QCOM_SCM_SVC_BOOT		0x1
#define QCOM_SCM_BOOT_ADDR		0x1
#define QCOM_SCM_BOOT_ADDR_MC		0x11

#define QCOM_SCM_FLAG_HLOS		0x01
#define QCOM_SCM_FLAG_COLDBOOT_MC	0x02
#define QCOM_SCM_FLAG_WARMBOOT_MC	0x04
extern int __qcom_scm_set_warm_boot_addr(void *entry, const uint64_t cpus);
extern int __qcom_scm_set_cold_boot_addr(void *entry, const uint64_t cpus);

#define QCOM_SCM_CMD_TERMINATE_PC	0x2
#define QCOM_SCM_FLUSH_FLAG_MASK	0x3
#define QCOM_SCM_CMD_CORE_HOTPLUGGED	0x10
extern void __qcom_scm_cpu_power_down(uint32_t flags);

#define QCOM_SCM_SVC_INFO		0x6
#define QCOM_IS_CALL_AVAIL_CMD		0x1
extern int __qcom_scm_is_call_available(uint32_t svc_id, uint32_t cmd_id);

#define QCOM_SCM_SVC_HDCP		0x11
#define QCOM_SCM_CMD_HDCP		0x01
extern int __qcom_scm_hdcp_req(struct qcom_scm_hdcp_req *req, uint32_t req_cnt, uint32_t *resp);

#define QCOM_SCM_SVC_PIL		0x2
#define QCOM_SCM_PAS_INIT_IMAGE_CMD	0x1
#define QCOM_SCM_PAS_MEM_SETUP_CMD	0x2
#define QCOM_SCM_PAS_AUTH_AND_RESET_CMD	0x5
#define QCOM_SCM_PAS_SHUTDOWN_CMD	0x6
#define QCOM_SCM_PAS_IS_SUPPORTED_CMD	0x7
extern int __qcom_scm_pas_supported(uint32_t peripheral);
// extern int  __qcom_scm_pas_init_image(struct device *dev, uint32_t peripheral, const void *metadata, size_t size);
extern int  __qcom_scm_pas_mem_setup(uint32_t peripheral, phys_addr_t addr, phys_addr_t size);
extern int  __qcom_scm_pas_auth_and_reset(uint32_t peripheral);
extern int  __qcom_scm_pas_shutdown(uint32_t peripheral);

/* common error codes */
#define QCOM_SCM_ENOMEM		-5
#define QCOM_SCM_EOPNOTSUPP	-4
#define QCOM_SCM_EINVAL_ADDR	-3
#define QCOM_SCM_EINVAL_ARG	-2
#define QCOM_SCM_ERROR		-1
#define QCOM_SCM_INTERRUPTED	1
#define QCOM_SCM_EBUSY         -55
#define QCOM_SCM_V2_EBUSY      -12


static inline int qcom_scm_remap_error(int err)
{
    /*
	switch (err) {
	case QCOM_SCM_ERROR:
		return -EIO;
	case QCOM_SCM_EINVAL_ADDR:
	case QCOM_SCM_EINVAL_ARG:
		return -EINVAL;
	case QCOM_SCM_EOPNOTSUPP:
		return -EOPNOTSUPP;
	case QCOM_SCM_ENOMEM:
		return -ENOMEM;
	case QCOM_SCM_EBUSY:
		return QCOM_SCM_EBUSY;
	case QCOM_SCM_V2_EBUSY:
		return QCOM_SCM_V2_EBUSY;
	}
	return -EINVAL;
    */

    return 1;
}

enum scm_cmd {
	PAS_INIT_IMAGE_CMD = 1,
	PAS_MEM_SETUP_CMD,
	PAS_AUTH_AND_RESET_CMD = 5,
	PAS_SHUTDOWN_CMD,
};

#define SCM_SVC_BOOT		0x1
#define SCM_SVC_PIL		0x2
#define SCM_SVC_INFO		0x6

#define GET_FEAT_VERSION_CMD	3

extern int __qcom_scm_pil_init_image_cmd(uint32_t proc, uint64_t image_addr);
extern int __qcom_scm_pil_mem_setup_cmd(uint32_t proc, uint64_t start_addr, uint32_t len);
extern int __qcom_scm_pil_auth_and_reset_cmd(uint32_t proc);
extern int __qcom_scm_pil_shutdown_cmd(uint32_t proc);

extern int __qcom_scm_iommu_dump_fault_regs(uint32_t id, uint32_t context, uint64_t addr,
					    uint32_t len);
extern int __qcom_scm_iommu_set_cp_pool_size(uint32_t size, uint32_t spare);
extern int __qcom_scm_iommu_secure_ptbl_size(uint32_t spare, int psize[2]);
extern int __qcom_scm_iommu_secure_ptbl_init(uint64_t addr, uint32_t size, uint32_t spare);
extern int __qcom_scm_iommu_secure_map(uint64_t list, uint32_t list_size, uint32_t size,
				       uint32_t id, uint32_t ctx_id, uint64_t va,
				       uint32_t info_size, uint32_t flags);
extern int __qcom_scm_iommu_secure_unmap(uint32_t id, uint32_t ctx_id, uint64_t va,
					 uint32_t size, uint32_t flags);

extern int __qcom_scm_is_call_available(uint32_t svc_id, uint32_t cmd_id);
extern int __qcom_scm_get_feat_version(uint32_t feat);
extern int __qcom_scm_restore_sec_cfg(uint32_t device_id, uint32_t spare);
extern int __qcom_scm_restart_proc(uint32_t proc_id, int restart, uint32_t *resp);

extern int __qcom_scm_set_video_state(uint32_t state, uint32_t spare);
extern int __qcom_scm_mem_protect_video_var(uint32_t start, uint32_t size,
					    uint32_t nonpixel_start,
					    uint32_t nonpixel_size);
#endif
