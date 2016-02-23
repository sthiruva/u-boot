/* Copyright (c) 2015, The Linux Foundation. All rights reserved.
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
//#include <linux/delay.h>
//#include <linux/mutex.h>
//#include <linux/slab.h>
//#include <linux/types.h>
//#include <linux/dma-mapping.h>

//#include <asm/cacheflush.h>
//#include <asm/compiler.h>
//#include <asm/smp_plat.h>


#include <common.h>
#include <linux/compiler.h>
#include "qcom_scm.h"
#include "include/qcom_scm.h"


#define MPIDR_LEVEL_BITS 8
#define MPIDR_LEVEL_MASK ((1 << MPIDR_LEVEL_BITS) - 1)

#define MPIDR_AFFINITY_LEVEL(mpidr, level) \
	((mpidr >> (MPIDR_LEVEL_BITS * level)) & MPIDR_LEVEL_MASK)


#define __asmeq(x, y)				\
	".ifnc " x "," y "; "			\
	  ".ifnc " x y ",fpr11; " 		\
	    ".ifnc " x y ",r11fp; "		\
	      ".ifnc " x y ",ipr12; " 		\
	        ".ifnc " x y ",r12ip; "		\
	          ".err; "			\
	        ".endif; "			\
	      ".endif; "			\
	    ".endif; "				\
	  ".endif; "				\
	".endif\n\t"


#include "qcom_scm.h"

#define QCOM_SCM_SIP_FNID(s, c) (((((s) & 0xFF) << 8) | ((c) & 0xFF)) | 0x02000000)

#define MAX_QCOM_SCM_ARGS 10
#define MAX_QCOM_SCM_RETS 3

enum qcom_scm_arg_types {
	QCOM_SCM_VAL,
	QCOM_SCM_RO,
	QCOM_SCM_RW,
	QCOM_SCM_BUFVAL,
};

#define QCOM_SCM_ARGS_IMPL(num, a, b, c, d, e, f, g, h, i, j, ...) (\
			(((a) & 0xff) << 4) | \
			(((b) & 0xff) << 6) | \
			(((c) & 0xff) << 8) | \
			(((d) & 0xff) << 10) | \
			(((e) & 0xff) << 12) | \
			(((f) & 0xff) << 14) | \
			(((g) & 0xff) << 16) | \
			(((h) & 0xff) << 18) | \
			(((i) & 0xff) << 20) | \
			(((j) & 0xff) << 22) | \
			(num & 0xffff))

#define QCOM_SCM_ARGS(...) QCOM_SCM_ARGS_IMPL(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

/**
 * struct qcom_scm_desc
 * @arginfo: Metadata describing the arguments in args[]
 * @args: The array of arguments for the secure syscall
 * @ret: The values returned by the secure syscall
 * @extra_arg_buf: The buffer containing extra arguments
		   (that don't fit in available registers)
 * @x5: The 4rd argument to the secure syscall or physical address of
	extra_arg_buf
 */
struct qcom_scm_desc {
	uint32_t arginfo;
	uint64_t args[MAX_QCOM_SCM_ARGS];
	uint64_t ret[MAX_QCOM_SCM_RETS];

	/* private */
	void *extra_arg_buf;
	uint64_t x5;
};


#define QCOM_SCM_ENOMEM		-5
#define QCOM_SCM_EOPNOTSUPP	-4
#define QCOM_SCM_EINVAL_ADDR	-3
#define QCOM_SCM_EINVAL_ARG	-2
#define QCOM_SCM_ERROR		-1
#define QCOM_SCM_INTERRUPTED	1
#define QCOM_SCM_EBUSY		-55
#define QCOM_SCM_V2_EBUSY	-12

#define QCOM_SCM_EBUSY_WAIT_MS 30
#define QCOM_SCM_EBUSY_MAX_RETRY 20

#define N_EXT_QCOM_SCM_ARGS 7
#define FIRST_EXT_ARG_IDX 3
#define SMC_ATOMIC_SYSCALL 31
#define N_REGISTER_ARGS (MAX_QCOM_SCM_ARGS - N_EXT_QCOM_SCM_ARGS + 1)
#define SMC64_MASK 0x40000000
#define SMC_ATOMIC_MASK 0x80000000
#define IS_CALL_AVAIL_CMD 1

#define R0_STR "x0"
#define R1_STR "x1"
#define R2_STR "x2"
#define R3_STR "x3"
#define R4_STR "x4"
#define R5_STR "x5"
#define R6_STR "x6"

void msleep(uint64_t time){
    printf("msleep: not implemented!!\n");
}


int __qcom_scm_call_armv8_64(uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5,
				uint64_t *ret1, uint64_t *ret2, uint64_t *ret3)
{
	register uint64_t r0 asm("r0") = x0;
	register uint64_t r1 asm("r1") = x1;
	register uint64_t r2 asm("r2") = x2;
	register uint64_t r3 asm("r3") = x3;
	register uint64_t r4 asm("r4") = x4;
	register uint64_t r5 asm("r5") = x5;
	register uint64_t r6 asm("r6") = 0;

	do {
		asm volatile(
			__asmeq("%0", R0_STR)
			__asmeq("%1", R1_STR)
			__asmeq("%2", R2_STR)
			__asmeq("%3", R3_STR)
			__asmeq("%4", R0_STR)
			__asmeq("%5", R1_STR)
			__asmeq("%6", R2_STR)
			__asmeq("%7", R3_STR)
			__asmeq("%8", R4_STR)
			__asmeq("%9", R5_STR)
			__asmeq("%10", R6_STR)
#ifdef REQUIRES_SEC
			".arch_extension sec\n"
#endif
			"smc	#0\n"
			: "=r" (r0), "=r" (r1), "=r" (r2), "=r" (r3)
			: "r" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r4),
			  "r" (r5), "r" (r6)
			: "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			  "x14", "x15", "x16", "x17");
	} while (r0 == QCOM_SCM_INTERRUPTED);

	if (ret1)
		*ret1 = r1;
	if (ret2)
		*ret2 = r2;
	if (ret3)
		*ret3 = r3;

	return r0;
}

int __qcom_scm_call_armv8_32(uint32_t w0, uint32_t w1, uint32_t w2, uint32_t w3, uint32_t w4, uint32_t w5,
				uint64_t *ret1, uint64_t *ret2, uint64_t *ret3)
{
	register uint32_t r0 asm("r0") = w0;
	register uint32_t r1 asm("r1") = w1;
	register uint32_t r2 asm("r2") = w2;
	register uint32_t r3 asm("r3") = w3;
	register uint32_t r4 asm("r4") = w4;
	register uint32_t r5 asm("r5") = w5;
	register uint32_t r6 asm("r6") = 0;

	do {
		asm volatile(
			__asmeq("%0", R0_STR)
			__asmeq("%1", R1_STR)
			__asmeq("%2", R2_STR)
			__asmeq("%3", R3_STR)
			__asmeq("%4", R0_STR)
			__asmeq("%5", R1_STR)
			__asmeq("%6", R2_STR)
			__asmeq("%7", R3_STR)
			__asmeq("%8", R4_STR)
			__asmeq("%9", R5_STR)
			__asmeq("%10", R6_STR)
#ifdef REQUIRES_SEC
			".arch_extension sec\n"
#endif
			"smc	#0\n"
			: "=r" (r0), "=r" (r1), "=r" (r2), "=r" (r3)
			: "r" (r0), "r" (r1), "r" (r2), "r" (r3), "r" (r4),
			  "r" (r5), "r" (r6)
			: "x7", "x8", "x9", "x10", "x11", "x12", "x13",
			"x14", "x15", "x16", "x17");

	} while (r0 == QCOM_SCM_INTERRUPTED);

	if (ret1)
		*ret1 = r1;
	if (ret2)
		*ret2 = r2;
	if (ret3)
		*ret3 = r3;

	return r0;
}

struct qcom_scm_extra_arg {
	union {
		uint32_t args32[N_EXT_QCOM_SCM_ARGS];
		uint64_t args64[N_EXT_QCOM_SCM_ARGS];
	};
};

static enum qcom_scm_interface_version {
	QCOM_SCM_UNKNOWN,
	QCOM_SCM_LEGACY,
	QCOM_SCM_ARMV8_32,
	QCOM_SCM_ARMV8_64,
} qcom_scm_version = QCOM_SCM_UNKNOWN;

/* This will be set to specify SMC32 or SMC64 */
static uint32_t qcom_scm_version_mask;

static __attribute__((aligned(0x1000))) struct qcom_scm_extra_arg scm_extra_arg_array[10];
static uint32_t  extra_arg_count = 0;

/*
 * If there are more than N_REGISTER_ARGS, allocate a buffer and place
 * the additional arguments in it. The extra argument buffer will be
 * pointed to by X5.
 */
static int allocate_extra_arg_buffer(struct qcom_scm_desc *desc)
{
	int i, j;
	struct qcom_scm_extra_arg *argbuf;
	int arglen = desc->arginfo & 0xf;
//	size_t argbuflen = PAGE_ALIGN(sizeof(struct qcom_scm_extra_arg));

	desc->x5 = desc->args[FIRST_EXT_ARG_IDX];

	if (likely(arglen <= N_REGISTER_ARGS)) {
		desc->extra_arg_buf = NULL;
		return 0;
	}

	argbuf = &scm_extra_arg_array[0];
    extra_arg_count++;

    if( extra_arg_count == 10){
		printf("qcom_scm_call: out of scm_extra_arg_array\n");
        while(1);
    }

	if (!argbuf) {
		printf("qcom_scm_call: failed to alloc mem for extended argument buffer\n");
		return -1;
	}

	desc->extra_arg_buf = argbuf;

	j = FIRST_EXT_ARG_IDX;
	if (qcom_scm_version == QCOM_SCM_ARMV8_64)
		for (i = 0; i < N_EXT_QCOM_SCM_ARGS; i++)
			argbuf->args64[i] = desc->args[j++];
	else
		for (i = 0; i < N_EXT_QCOM_SCM_ARGS; i++)
			argbuf->args32[i] = desc->args[j++];
	//desc->x5 = virt_to_phys(argbuf);
	desc->x5 = (uint64_t)argbuf;
//	__flush_dcache_area(argbuf, argbuflen);
  	flush_dcache_range(argbuf, 0x1000);

	return 0;
}

/**
 * qcom_scm_call() - Invoke a syscall in the secure world
 * @svc_id: service identifier
 * @cmd_id: command identifier
 * @fn_id: The function ID for this syscall
 * @desc: Descriptor structure containing arguments and return values
 *
 * Sends a command to the SCM and waits for the command to finish processing.
 * This should *only* be called in pre-emptible context.
 *
 * A note on cache maintenance:
 * Note that any buffers that are expected to be accessed by the secure world
 * must be flushed before invoking qcom_scm_call and invalidated in the cache
 * immediately after qcom_scm_call returns. An important point that must be noted
 * is that on ARMV8 architectures, invalidation actually also causes a dirty
 * cache line to be cleaned (flushed + unset-dirty-bit). Therefore it is of
 * paramount importance that the buffer be flushed before invoking qcom_scm_call,
 * even if you don't care about the contents of that buffer.
 *
 * Note that cache maintenance on the argument buffer (desc->args) is taken care
 * of by qcom_scm_call; however, callers are responsible for any other cached
 * buffers passed over to the secure world.
*/
static int qcom_scm_call(uint32_t svc_id, uint32_t cmd_id, struct qcom_scm_desc *desc)
{
//	int arglen = desc->arginfo & 0xf;
	int ret, retry_count = 0;
	uint32_t fn_id = QCOM_SCM_SIP_FNID(svc_id, cmd_id);
	uint64_t x0;

	ret = allocate_extra_arg_buffer(desc);
	if (ret)
		return ret;

	x0 = fn_id | qcom_scm_version_mask;

	do {

		desc->ret[0] = desc->ret[1] = desc->ret[2] = 0;

//  	printf("qcom_scm_call: func id %#llx, args: %#x, %#llx, %#llx, %#llx, %#llx\n",
//  		x0, desc->arginfo, desc->args[0], desc->args[1],
//  		desc->args[2], desc->x5);

		if (qcom_scm_version == QCOM_SCM_ARMV8_64)
			ret = __qcom_scm_call_armv8_64(x0, desc->arginfo,
						  desc->args[0], desc->args[1],
						  desc->args[2], desc->x5,
						  &desc->ret[0], &desc->ret[1],
						  &desc->ret[2]);
		else
			ret = __qcom_scm_call_armv8_32(x0, desc->arginfo,
						  desc->args[0], desc->args[1],
						  desc->args[2], desc->x5,
						  &desc->ret[0], &desc->ret[1],
						  &desc->ret[2]);

		if (ret == QCOM_SCM_V2_EBUSY){
            printf("SCM is busy: we need to sleep!\n");
			msleep(QCOM_SCM_EBUSY_WAIT_MS);
        }
	}  while (ret == QCOM_SCM_V2_EBUSY && (retry_count++ < QCOM_SCM_EBUSY_MAX_RETRY));

	if (ret < 0)
		printf("qcom_scm_call failed: func id %#llx, arginfo: %#x, args: %#llx, %#llx, %#llx, %#llx, ret: %d, syscall returns: %#llx, %#llx, %#llx\n",
			x0, desc->arginfo, desc->args[0], desc->args[1],
			desc->args[2], desc->x5, ret, desc->ret[0],
			desc->ret[1], desc->ret[2]);

//  if (arglen > N_REGISTER_ARGS)
//  	kfree(desc->extra_arg_buf);

	if (ret < 0)
		return qcom_scm_remap_error(ret);
	return 0;
}

/**
 * qcom_scm_call_atomic() - Invoke a syscall in the secure world
 *
 * Similar to qcom_scm_call except that this can be invoked in atomic context.
 * There is also no retry mechanism implemented. Please ensure that the
 * secure world syscall can be executed in such a context and can complete
 * in a timely manner.
 */
static int qcom_scm_call_atomic(uint32_t s, uint32_t c, struct qcom_scm_desc *desc)
{
//	int arglen = desc->arginfo & 0xf;
	int ret;
	uint32_t fn_id = QCOM_SCM_SIP_FNID(s, c);
	uint64_t x0;

	ret = allocate_extra_arg_buffer(desc);
	if (ret)
		return ret;

	x0 = fn_id | BIT(SMC_ATOMIC_SYSCALL) | qcom_scm_version_mask;

	printf("qcom_scm_call: func id %#llx, args: %#x, %#llx, %#llx, %#llx, %#llx\n",
		x0, desc->arginfo, desc->args[0], desc->args[1],
		desc->args[2], desc->x5);

	if (qcom_scm_version == QCOM_SCM_ARMV8_64)
		ret = __qcom_scm_call_armv8_64(x0, desc->arginfo, desc->args[0],
					  desc->args[1], desc->args[2],
					  desc->x5, &desc->ret[0],
					  &desc->ret[1], &desc->ret[2]);
	else
		ret = __qcom_scm_call_armv8_32(x0, desc->arginfo, desc->args[0],
					  desc->args[1], desc->args[2],
					  desc->x5, &desc->ret[0],
					  &desc->ret[1], &desc->ret[2]);
	if (ret < 0)
		printf("qcom_scm_call failed: func id %#llx, arginfo: %#x, args: %#llx, %#llx, %#llx, %#llx, ret: %d, syscall returns: %#llx, %#llx, %#llx\n",
			x0, desc->arginfo, desc->args[0], desc->args[1],
			desc->args[2], desc->x5, ret, desc->ret[0],
			desc->ret[1], desc->ret[2]);

//	if (arglen > N_REGISTER_ARGS)
//		kfree(desc->extra_arg_buf);

	if (ret < 0)
		return qcom_scm_remap_error(ret);
	return ret;
}

static int qcom_scm_set_boot_addr(void *entry, uint64_t cpu, int flags)
{
	struct qcom_scm_desc desc = {0};
//	unsigned int cpu = cpumask_first(cpus);
	uint64_t mpidr_el1 = cpu;

	/* For now we assume only a single cpu is set in the mask */
	// WARN_ON(cpumask_weight(cpus) != 1);

////if (mpidr_el1 & ~MPIDR_HWID_BITMASK) {
////	printf("CPU%d:Failed to set boot address\n", cpu);
////	return -ENOSYS;
////}

	desc.args[0] = (uint64_t)entry;
	desc.args[1] = BIT(MPIDR_AFFINITY_LEVEL(mpidr_el1, 0));
	desc.args[2] = BIT(MPIDR_AFFINITY_LEVEL(mpidr_el1, 1));
	desc.args[3] = BIT(MPIDR_AFFINITY_LEVEL(mpidr_el1, 2));
	desc.args[4] = ~0ULL;
	desc.args[5] = QCOM_SCM_FLAG_HLOS | flags;
	desc.arginfo = QCOM_SCM_ARGS(6);

	return qcom_scm_call(QCOM_SCM_SVC_BOOT, QCOM_SCM_BOOT_ADDR_MC, &desc);
}

int __qcom_scm_set_cold_boot_addr(void *entry, const uint64_t cpu)
{
	int flags = QCOM_SCM_FLAG_COLDBOOT_MC;

	return qcom_scm_set_boot_addr(entry, cpu, flags);
}

int __qcom_scm_set_warm_boot_addr(void *entry, const uint64_t cpus)
{
	int flags = QCOM_SCM_FLAG_WARMBOOT_MC;

	return qcom_scm_set_boot_addr(entry, cpus, flags);
}

void __qcom_scm_cpu_power_down(uint32_t flags)
{
	struct qcom_scm_desc desc = {0};
	desc.args[0] = QCOM_SCM_CMD_CORE_HOTPLUGGED |
		       (flags & QCOM_SCM_FLUSH_FLAG_MASK);
	desc.arginfo = QCOM_SCM_ARGS(1);

	qcom_scm_call_atomic(QCOM_SCM_SVC_BOOT, QCOM_SCM_CMD_TERMINATE_PC, &desc);
}

int __qcom_scm_is_call_available(uint32_t svc_id, uint32_t cmd_id)
{
	int ret;
	struct qcom_scm_desc desc = {0};

	desc.arginfo = QCOM_SCM_ARGS(1);
	desc.args[0] = QCOM_SCM_SIP_FNID(svc_id, cmd_id);

	ret = qcom_scm_call(QCOM_SCM_SVC_INFO, QCOM_IS_CALL_AVAIL_CMD, &desc);

	if (ret)
		return ret;

	return desc.ret[0];
}

#define QCOM_SCM_HDCP_MAX_REQ_CNT	5

int __qcom_scm_hdcp_req(struct qcom_scm_hdcp_req *req, uint32_t req_cnt, uint32_t *resp)
{
	int ret;
	struct qcom_scm_desc desc = {0};

	if (req_cnt > QCOM_SCM_HDCP_MAX_REQ_CNT)
		return -1;

	desc.args[0] = req[0].addr;
	desc.args[1] = req[0].val;
	desc.args[2] = req[1].addr;
	desc.args[3] = req[1].val;
	desc.args[4] = req[2].addr;
	desc.args[5] = req[2].val;
	desc.args[6] = req[3].addr;
	desc.args[7] = req[3].val;
	desc.args[8] = req[4].addr;
	desc.args[9] = req[4].val;
	desc.arginfo = QCOM_SCM_ARGS(10);

	ret = qcom_scm_call(QCOM_SCM_SVC_HDCP, QCOM_SCM_CMD_HDCP, &desc);
	*resp = desc.ret[0];

	return ret;
}

int __qcom_scm_restart_proc(uint32_t proc_id, int restart, uint32_t *resp)
{
	int ret;
	struct qcom_scm_desc desc = {0};

	desc.args[0] = restart;
	desc.args[1] = 0;
	desc.arginfo = QCOM_SCM_ARGS(2);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, proc_id,
				&desc);
	*resp = desc.ret[0];

	return ret;
}

int __qcom_scm_pas_supported(uint32_t peripheral)
{
	int ret;
	struct qcom_scm_desc desc = {0};

	desc.args[0] = peripheral;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, QCOM_SCM_PAS_IS_SUPPORTED_CMD,
				&desc);

	return ret ? 0 : !!desc.ret[0];
}

int __qcom_scm_pas_init_image(struct device *dev, uint32_t peripheral, const void *metadata, size_t size)
{
    /*
	int ret;
	struct qcom_scm_desc desc = {0};
	uint32_t scm_ret;
	dma_addr_t mdata_phys;
	void *mdata_buf;

    // dev->coherent_dma_mask = DMA_BIT_MASK(sizeof(dma_addr_t) * 8);
    */

	/*
	 * During the scm call memory protection will be enabled for the meta
	 * data blob, so make sure it's physically contiguous, 4K aligned and
	 * non-cachable to avoid XPU violations.
	mdata_buf = dma_alloc_coherent(dev, size, &mdata_phys, GFP_KERNEL);
	if (!mdata_buf) {
		printf("Allocation of metadata buffer failed.\n");
		return -ENOMEM;
	}
	memcpy(mdata_buf, metadata, size);

	desc.args[0] = peripheral;
	desc.args[1] = mdata_phys;
	desc.arginfo = QCOM_SCM_ARGS(2, QCOM_SCM_VAL, QCOM_SCM_RW);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, QCOM_SCM_PAS_INIT_IMAGE_CMD,
				&desc);
	scm_ret = desc.ret[0];

	dma_free_coherent(dev, size, mdata_buf, mdata_phys);
	return ret ? : scm_ret;
	 */

    return -1;
}

int __qcom_scm_pas_mem_setup(uint32_t peripheral, phys_addr_t addr, phys_addr_t size)
{
	int ret;
	struct qcom_scm_desc desc = {0};
	uint32_t scm_ret;

	desc.args[0] = peripheral;
	desc.args[1] = addr;
	desc.args[2] = size;
	desc.arginfo = QCOM_SCM_ARGS(3);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, QCOM_SCM_PAS_MEM_SETUP_CMD,
				&desc);
	scm_ret = desc.ret[0];

	return ret ? : scm_ret;
}

int __qcom_scm_pas_auth_and_reset(uint32_t peripheral)
{
	int ret;
	struct qcom_scm_desc desc = {0};
	uint32_t scm_ret;

	desc.args[0] = peripheral;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, QCOM_SCM_PAS_AUTH_AND_RESET_CMD,
				&desc);
	scm_ret = desc.ret[0];

	return ret ? : scm_ret;
}

int __qcom_scm_pas_shutdown(uint32_t peripheral)
{
	int ret;
	struct qcom_scm_desc desc = {0};
	uint32_t scm_ret;

	desc.args[0] = peripheral;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, QCOM_SCM_PAS_SHUTDOWN_CMD,
			&desc);
	scm_ret = desc.ret[0];

	return ret ? : scm_ret;
}

int __qcom_scm_pil_init_image_cmd(uint32_t proc, uint64_t image_addr)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret;

	desc.args[0] = proc;
	desc.args[1] = image_addr;
	desc.arginfo = QCOM_SCM_ARGS(2, QCOM_SCM_VAL, QCOM_SCM_RW);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, PAS_INIT_IMAGE_CMD, &desc);
	scm_ret = desc.ret[0];

	if (ret)
		return ret;

	return scm_ret;
}

int __qcom_scm_pil_mem_setup_cmd(uint32_t proc, uint64_t start_addr, uint32_t len)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret;

	desc.args[0] = proc;
	desc.args[1] = start_addr;
	desc.args[2] = len;
	desc.arginfo = QCOM_SCM_ARGS(3);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, PAS_MEM_SETUP_CMD, &desc);
	scm_ret = desc.ret[0];

	if (ret)
		return ret;

	return scm_ret;
}

int __qcom_scm_pil_auth_and_reset_cmd(uint32_t proc)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret;

	desc.args[0] = proc;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, PAS_AUTH_AND_RESET_CMD, &desc);
	scm_ret = desc.ret[0];

	if (ret)
		return ret;

	return scm_ret;
}

int __qcom_scm_pil_shutdown_cmd(uint32_t proc)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret;

	desc.args[0] = proc;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(QCOM_SCM_SVC_PIL, PAS_SHUTDOWN_CMD, &desc);
	scm_ret = desc.ret[0];

	if (ret)
		return ret;

	return scm_ret;
}

#define SCM_SVC_UTIL			0x3
#define SCM_SVC_MP			0xc
#define IOMMU_DUMP_SMMU_FAULT_REGS	0xc

#define IOMMU_SECURE_PTBL_SIZE		3
#define IOMMU_SECURE_PTBL_INIT		4
#define IOMMU_SET_CP_POOL_SIZE		5
#define IOMMU_SECURE_MAP		6
#define IOMMU_SECURE_UNMAP		7
#define IOMMU_SECURE_MAP2		0xb
#define IOMMU_SECURE_MAP2_FLAT		0x12
#define IOMMU_SECURE_UNMAP2		0xc
#define IOMMU_SECURE_UNMAP2_FLAT	0x13

int __qcom_scm_iommu_dump_fault_regs(uint32_t id, uint32_t context, uint64_t addr, uint32_t len)
{
	struct qcom_scm_desc desc = {0};

	desc.args[0] = id;
	desc.args[1] = context;
	desc.args[2] = addr;
	desc.args[3] = len;
	desc.arginfo = QCOM_SCM_ARGS(4, QCOM_SCM_VAL, QCOM_SCM_VAL, QCOM_SCM_RW, QCOM_SCM_VAL);

	return qcom_scm_call(SCM_SVC_UTIL, IOMMU_DUMP_SMMU_FAULT_REGS, &desc);
}

int __qcom_scm_iommu_set_cp_pool_size(uint32_t size, uint32_t spare)
{
	struct qcom_scm_desc desc = {0};

	desc.args[0] = size;
	desc.args[1] = spare;
	desc.arginfo = QCOM_SCM_ARGS(2);

	return qcom_scm_call(SCM_SVC_MP, IOMMU_SET_CP_POOL_SIZE, &desc);
}

int __qcom_scm_iommu_secure_ptbl_size(uint32_t spare, int psize[2])
{
	struct qcom_scm_desc desc = {0};
	int ret;
	desc.args[0] = spare;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(SCM_SVC_MP, IOMMU_SECURE_PTBL_SIZE, &desc);

	psize[0] = desc.ret[0];
	psize[1] = desc.ret[1];

	return ret;
}

int __qcom_scm_iommu_secure_ptbl_init(uint64_t addr, uint32_t size, uint32_t spare)
{
	struct qcom_scm_desc desc = {0};
	int ret;
	uint64_t ptbl_ret;

	desc.args[0] = addr;
	desc.args[1] = size;
	desc.args[2] = spare;
	desc.arginfo = QCOM_SCM_ARGS(3, QCOM_SCM_RW, QCOM_SCM_VAL, QCOM_SCM_VAL);

	ret = qcom_scm_call(SCM_SVC_MP, IOMMU_SECURE_PTBL_INIT, &desc);

	ptbl_ret = desc.ret[0];

	if (ret)
		return ret;

	if (ptbl_ret)
		return ptbl_ret;

	return 0;
}

int __qcom_scm_iommu_secure_map(uint64_t list, uint32_t list_size, uint32_t size,
				uint32_t id, uint32_t ctx_id, uint64_t va, uint32_t info_size,
				uint32_t flags)
{
	struct qcom_scm_desc desc = {0};
	uint32_t resp;
	int ret;

	desc.args[0] = list;
	desc.args[1] = list_size;
	desc.args[2] = size;
	desc.args[3] = id;
	desc.args[4] = ctx_id;
	desc.args[5] = va;
	desc.args[6] = info_size;
	desc.args[7] = flags;
	desc.arginfo = QCOM_SCM_ARGS(8, QCOM_SCM_RW, QCOM_SCM_VAL, QCOM_SCM_VAL, QCOM_SCM_VAL,
				     QCOM_SCM_VAL, QCOM_SCM_VAL, QCOM_SCM_VAL, QCOM_SCM_VAL);

	ret = qcom_scm_call(SCM_SVC_MP, IOMMU_SECURE_MAP2_FLAT, &desc);

	resp = desc.ret[0];

	if (ret || resp)
		return -1;

	return 0;
}

int __qcom_scm_iommu_secure_unmap(uint32_t id, uint32_t ctx_id, uint64_t va,
				  uint32_t size, uint32_t flags)
{
	struct qcom_scm_desc desc = {0};

	desc.args[0] = id;
	desc.args[1] = ctx_id;
	desc.args[2] = va;
	desc.args[3] = size;
	desc.args[4] = flags;
	desc.arginfo = QCOM_SCM_ARGS(5);

	return qcom_scm_call(SCM_SVC_MP, IOMMU_SECURE_UNMAP2_FLAT, &desc);
}

int __qcom_scm_get_feat_version(uint32_t feat)
{
	struct qcom_scm_desc desc = {0};
	int ret;

	ret = __qcom_scm_is_call_available(SCM_SVC_INFO, GET_FEAT_VERSION_CMD);
	if (ret <= 0)
		return 0;

	desc.args[0] = feat;
	desc.arginfo = QCOM_SCM_ARGS(1);

	ret = qcom_scm_call(SCM_SVC_INFO, GET_FEAT_VERSION_CMD, &desc);
	if (!ret)
		return desc.ret[0];

	return 0;
}

#define RESTORE_SEC_CFG		2
int __qcom_scm_restore_sec_cfg(uint32_t device_id, uint32_t spare)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret = 0;

	desc.args[0] = device_id;
	desc.args[1] = spare;
	desc.arginfo = QCOM_SCM_ARGS(2);

	ret = qcom_scm_call(SCM_SVC_MP, RESTORE_SEC_CFG, &desc);

	scm_ret = desc.ret[0];

	if (ret || scm_ret)
		return ret ? ret : -1;

	return 0;
}

#define TZBSP_VIDEO_SET_STATE	0xa
int __qcom_scm_set_video_state(uint32_t state, uint32_t spare)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret;

	desc.args[0] = state;
	desc.args[1] = spare;
	desc.arginfo = QCOM_SCM_ARGS(2);

	ret = qcom_scm_call(SCM_SVC_BOOT, TZBSP_VIDEO_SET_STATE, &desc);

	scm_ret = desc.ret[0];

	if (ret || scm_ret)
		return ret ? ret : -1;

	return 0;
}

#define TZBSP_MEM_PROTECT_VIDEO_VAR	0x8

int __qcom_scm_mem_protect_video_var(uint32_t start, uint32_t size, uint32_t nonpixel_start,
				     uint32_t nonpixel_size)
{
	struct qcom_scm_desc desc = {0};
	int ret, scm_ret;

	desc.args[0] = start;
	desc.args[1] = size;
	desc.args[2] = nonpixel_start;
	desc.args[3] = nonpixel_size;
	desc.arginfo = QCOM_SCM_ARGS(4);

	ret = qcom_scm_call(SCM_SVC_MP, TZBSP_MEM_PROTECT_VIDEO_VAR, &desc);

	scm_ret = desc.ret[0];

	if (ret || scm_ret)
		return ret ? ret : -1;

	return 0;
}

#define QCOM_SCM_SVC_INFO              0x6
int qcom_scm_init(void)
{
	int ret;
	uint64_t ret1 = 0, x0;

	/* First try a SMC64 call */
	qcom_scm_version = QCOM_SCM_ARMV8_64;
	x0 = QCOM_SCM_SIP_FNID(QCOM_SCM_SVC_INFO, QCOM_IS_CALL_AVAIL_CMD) | SMC_ATOMIC_MASK;
	ret = __qcom_scm_call_armv8_64(x0 | SMC64_MASK, QCOM_SCM_ARGS(1), x0, 0, 0, 0,
				  &ret1, NULL, NULL);
	if (ret || !ret1) {
		/* Try SMC32 call */
		ret1 = 0;
		ret = __qcom_scm_call_armv8_32(x0, QCOM_SCM_ARGS(1), x0, 0, 0,
						0, &ret1, NULL, NULL);
		if (ret || !ret1)
			qcom_scm_version = QCOM_SCM_LEGACY;
		else
			qcom_scm_version = QCOM_SCM_ARMV8_32;
	} else
		qcom_scm_version_mask = SMC64_MASK;

	printf("qcom_scm_call: qcom_scm version is %x, mask is %x\n",
		 qcom_scm_version, qcom_scm_version_mask);

	return 0;
}
