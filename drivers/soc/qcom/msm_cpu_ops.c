/* Copyright (c) 2014, The Linux Foundation. All rights reserved.
 * Copyright (c) 2013 ARM Ltd.
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

/* MSM ARMv8 CPU Operations
 * Based on arch/arm64/kernel/smp_spin_table.c
 */

//#include <linux/bitops.h>
//#include <linux/cpu.h>
//#include <linux/cpumask.h>
//#include <linux/delay.h>
//#include <linux/init.h>
//#include <linux/io.h>
//#include <linux/of.h>
//#include <linux/of_address.h>
//#include <linux/smp.h>
//#include <linux/qcom_scm.h>

//#include <asm/barrier.h>
//#include <asm/cacheflush.h>
//#include <asm/cpu_ops.h>
//#include <asm/cputype.h>
//#include <asm/smp_plat.h>


#include "common.h"
#include <asm/io.h>

int qcom_scm_set_cold_boot_addr(void *entry, const uint64_t cpus);

//static DEFINE_RAW_SPINLOCK(boot_lock);

// DEFINE_PER_CPU(int, cold_boot_done);

#if 0
static int cold_boot_flags[] = {
	0,
	QCOM_SCM_FLAG_COLDBOOT_CPU1,
	QCOM_SCM_FLAG_COLDBOOT_CPU2,
	QCOM_SCM_FLAG_COLDBOOT_CPU3,
};
#endif

/* CPU power domain register offsets */
#define CPU_PWR_CTL		0x4
#define CPU_PWR_GATE_CTL	0x14
#define LDO_BHS_PWR_CTL		0x28

/* L2 power domain register offsets */
#define L2_PWR_CTL_OVERRIDE	0xc
#define L2_PWR_CTL		0x14
#define L2_PWR_STATUS		0x18
#define	L2_CORE_CBCR		0x58
#define L1_RST_DIS		0x284

#define L2_SPM_STS		0xc
#define L2_VREG_CTL		0x1c

#define SCM_IO_READ		1
#define SCM_IO_WRITE		2



static void uwr32(uint32_t v, uint64_t a)
{
	writel(v, a);
}

static uint32_t urd32(uint64_t a)
{
	return readl(a);
}


/*
 * struct msm_l2ccc_of_info: represents of data for l2 cache clock controller.
 * @compat: compat string for l2 cache clock controller
 * @l2_pon: l2 cache power on routine
 */
struct msm_l2ccc_of_info {
	const char *compat;
	int (*l2_power_on) (uint32_t l2_mask, int cpu);
	uint32_t l2_power_on_mask;
};


//static int power_on_l2_msm8916(struct device_node *l2ccc_node, uint32_t pon_mask, int cpu)
int power_on_l2_msm8916(uint32_t pon_mask, int cpu)
{
	uint32_t pon_status;
	uint64_t l2_base;

    l2_base = (uint64_t)0x0b011000;

	/* Skip power-on sequence if l2 cache is already powered up*/
	pon_status = (urd32(l2_base + L2_PWR_STATUS) & pon_mask) == pon_mask;

	if (pon_status) {
        //printf("L2 is already powered on\n");
		return 0;
	}

	/* Close L2/SCU Logic GDHS and power up the cache */
	uwr32(0x10D700, l2_base + L2_PWR_CTL);

	/* Assert PRESETDBGn */
	uwr32(0x400000, l2_base + L2_PWR_CTL_OVERRIDE);
	mb();
	udelay(2);

	/* De-assert L2/SCU memory Clamp */
	uwr32(0x101700, l2_base + L2_PWR_CTL);

	/* Wakeup L2/SCU RAMs by deasserting sleep signals */
	uwr32(0x101703, l2_base + L2_PWR_CTL);
	mb();
	udelay(2);

	/* Enable clocks via SW_CLK_EN */
	uwr32(0x01, l2_base + L2_CORE_CBCR);

	/* De-assert L2/SCU logic clamp */
	uwr32(0x101603, l2_base + L2_PWR_CTL);
	mb();
	udelay(2);

	/* De-assert PRESSETDBg */
	uwr32(0x0, l2_base + L2_PWR_CTL_OVERRIDE);

	/* De-assert L2/SCU Logic reset */
	uwr32(0x100203, l2_base + L2_PWR_CTL);
	mb();
	udelay(54);

	/* Turn on the PMIC_APC */
	uwr32(0x10100203, l2_base + L2_PWR_CTL);

	/* Set H/W clock control for the cpu CBC block */
	uwr32(0x03, l2_base + L2_CORE_CBCR);
	mb();

	return 0;
}

static const struct msm_l2ccc_of_info l2ccc_info[] = {
	{
		.compat = "qcom,8916-l2ccc",
		.l2_power_on = power_on_l2_msm8916,
		.l2_power_on_mask = BIT(9),
	},
};

static int power_on_l2_cache(int cpu)
{
//	int ret, i;
	int i;
//	const char *compat;

//  ret = of_property_read_string(l2ccc_node, "compatible", &compat);
//  if (ret)
//  	return ret;

	for (i = 0; i < ARRAY_SIZE(l2ccc_info); i++) {
		const struct msm_l2ccc_of_info *ptr = &l2ccc_info[i];

        return ptr->l2_power_on(ptr->l2_power_on_mask, cpu);
	}
	printf("Compat string not found for L2CCC node\n");
	return -1;
}

static int msm_unclamp_secondary_arm_cpu(unsigned int cpu)
{

	int ret = 0;
	uint64_t reg;
/*
//	struct device_node *cpu_node, *acc_node, *l2_node, *l2ccc_node;
	//void __iomem *reg;

//  cpu_node = of_get_cpu_node(cpu, NULL);
//  if (!cpu_node)
//  	return -ENODEV;

//  acc_node = of_parse_phandle(cpu_node, "qcom,acc", 0);
//  if (!acc_node) {
//  		ret = -ENODEV;
//  		goto out_acc;
//  }

//  l2_node = of_parse_phandle(cpu_node, "next-level-cache", 0);
//  if (!l2_node) {
//  	ret = -ENODEV;
//  	goto out_l2;
//  }

//  l2ccc_node = of_parse_phandle(l2_node, "power-domain", 0);
//  if (!l2ccc_node) {
//  	ret = -ENODEV;
//  	goto out_l2;
//  }
*/

	/* Ensure L2-cache of the CPU is powered on before
	 * unclamping cpu power rails.
	 */
	ret = power_on_l2_cache(cpu);
	if (ret) {
		printf("L2 cache power up failed for CPU%d\n", cpu);
		goto out_l2ccc;
	}

//  reg = of_iomap(acc_node, 0);
//  if (!reg) {
//  	ret = -ENOMEM;
//  	goto out_acc_reg;
//  }

    // We should really read this from the tree, For now hard code
    uint64_t acc_addrs[] = {
        0x0b088000,
        0x0b098000,
        0x0b0a8000,
        0x0b0b8000
    };

    reg = acc_addrs[cpu];

	/* Assert Reset on cpu-n */
	uwr32(0x00000033, reg + CPU_PWR_CTL);
	mb();

	/*Program skew to 16 X0 clock cycles*/
	uwr32(0x10000001, reg + CPU_PWR_GATE_CTL);
	mb();
	udelay(2);

	/* De-assert coremem clamp */
	uwr32(0x00000031, reg + CPU_PWR_CTL);
	mb();

	/* Close coremem array gdhs */
	uwr32(0x00000039, reg + CPU_PWR_CTL);
	mb();
	udelay(2);

	/* De-assert cpu-n clamp */
	uwr32(0x00020038, reg + CPU_PWR_CTL);
	mb();
	udelay(2);

	/* De-assert cpu-n reset */
	uwr32(0x00020008, reg + CPU_PWR_CTL);
	mb();

	/* Assert PWRDUP signal on core-n */
	uwr32(0x00020088, reg + CPU_PWR_CTL);
	mb();

	/* Secondary CPU-N is now alive */
	// iounmap(reg);
//out_acc_reg:
//	of_node_put(l2ccc_node);
out_l2ccc:
//	of_node_put(l2_node);
//out_l2:
//	of_node_put(acc_node);
//out_acc:
//	of_node_put(cpu_node);

	return ret;
}

static void write_pen_release(u64 val)
{
    /*
	void *start = (void *)&secondary_holding_pen_release;
	unsigned long size = sizeof(secondary_holding_pen_release);

	secondary_holding_pen_release = val;
	smp_wmb();
	__flush_dcache_area(start, size);
    */
}

static int secondary_pen_release(unsigned int cpu)
{
	//unsigned long timeout;

	/*
	 * Set synchronisation state between this boot processor
	 * and the secondary one
	 */
//	raw_spin_lock(&boot_lock);
    /*
	write_pen_release(cpu_logical_map(cpu));

	timeout = jiffies + (1 * HZ);
	while (time_before(jiffies, timeout)) {
		if (secondary_holding_pen_release == INVALID_HWID)
			break;
		udelay(10);
	}
    */
//	raw_spin_unlock(&boot_lock);

	// return secondary_holding_pen_release != INVALID_HWID ? -ENOSYS : 0;

    return 0;
}

static int msm_cpu_init(unsigned int cpu)
{
	/* Mark CPU0 cold boot flag as done */
    /*
	if (!cpu && !per_cpu(cold_boot_done, cpu))
		per_cpu(cold_boot_done, cpu) = true;
        */

	return 0;
}

int msm_cpu_prepare(unsigned int cpu, void* start_addr)
{
	// const cpumask_t *mask = cpumask_of(cpu);

	if (qcom_scm_set_cold_boot_addr(start_addr, cpu)) {
	//if (qcom_scm_set_cold_boot_addr(_start, cpu)) {
		printf("CPU%d:Failed to set boot address\n", cpu);
		return -1;
	}

	return 0;
}

int msm_cpu_boot(unsigned int cpu)
{
	int ret = 0;

    ret = msm_unclamp_secondary_arm_cpu(cpu);
    if (ret)
        return ret;

    return ret;

    /*
	if (per_cpu(cold_boot_done, cpu) == false) {
		ret = msm_unclamp_secondary_arm_cpu(cpu);
		if (ret)
			return ret;
		per_cpu(cold_boot_done, cpu) = true;
	}
    */
	// return secondary_pen_release(cpu);
}

void msm_cpu_postboot(void)
{
	/*
	 * Let the primary processor know we're out of the pen.
	 */
	// write_pen_release(INVALID_HWID);

	/*
	 * Synchronise with the boot thread.
	 */
//	raw_spin_lock(&boot_lock);
//	raw_spin_unlock(&boot_lock);
}

/*
static const struct cpu_operations msm_cortex_a_ops = {
	.name		= "qcom,arm-cortex-acc",
	.cpu_init	= msm_cpu_init,
	.cpu_prepare	= msm_cpu_prepare,
	.cpu_boot	= msm_cpu_boot,
	.cpu_postboot	= msm_cpu_postboot,
};
*/
// CPU_METHOD_OF_DECLARE(msm_cortex_a_ops, &msm_cortex_a_ops);