#include <common.h>
#include <command.h>
#include <cpu.h>
#include <dm.h>
#include <errno.h>

int msm_cpu_boot(unsigned int cpu);
int msm_cpu_prepare(unsigned int cpu, void *start_addr);

static int do_ssa(cmd_tbl_t *cmdtp, int flag, int argc,
			 char *const argv[])
{

    if(argc == 1)
		return CMD_RET_USAGE;

    void* start_addr = (void*) simple_strtoull(argv[1], NULL, 16);

    for(uint32_t i = 1; i < 4; i++)
    {
        msm_cpu_prepare(i, start_addr);
        msm_cpu_boot(i);
    }

    return 0;
}

U_BOOT_CMD(
	ssa, 2, 0, do_ssa,
	"Set Secondary Address: Wake up and set the secondary address",
	"ssa address\n"
    "address is the location where you want your secondary cpus to be\n"
);
