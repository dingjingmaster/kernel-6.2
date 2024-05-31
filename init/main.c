// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  GK 2/5/95  -  Changed to support mounting root fs via NFS
 *  Added initrd & change_root: Werner Almesberger & Hans Lermen, Feb '96
 *  Moan early if gcc is old, avoiding bogus kernels - Paul Gortmaker, May '96
 *  Simplified starting of init:  Michael A. Griffith <grif@acm.org>
 */

#define DEBUG		/* Enable initcall_debug */

#include <linux/types.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/stackprotector.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/acpi.h>
#include <linux/bootconfig.h>
#include <linux/console.h>
#include <linux/nmi.h>
#include <linux/percpu.h>
#include <linux/kmod.h>
#include <linux/kprobes.h>
#include <linux/kmsan.h>
#include <linux/vmalloc.h>
#include <linux/kernel_stat.h>
#include <linux/start_kernel.h>
#include <linux/security.h>
#include <linux/smp.h>
#include <linux/profile.h>
#include <linux/kfence.h>
#include <linux/rcupdate.h>
#include <linux/srcu.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/buildid.h>
#include <linux/writeback.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/cgroup.h>
#include <linux/efi.h>
#include <linux/tick.h>
#include <linux/sched/isolation.h>
#include <linux/interrupt.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <linux/key.h>
#include <linux/page_ext.h>
#include <linux/debug_locks.h>
#include <linux/debugobjects.h>
#include <linux/lockdep.h>
#include <linux/kmemleak.h>
#include <linux/padata.h>
#include <linux/pid_namespace.h>
#include <linux/device/driver.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/sched/init.h>
#include <linux/signal.h>
#include <linux/idr.h>
#include <linux/kgdb.h>
#include <linux/ftrace.h>
#include <linux/async.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/pti.h>
#include <linux/blkdev.h>
#include <linux/sched/clock.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/context_tracking.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/integrity.h>
#include <linux/proc_ns.h>
#include <linux/io.h>
#include <linux/cache.h>
#include <linux/rodata_test.h>
#include <linux/jump_label.h>
#include <linux/mem_encrypt.h>
#include <linux/kcsan.h>
#include <linux/init_syscalls.h>
#include <linux/stackdepot.h>
#include <linux/randomize_kstack.h>
#include <net/net_namespace.h>

#include <asm/io.h>
#include <asm/bugs.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/cacheflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/initcall.h>

#include <kunit/test.h>

static int kernel_init(void *);

extern void init_IRQ(void);
extern void radix_tree_init(void);
extern void maple_tree_init(void);

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/*
 * Boot command-line arguments
 */
#define MAX_INIT_ARGS CONFIG_INIT_ENV_ARG_LIMIT
#define MAX_INIT_ENVS CONFIG_INIT_ENV_ARG_LIMIT

extern void time_init(void);
/* Default late time init is NULL. archs can override this later. */
void (*__initdata late_time_init)(void);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];
/* Untouched saved command line (eg. for /proc) */
char *saved_command_line __ro_after_init;
unsigned int saved_command_line_len __ro_after_init;
/* Command line for parameter parsing */
static char *static_command_line;
/* Untouched extra command line */
static char *extra_command_line;
/* Extra init arguments */
static char *extra_init_args;

#ifdef CONFIG_BOOT_CONFIG
/* Is bootconfig on command line? */
static bool bootconfig_found;
static size_t initargs_offs;
#else
# define bootconfig_found false
# define initargs_offs 0
#endif

static char *execute_command;
static char *ramdisk_execute_command = "/init";

/*
 * Used to generate warnings if static_key manipulation functions are used
 * before jump_label_init is called.
 */
bool static_key_initialized __read_mostly;
EXPORT_SYMBOL_GPL(static_key_initialized);

/*
 * If set, this is an indication to the drivers that reset the underlying
 * device before going ahead with the initialization otherwise driver might
 * rely on the BIOS and skip the reset operation.
 *
 * This is useful if kernel is booting in an unreliable environment.
 * For ex. kdump situation where previous kernel has crashed, BIOS has been
 * skipped and devices will be in unknown state.
 */
unsigned int reset_devices;
EXPORT_SYMBOL(reset_devices);

static int __init set_reset_devices(char *str)
{
	reset_devices = 1;
	return 1;
}

__setup("reset_devices", set_reset_devices);

static const char *argv_init[MAX_INIT_ARGS+2] = { "init", NULL, };
const char *envp_init[MAX_INIT_ENVS+2] = { "HOME=/", "TERM=linux", NULL, };
static const char *panic_later, *panic_param;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

static bool __init obsolete_checksetup(char *line)
{
	const struct obs_kernel_param *p;
	bool had_early_param = false;

	p = __setup_start;
	do {
		int n = strlen(p->str);
		if (parameqn(line, p->str, n)) {
			if (p->early) {
				/* Already done in parse_early_param?
				 * (Needs exact match on param part).
				 * Keep iterating, as we can have early
				 * params and __setups of same names 8( */
				if (line[n] == '\0' || line[n] == '=')
					had_early_param = true;
			} else if (!p->setup_func) {
				pr_warn("Parameter %s is obsolete, ignored\n",
					p->str);
				return true;
			} else if (p->setup_func(line + n))
				return true;
		}
		p++;
	} while (p < __setup_end);

	return had_early_param;
}

/*
 * This should be approx 2 Bo*oMips to start (note initial shift), and will
 * still work even if initially too large, it will just take slightly longer
 */
unsigned long loops_per_jiffy = (1<<12);
EXPORT_SYMBOL(loops_per_jiffy);

static int __init debug_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_DEBUG;
	return 0;
}

static int __init quiet_kernel(char *str)
{
	console_loglevel = CONSOLE_LOGLEVEL_QUIET;
	return 0;
}

early_param("debug", debug_kernel);
early_param("quiet", quiet_kernel);

static int __init loglevel(char *str)
{
	int newlevel;

	/*
	 * Only update loglevel value when a correct setting was passed,
	 * to prevent blind crashes (when loglevel being set to 0) that
	 * are quite hard to debug
	 */
	if (get_option(&str, &newlevel)) {
		console_loglevel = newlevel;
		return 0;
	}

	return -EINVAL;
}

early_param("loglevel", loglevel);

#ifdef CONFIG_BLK_DEV_INITRD
static void * __init get_boot_config_from_initrd(size_t *_size)
{
	u32 size, csum;
	char *data;
	u32 *hdr;
	int i;

	if (!initrd_end)
		return NULL;

	data = (char *)initrd_end - BOOTCONFIG_MAGIC_LEN;
	/*
	 * Since Grub may align the size of initrd to 4, we must
	 * check the preceding 3 bytes as well.
	 */
	for (i = 0; i < 4; i++) {
		if (!memcmp(data, BOOTCONFIG_MAGIC, BOOTCONFIG_MAGIC_LEN))
			goto found;
		data--;
	}
	return NULL;

found:
	hdr = (u32 *)(data - 8);
	size = le32_to_cpu(hdr[0]);
	csum = le32_to_cpu(hdr[1]);

	data = ((void *)hdr) - size;
	if ((unsigned long)data < initrd_start) {
		pr_err("bootconfig size %d is greater than initrd size %ld\n",
			size, initrd_end - initrd_start);
		return NULL;
	}

	if (xbc_calc_checksum(data, size) != csum) {
		pr_err("bootconfig checksum failed\n");
		return NULL;
	}

	/* Remove bootconfig from initramfs/initrd */
	initrd_end = (unsigned long)data;
	if (_size)
		*_size = size;

	return data;
}
#else
static void * __init get_boot_config_from_initrd(size_t *_size)
{
	return NULL;
}
#endif

#ifdef CONFIG_BOOT_CONFIG

static char xbc_namebuf[XBC_KEYLEN_MAX] __initdata;

#define rest(dst, end) ((end) > (dst) ? (end) - (dst) : 0)

static int __init xbc_snprint_cmdline(char *buf, size_t size,
				      struct xbc_node *root)
{
	struct xbc_node *knode, *vnode;
	char *end = buf + size;
	const char *val;
	int ret;

	xbc_node_for_each_key_value(root, knode, val) {
		ret = xbc_node_compose_key_after(root, knode,
					xbc_namebuf, XBC_KEYLEN_MAX);
		if (ret < 0)
			return ret;

		vnode = xbc_node_get_child(knode);
		if (!vnode) {
			ret = snprintf(buf, rest(buf, end), "%s ", xbc_namebuf);
			if (ret < 0)
				return ret;
			buf += ret;
			continue;
		}
		xbc_array_for_each_value(vnode, val) {
			ret = snprintf(buf, rest(buf, end), "%s=\"%s\" ",
				       xbc_namebuf, val);
			if (ret < 0)
				return ret;
			buf += ret;
		}
	}

	return buf - (end - size);
}
#undef rest

/* Make an extra command line under given key word */
static char * __init xbc_make_cmdline(const char *key)
{
	struct xbc_node *root;
	char *new_cmdline;
	int ret, len = 0;

	root = xbc_find_node(key);
	if (!root)
		return NULL;

	/* Count required buffer size */
	len = xbc_snprint_cmdline(NULL, 0, root);
	if (len <= 0)
		return NULL;

	new_cmdline = memblock_alloc(len + 1, SMP_CACHE_BYTES);
	if (!new_cmdline) {
		pr_err("Failed to allocate memory for extra kernel cmdline.\n");
		return NULL;
	}

	ret = xbc_snprint_cmdline(new_cmdline, len + 1, root);
	if (ret < 0 || ret > len) {
		pr_err("Failed to print extra kernel cmdline.\n");
		memblock_free(new_cmdline, len + 1);
		return NULL;
	}

	return new_cmdline;
}

static int __init bootconfig_params(char *param, char *val,
				    const char *unused, void *arg)
{
	if (strcmp(param, "bootconfig") == 0) {
		bootconfig_found = true;
	}
	return 0;
}

static int __init warn_bootconfig(char *str)
{
	/* The 'bootconfig' has been handled by bootconfig_params(). */
	return 0;
}

static void __init setup_boot_config(void)
{
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;
	const char *msg, *data;
	int pos, ret;
	size_t size;
	char *err;

	/* Cut out the bootconfig data even if we have no bootconfig option */
	data = get_boot_config_from_initrd(&size);
	/* If there is no bootconfig in initrd, try embedded one. */
	if (!data)
		data = xbc_get_embedded_bootconfig(&size);

	strscpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	err = parse_args("bootconfig", tmp_cmdline, NULL, 0, 0, 0, NULL,
			 bootconfig_params);

	if (IS_ERR(err) || !bootconfig_found)
		return;

	/* parse_args() stops at the next param of '--' and returns an address */
	if (err)
		initargs_offs = err - tmp_cmdline;

	if (!data) {
		pr_err("'bootconfig' found on command line, but no bootconfig found\n");
		return;
	}

	if (size >= XBC_DATA_MAX) {
		pr_err("bootconfig size %ld greater than max size %d\n",
			(long)size, XBC_DATA_MAX);
		return;
	}

	ret = xbc_init(data, size, &msg, &pos);
	if (ret < 0) {
		if (pos < 0)
			pr_err("Failed to init bootconfig: %s.\n", msg);
		else
			pr_err("Failed to parse bootconfig: %s at %d.\n",
				msg, pos);
	} else {
		xbc_get_info(&ret, NULL);
		pr_info("Load bootconfig: %ld bytes %d nodes\n", (long)size, ret);
		/* keys starting with "kernel." are passed via cmdline */
		extra_command_line = xbc_make_cmdline("kernel");
		/* Also, "init." keys are init arguments */
		extra_init_args = xbc_make_cmdline("init");
	}
	return;
}

static void __init exit_boot_config(void)
{
	xbc_exit();
}

#else	/* !CONFIG_BOOT_CONFIG */

static void __init setup_boot_config(void)
{
	/* Remove bootconfig data from initrd */
	get_boot_config_from_initrd(NULL);
}

static int __init warn_bootconfig(char *str)
{
	pr_warn("WARNING: 'bootconfig' found on the kernel command line but CONFIG_BOOT_CONFIG is not set.\n");
	return 0;
}

#define exit_boot_config()	do {} while (0)

#endif	/* CONFIG_BOOT_CONFIG */

early_param("bootconfig", warn_bootconfig);

/* Change NUL term back to "=", to make "param" the whole string. */
static void __init repair_env_string(char *param, char *val)
{
	if (val) {
		/* param=val or param="val"? */
		if (val == param+strlen(param)+1)
			val[-1] = '=';
		else if (val == param+strlen(param)+2) {
			val[-2] = '=';
			memmove(val-1, val, strlen(val)+1);
		} else
			BUG();
	}
}

/* Anything after -- gets handed straight to init. */
static int __init set_init_arg(char *param, char *val,
			       const char *unused, void *arg)
{
	unsigned int i;

	if (panic_later)
		return 0;

	repair_env_string(param, val);

	for (i = 0; argv_init[i]; i++) {
		if (i == MAX_INIT_ARGS) {
			panic_later = "init";
			panic_param = param;
			return 0;
		}
	}
	argv_init[i] = param;
	return 0;
}

/*
 * Unknown boot options get handed to init, unless they look like
 * unused parameters (modprobe will find them in /proc/cmdline).
 */
static int __init unknown_bootoption(char *param, char *val,
				     const char *unused, void *arg)
{
	size_t len = strlen(param);

	repair_env_string(param, val);

	/* Handle obsolete-style parameters */
	if (obsolete_checksetup(param))
		return 0;

	/* Unused module parameter. */
	if (strnchr(param, len, '.'))
		return 0;

	if (panic_later)
		return 0;

	if (val) {
		/* Environment option */
		unsigned int i;
		for (i = 0; envp_init[i]; i++) {
			if (i == MAX_INIT_ENVS) {
				panic_later = "env";
				panic_param = param;
			}
			if (!strncmp(param, envp_init[i], len+1))
				break;
		}
		envp_init[i] = param;
	} else {
		/* Command line option */
		unsigned int i;
		for (i = 0; argv_init[i]; i++) {
			if (i == MAX_INIT_ARGS) {
				panic_later = "init";
				panic_param = param;
			}
		}
		argv_init[i] = param;
	}
	return 0;
}

static int __init init_setup(char *str)
{
	unsigned int i;

	execute_command = str;
	/*
	 * In case LILO is going to boot us with default command line,
	 * it prepends "auto" before the whole cmdline which makes
	 * the shell think it should execute a script with such name.
	 * So we ignore all arguments entered _before_ init=... [MJ]
	 */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
	unsigned int i;

	ramdisk_execute_command = str;
	/* See "auto" comment in init_setup */
	for (i = 1; i < MAX_INIT_ARGS; i++)
		argv_init[i] = NULL;
	return 1;
}
__setup("rdinit=", rdinit_setup);

#ifndef CONFIG_SMP
static const unsigned int setup_max_cpus = NR_CPUS;
static inline void setup_nr_cpu_ids(void) { }
static inline void smp_prepare_cpus(unsigned int maxcpus) { }
#endif

/*
 * We need to store the untouched command line for future reference.
 * We also need to store the touched command line since the parameter
 * parsing is performed in place, and we should allow a component to
 * store reference of name/value for future reference.
 */
static void __init setup_command_line(char *command_line)
{
	size_t len, xlen = 0, ilen = 0;

	if (extra_command_line)
		xlen = strlen(extra_command_line);
	if (extra_init_args)
		ilen = strlen(extra_init_args) + 4; /* for " -- " */

	len = xlen + strlen(boot_command_line) + 1;

	saved_command_line = memblock_alloc(len + ilen, SMP_CACHE_BYTES);
	if (!saved_command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len + ilen);

	static_command_line = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!static_command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	if (xlen) {
		/*
		 * We have to put extra_command_line before boot command
		 * lines because there could be dashes (separator of init
		 * command line) in the command lines.
		 */
		strcpy(saved_command_line, extra_command_line);
		strcpy(static_command_line, extra_command_line);
	}
	strcpy(saved_command_line + xlen, boot_command_line);
	strcpy(static_command_line + xlen, command_line);

	if (ilen) {
		/*
		 * Append supplemental init boot args to saved_command_line
		 * so that user can check what command line options passed
		 * to init.
		 * The order should always be
		 * " -- "[bootconfig init-param][cmdline init-param]
		 */
		if (initargs_offs) {
			len = xlen + initargs_offs;
			strcpy(saved_command_line + len, extra_init_args);
			len += ilen - 4;	/* strlen(extra_init_args) */
			strcpy(saved_command_line + len,
				boot_command_line + initargs_offs - 1);
		} else {
			len = strlen(saved_command_line);
			strcpy(saved_command_line + len, " -- ");
			len += 4;
			strcpy(saved_command_line + len, extra_init_args);
		}
	}

	saved_command_line_len = strlen(saved_command_line);
}

/*
 * We need to finalize in a non-__init function or else race conditions
 * between the root thread and the init thread may cause start_kernel to
 * be reaped by free_initmem before the root thread has proceeded to
 * cpu_idle.
 *
 * gcc-3.4 accidentally inlines this function, so use noinline.
 */

static __initdata DECLARE_COMPLETION(kthreadd_done);

noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;

	rcu_scheduler_starting();
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = user_mode_thread(kernel_init, NULL, CLONE_FS);
	/*
	 * Pin init on the boot CPU. Task migration is not properly working
	 * until sched_init_smp() has been run. It will set the allowed
	 * CPUs for init to the non isolated CPUs.
	 */
	rcu_read_lock();
	tsk = find_task_by_pid_ns(pid, &init_pid_ns);
	tsk->flags |= PF_NO_SETAFFINITY;
	set_cpus_allowed_ptr(tsk, cpumask_of(smp_processor_id()));
	rcu_read_unlock();

	numa_default_policy();
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
	rcu_read_lock();
	kthreadd_task = find_task_by_pid_ns(pid, &init_pid_ns);
	rcu_read_unlock();

	/*
	 * Enable might_sleep() and smp_processor_id() checks.
	 * They cannot be enabled earlier because with CONFIG_PREEMPTION=y
	 * kernel_thread() would trigger might_sleep() splats. With
	 * CONFIG_PREEMPT_VOLUNTARY=y the init task might have scheduled
	 * already, but it's stuck on the kthreadd_done completion.
	 */
	system_state = SYSTEM_SCHEDULING;

	complete(&kthreadd_done);

	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);
}

/* Check for early params. */
static int __init do_early_param(char *param, char *val,
				 const char *unused, void *arg)
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {
		if ((p->early && parameq(param, p->str)) ||
		    (strcmp(param, "console") == 0 &&
		     strcmp(p->str, "earlycon") == 0)
		) {
			if (p->setup_func(val) != 0)
				pr_warn("Malformed early option '%s'\n", param);
		}
	}
	/* We accept everything at this stage. */
	return 0;
}

void __init parse_early_options(char *cmdline)
{
	parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
		   do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
	static int done __initdata;
	static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

	if (done)
		return;

	/* All fall through to do_early_param. */
	strscpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
	parse_early_options(tmp_cmdline);
	done = 1;
}

void __init __weak arch_post_acpi_subsys_init(void) { }

void __init __weak smp_setup_processor_id(void)
{
}

# if THREAD_SIZE >= PAGE_SIZE
void __init __weak thread_stack_cache_init(void)
{
}
#endif

void __init __weak mem_encrypt_init(void) { }

void __init __weak poking_init(void) { }

void __init __weak pgtable_cache_init(void) { }

void __init __weak trap_init(void) { }

bool initcall_debug;
core_param(initcall_debug, initcall_debug, bool, 0644);

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void);
#else
static inline void initcall_debug_enable(void)
{
}
#endif

/* Report memory auto-initialization states for this boot. */
static void __init report_meminit(void)
{
	const char *stack;

	if (IS_ENABLED(CONFIG_INIT_STACK_ALL_PATTERN))
		stack = "all(pattern)";
	else if (IS_ENABLED(CONFIG_INIT_STACK_ALL_ZERO))
		stack = "all(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL))
		stack = "byref_all(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF))
		stack = "byref(zero)";
	else if (IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK_USER))
		stack = "__user(zero)";
	else
		stack = "off";

	pr_info("mem auto-init: stack:%s, heap alloc:%s, heap free:%s\n",
		stack, want_init_on_alloc(GFP_KERNEL) ? "on" : "off",
		want_init_on_free() ? "on" : "off");
	if (want_init_on_free())
		pr_info("mem auto-init: clearing system memory may take some time...\n");
}

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
	/*
	 * page_ext requires contiguous pages,
	 * bigger than MAX_ORDER unless SPARSEMEM.
	 */
	page_ext_init_flatmem();
	init_mem_debugging_and_hardening();
	kfence_alloc_pool();
	report_meminit();
	kmsan_init_shadow();
	stack_depot_early_init();
	mem_init();
	mem_init_print_info();
	kmem_cache_init();
	/*
	 * page_owner must be initialized after buddy is ready, and also after
	 * slab is ready so that stack_depot_init() works properly
	 */
	page_ext_init_flatmem_late();
	kmemleak_init();
	pgtable_init();
	debug_objects_mem_init();
	vmalloc_init();
	/* Should be run after vmap initialization */
	if (early_page_ext_enabled())
		page_ext_init();
	/* Should be run before the first non-init thread is created */
	init_espfix_bsp();
	/* Should be run after espfix64 is set up. */
	pti_init();
	kmsan_init_runtime();
	mm_cache_init();
}

#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
			   randomize_kstack_offset);
DEFINE_PER_CPU(u32, kstack_offset);

static int __init early_randomize_kstack_offset(char *buf)
{
	int ret;
	bool bool_result;

	ret = kstrtobool(buf, &bool_result);
	if (ret)
		return ret;

	if (bool_result)
		static_branch_enable(&randomize_kstack_offset);
	else
		static_branch_disable(&randomize_kstack_offset);
	return 0;
}
early_param("randomize_kstack_offset", early_randomize_kstack_offset);
#endif

void __init __weak arch_call_rest_init(void)
{
	rest_init();
}

static void __init print_unknown_bootoptions(void)
{
	char *unknown_options;
	char *end;
	const char *const *p;
	size_t len;

	if (panic_later || (!argv_init[1] && !envp_init[2]))
		return;

	/*
	 * Determine how many options we have to print out, plus a space
	 * before each
	 */
	len = 1; /* null terminator */
	for (p = &argv_init[1]; *p; p++) {
		len++;
		len += strlen(*p);
	}
	for (p = &envp_init[2]; *p; p++) {
		len++;
		len += strlen(*p);
	}

	unknown_options = memblock_alloc(len, SMP_CACHE_BYTES);
	if (!unknown_options) {
		pr_err("%s: Failed to allocate %zu bytes\n",
			__func__, len);
		return;
	}
	end = unknown_options;

	for (p = &argv_init[1]; *p; p++)
		end += sprintf(end, " %s", *p);
	for (p = &envp_init[2]; *p; p++)
		end += sprintf(end, " %s", *p);

	/* Start at unknown_options[1] to skip the initial space */
	pr_notice("Unknown kernel command line parameters \"%s\", will be passed to user space.\n",
		&unknown_options[1]);
	memblock_free(unknown_options, len);
}

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
	char *command_line;
	char *after_dashes;

    /**
     * kernel/fork.c
     *
     * init_task + thread_info 32 字节对齐处写入栈越界标记。
     */
	set_task_stack_end_magic(&init_task);

    /**
     *  FIXME:// 空实现
     * 1. 为每个处理器分配一个唯一的ID
     * 2. 初始化处理器本地数据结构；例如：每个处理器的栈、寄存器状态等
     * 3. 设置处理器的特定资源，比如时钟中断和本地中断控制器
     * 4. 设置处理器之间的通信机制，如：Inter-Processor Interrupts(IPI)
     * 5. 进行任何其它必要的平台特定的初始化
     */
	smp_setup_processor_id();
    
    /**
     * lib/debugobjects.c
     * 内核调试相关数据结构初始化
     */
	debug_objects_early_init();             

    /**
     * lib/buildid.c
     *
     * 编译内核时候生成构建ID，此ID用于确定内核版本。
     * 此ID由解析内核文件获得
     */
	init_vmlinux_build_id();

    /**
     * FIXME:// 未定义？
     *
     * 初始化 cgroup 子系统。cgroup用于限制、记录、隔离进程组使用的物理资源（如：CPU、内存、磁盘ID等）
     *
     * 1. 初始化数据结构
     * 2. 注册子系统
     * 3. 设置默认值
     * 4. 初始化资源控制器
     * 5. 创建根cgroup
     */
	cgroup_init_early();

    /**
     * 用于在当前处理器上禁用本地中断。
     *
     * 多处理器中，每个处理器都可以独立禁用或启用它们自己的中断。
     * 一般实现方式是：控制寄存器写入值，以清除允许中断位。
     */
	local_irq_disable();

    /**
     * true: 禁用中断
     *
     * grub把控制权给到操作系统时候已经禁用中断
     */
	early_boot_irqs_disabled = true;

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
    /**
     * kernel/cpu.c
     *
     * 初始化启动（或引导）CPU。多处理器系统中，第一个启动的CPU就是引导CPU，负责执行一些早期的系统初始化任务，
     * 之后才允许其它CPU加入系统的启动过程。
     *
     * 1. 初始化CPU特定的数据结构：如，每个CPU变量和状态信息
     * 2. 设置CPU相关的硬件：如，缓存、时钟等
     * 3. 初始化中断和异常处理：设置中断描述符表IDT 和 异常处理程序。
     * 4. 初始化内存管理单元：配置内存分页和映射
     * 5. 初始化cgroup：如果启用了cgroup，将在CPU上进行初始化
     * 6. 初始化其它内核子系统：调度器、内核同步机制等
     * 7. 设置CPU状态：标志CPU为在线状态，使其能够接收和执行任务
     * 8. 通知其它CPU：一旦CPU初始化完成，它将通知其它CPU开始它们的启动过程。
     */
	boot_cpu_init();

    /**
     * mm/highmem.c
     *
     * 初始化页表。
     *
     * Linux中，页表是用于实现虚拟内存管理的数据结构，它将虚拟地址映射到物理地址。
     * 这个函数通常在内核启动过程中的早期被调用，以确保在操作系统运行时候，所有内存访问都是通过正确的页表进行的。
     * 这个过程涉及到设置目录页、页表项、以及相关的内存管理单元(MMU)配置。
     */
	page_address_init();
	pr_notice("%s", linux_banner);

    /**
     * security/security.c
     *
     * 初始化内核安全机制
     * 1. 访问控制
     * 2. 权限管理
     * 3. 安全策略
     * 4. 安全模块
     *
     * lsm ???
     */
	early_security_init();

    /**
     * 
     * 用于初始化和配置特定于体系结构(arch)的硬件和软件组件。这个函数能够确保内核能够正确与底层硬件交互。
     *
     * 主要职责：
     * 1. 检测和配置CPU：确定CPU的类型和特性，并根据这些信息配置内核
     * 2. 内存管理：初始化内存管理单元(MMU)，设置页表，以及配置内存映射
     * 3. 中断和异常处理：设置中断描述符表(IDT)和异常处理程序
     * 4. 计时器：初始化系统计时器，这对于调度和时钟中断至关重要
     * 5. I/O设备：检测和初始化I/O设备，如串行端口、网络接口等
     * 6. 总线和控制器：初始化系统总线和各种控制器，如：PCI、USB控制器等
     * 7. 电源管理：配置电源管理功能，如睡眠模式等
     * 8. 其它硬件特定功能：根据具体的硬件平台，可能还需要初始化特定硬件功能
     *
     * @note:// 后续看，这个函数里很多代码
     */
	setup_arch(&command_line);

    /**
     * 用于设置内核启动参数
     *
     * 启动参数由grub那里来，具体包含：
     * 1. 内核版本
     * 2. 根文件系统(根文件系统的类型和位置)
     * 3. 内存参数(内存大小、内存管理策略等)
     * 4. CPU参数(CPU频率、节能模式)
     * 5. 模块参数(用于加载和配置内核模块的参数)
     * 6. 安全参数(如启用SELinux或AppArmor等安全模块)
     * 7. 调试选项(用于内核调试的选项，如启用内核同页检查(KASAN)等)
     *
     * 此函数主要任务包括：
     * 1. 解析启动参数
     * 2. 设置内核选项
     * 3. 配置内核参数(将解析后的参数设置为内核参数，供内核其它部分使用)
     * 4. 初始化内核子系统(根据启动参数初始化内核的子系统，如文件系统、网络等)
     */
	setup_boot_config();

    /**
     * 负责设置和解析内核的命令行参数。命令行参数是在启动Linux系统时候通过引导加载器(grub)传递给内核的参数，这些参数可以用于控制内核的行为或传递系统启动所需的信息
     *
     * 主要任务包括：
     * 1. 初始化命令行缓存区
     * 2. 解密命令行参数
     * 3. 设置内核参数
     * 4. 处理早期参数
     * 5. 错误处理
     */
	setup_command_line(command_line);

    /**
     * 用于设置系统中CPU的数量，nr_cpu_ids 是一个全局变量，它记录了系统中CPU的总数。
     *
     * 通常执行如下操作：
     * 1. 检测CPU数量
     * 2. 设置 nr_cpu_ids
     * 3. 配置内核数据结构
     * 4. 初始化CPU特定的代码
     * 5. 配置SMP(对称多处理)
     */
	setup_nr_cpu_ids();

    /**
     * 负责初始化每个CPU核心的特定区域，确保每个CPU都有自己的内存区域，这些区域用于存储特定的数据结构和资源，以支持多核处理器(SMP)的高效运行
     * 1. 初始化每个CPU的内存区域
     * 2. 支持多核处理器
     * 3. 优化内存访问
     *
     * 实现细节：
     * 1. 分配内存
     * 2. 设置内存区域的属性
     * 3. 初始化数据结构
     *
     * 重要性：
     * 1. 性能优化
     * 2. 系统稳定性
     * 3. 资源管理
     */
	setup_per_cpu_areas();

    /**
     * 用于准备启动CPU，确保引导CPU被正确设置，以便它能协调其它CPU的启动和运行
     *
     * 主要任务：
     * 1. 初始化引导CPU的本地数据：为引导CPU设置本地数据结构，如：栈、寄存器等
     * 2. 设置CPU ID,用于在多核处理器中区分不同的CPU
     * 3. 初始化CPU状态，比如：将CPU状态设置为online
     * 4. 配置CPU特定的硬件
     * 5. 注册引导CPU
     * 6. 准备其它CPU的启动
     */
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */

    /**
     * 负责初始化引导CPU的热插拔支持
     *
     * 热插拔是一种允许不重启系统情况下动态添加或移出硬件资源，如CPU、内存或I/O设备的技术。
     * 主要任务：
     * 1. 初始化热插拔机制
     * 2. 配置CPU状态
     * 3. 注册热插拔处理程序
     * 4. 设置CPU热插拔策略
     * 5. 准备CPU热插拔通知
     * 6. 初始化相关数据结构
     */
	boot_cpu_hotplug_init();

    /**
     * 负责构建所有内存区域的列表。在Linux中，内存被划分处不同的区域，每个区域具有不同的属性和用途
     *
     * 主要任务：
     * 1. 初始化内存区域
     * 2. 构建区域列表
     * 3. 设置内存访问区域
     * 4. 优化内存访问
     * 5. 配置NUMA支持
     * 6. 初始化内存分配器
     */
	build_all_zonelists(NULL);

    /**
     * 负责初始化内核的内存分配机制，特别是与页面分配相关的部分。页面是内存管理中的一个基本单位，通常大小是4KB。页面分配器是内核中一个核心组件，它负责管理物理内存和虚拟内存的映射。
     *
     * 主要任务：
     * 1. 初始化页面分配器
     * 2. 设置页面大小
     * 3. 配置页面属性
     * 4. 初始化区域列表
     * 5. 注册页面分配回调
     * 6. 配置页面分配策略
     */
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", saved_command_line);

	/* parameters may set static keys */
    /**
     * 与内核跳转标签机制相关的初始化函数。跳转标签是内核提供的一种优化技术，它允许内核开发者在编译时指定某些代码段可以被动态的补丁化，以支持动态调整和优化
     *
     * 主要任务：
     * 1. 初始化跳转标签机制
     * 2. 注册跳转标签
     * 3. 配置跳转目标
     * 4. 设置权限和安全性
     * 5. 优化性能
     */
	jump_label_init();

    /**
     * 用于解析早期参数的函数。这些早期参数是在内核启动过程中，由引导加载器传递给内核的命令行参数。这些参数可以用于控制内核的行为，配置内核启动时的选项，或者传递系统所需的关键信息
     * 主要任务：
     * 1. 解析参数
     * 2. 设置内核选项
     * 3. 处理关键参数
     * 4. 错误检查
     * 5. 记录参数
     */
	parse_early_param();
	after_dashes = parse_args("Booting kernel",
				  static_command_line, __start___param,
				  __stop___param - __start___param,
				  -1, -1, NULL, &unknown_bootoption);
	print_unknown_bootoptions();
	if (!IS_ERR_OR_NULL(after_dashes))
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
			   NULL, set_init_arg);
	if (extra_init_args)
		parse_args("Setting extra init args", extra_init_args,
			   NULL, 0, -1, -1, NULL, set_init_arg);

	/* Architectural and non-timekeeping rng init, before allocator init */
    /**
     * 负责在系统启动的早期节点初始化随机数生成器。随机数生成器用于确保系统的安全性至关重要，尤其在加密、安全令牌生成、随机化内存布局等方面。
     * 1. 初始化随机数生成器
     * 2. 配置随机数生成策略
     * 3. 注册随机数回调
     * 4. 确保随机性
     * 5. 硬件熵收集
     */
	random_init_early(command_line);

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
    /**
     * 负责设置和初始化日志缓存区。
     */
	setup_log_buf(0);

    /**
     * fs/dcache.c
     *
     * 用于在Linux启动早期阶段初始化文件系统(VFS)缓存。
     *
     * dcache_init_early();
     * inode_init_early();
     *
     * 申请两个 hash 表
     */
	vfs_caches_init_early();

    /**
     * extable 是一个指向异常表的函数指针数组，用于处理内核中的异常情况，比如：也错误等。
     * 这些函数会响应内核中的特定异常
     *
     * 对异常表进行排序，为了优化内核的异常处理流程，确保异常发生是，内核能够以最高效的方式找到并调用适当的异常处理函数
     */
	sort_main_extable();

    /**
     * 陷阱处理函数，负责初始化内核的陷阱处理机制。
     *
     * 陷阱是一种由硬件异常、软件中断或系统调用触发的中断，它允许操作系统处理这些事件并采用相应的措施。
     *
     * 响应不同陷阱类型：
     * 1. 页错误
     * 2. 系统调用
     * 3. 中断
     * 4. 信号
     */
	trap_init();

    /**
     * 负责初始化内存子系统(MM)。它负责分配、管理、回收和保护内存资源。
     *
     * 主要任务有：
     * 1. 初始化内存描述符
     * 2. 设置页表
     * 3. 初始化内存分配器
     * 4. 配置内存区域
     * 5. 设置内存保护机制
     */
	mm_init();

    /**
     * 
     */
	poking_init();

    /**
     * 初始化 ftrace 系统。
     *
     * ftrace 是Linux提供的一个跟踪工具，可以跟踪内核函数的执行情况，帮助开发者分析和调试内核代码。
     *
     */
	ftrace_init();

	/* trace_printk can be enabled here */
    /**
     * 在内核启动早期阶段初始化跟踪功能。这个函数通过调用子系统 early_init 函数来设置早期跟踪，主要用于在内核引导阶段和早期初始化过程中进行跟踪，帮助调试和分析内核启动过程中的问题。
     *
     * 在early_trace_init函数中，会检查是否启用了早期跟踪，并根据情况调用跟踪子系统的early_init函数进行初始化。在这个过程中，会注册不同的跟踪处理函数，以便在不同的阶段进行跟踪。
     */
	early_trace_init();

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */

    /**
     * 负责初始化调度器。调度器是操作系统的核心组件之一，负责决定哪个进程获得CPU时间，以及何时进行任务切换。sched_init函数通常在内核启动过程中被调用，以确保调度器在系统运行之前被正确设置和配置。
     *
     * 调度器初始化包括多个方面：
     * 1. 初始化调度实体：调度器需要为每个进程和线程创建和管理调度实体，如任务结构体(task_struct)
     * 2. 设置调度策略：调度器支持多种调度策略（如：FIFO、Found-Robin等），此时会配置这些调度策略
     * 3. 初始化调度器的数据结构：这可能包括运行队列、优先级队列、调度器特定的数据结构等
     * 4. 配置调度器参数：调度器的行为受多个参数影响，如时间片大小、负载权重等，这些都需要在启动时候进行配置
     * 5. 设置调度器的中断处理：调度器需要响应各种内核事件，比如：定时器中断、以执行调度决策。
     * 6. 初始化调度类：在完全公平调度器(CFS)中，不同的进程类型可能需要不同的调度策略，调度类就是用来定义这些不同的调度行为。
     */
	sched_init();

	if (WARN(!irqs_disabled(),
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();

    /**
     * 初始化基数树。
     *
     * 基数树是一种快速查找的数据结构，它在内核中被广泛应用于各种场景，包括但不限于网络子系统（用于跟踪网络设备和路由）、文件系统（用于跟踪文件名）以及内存管理
     *
     * 基数树是一种类似于二叉树的树型数据结构，但它的每个节点可能有多于两个的子节点，具体取决于树的基数（通常是2的幂）。在Linux中，基数树通常用于保存键值对，其中键是一个整数，值是一个指针。
     *
     * 以下是函数主要用途：
     * 1. 内存分配：为基数树分配足够的内存空间，以存储器节点和可能的键值对
     * 2. 根节点初始化：设置基数树的根节点，这是树的起始点
     * 3. 配置树的属性：根据需要配置基数树的树型，如：树的深度、节点的大小等
     * 4. 准备插入和查找操作：确保树的插入新键值对或查找现有键值时候能正常工作。
     */
	radix_tree_init();

    /**
     *
     */
	maple_tree_init();

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
    /**
     * 初始化工作队列
     *
     * 工作队列是一种内核机制，允许内核线程异步执行工作项，这些工作项通常是一些需要稍后执行的任务，比如驱动程序的初始化、资源的回收、一些延迟执行的工作。
     *
     * 工作队列提供了有一种将工作推迟到以后执行的方式，这样就不会阻塞当前的内核操作或中断处理程序。常用于以下场景：
     * 1. 异步执行
     * 2. 延迟处理
     * 3. 资源管理
     * 4. 驱动程序初始化
     */
	workqueue_init_early();

    /**
     * 初始化 RCU(Read-Copy-Update)子系统。
     *
     * RCU是一种用于在多核处理器上高效同步多线程的机制，它允许多个读取操作者在没有获得锁的情况下访问共享数据结构，同时保持数据的一致性，并且只在必要时进行更新。
     * RCU核心思想：
     * 1. 读取者：不需要获取锁就可以访问数据结构，因为RCU保证了在读取者看到数据结构的某个版本时不会有写入者修改它。
     * 2. 写入者：在更新数据结构时，首先复制一份数据，进行修改，然后原子地将指向就数据结构的指针替换为新数据结构的指针。
     *
     * 主要工作：
     * 1. 初始化RCU控制块
     * 2. 配置RCU参数
     * 3. 设置回调函数：注册在每个RCU结束时调用的回调函数，用于执行必要的清理工作
     * 4. 初始化定时器：如果需要，初始化用于触发RCU结束的定时器
     *
     * RCU是Linux内核中非常重要的一个同步机制，特别是在驱动程序和内核子系统中，它被广泛用于处理并发数据访问
     */
	rcu_init();

	/* Trace events are available after this */
    /**
     * 初始化系统跟踪函数。跟踪函数是内核功能，它允许开发者监控和记录内核运行时发生的事件，这对于性能分析、调试和开发是非常有用的。
     *
     * 工作包括：
     * 1. 初始化跟踪缓存区：为存储跟踪数据分配内存和设置缓存区
     * 2. 注册跟踪点：设置系统中可用的跟踪点，这些是内核中用于手机信息的特定位置
     * 3. 配置事件过滤器：如果跟踪系统支持动态事件过滤，trace_init会配置这些过滤器
     * 4. 设置跟踪项：根据编译时配置或运行时参数设置跟踪选项，如跟踪哪些事件、采样频率等
     * 5. 初始化相关模块：如果跟踪系统包括模块化组件，trace_init会负责初始化这些模块
     * 6. 创建调试文件：在/sys/kernel/debug/tracing/目录下创建用于控制和访问跟踪数据的文件
     */
	trace_init();

    /**
     * 用于在内核初始化调用期间启用调试功能。初始化调用是内核启动过程中的一个阶段，在这个阶段中，一系列预先定义的函数按顺序被调用以初始化内核的各个子系统。
     *
     * 1. 调试初始化代码：捕获启动期间的问题
     * 2. 调试打印：输出额外的信息，包括有关初始化步骤、时间戳和状态信息的详细输出
     * 3. 断言检查：启动额外断言检测，确保初始化代码的正确性
     * 4. 调试模式：切换内核到调试模式，启用额外的入职记录、禁用某些优化
     * 5. 跟踪和分析：
     */
	if (initcall_debug)
		initcall_debug_enable();

    /**
     * 上下文跟踪，内核监控和跟踪进程或线程的执行上下文能力
     *
     * 上下文跟踪在多任务系统中非常重要，它允许内核：
     * 1. 调度决策
     * 2. 性能监控
     * 3. 资源管理
     * 4. 安全性
     */
	context_tracking_init();
	/* init some links before init_ISA_irqs() */
    /**
     * early_irq_init是Linux内核中的一个早期初始化函数，它在内核启动过程的早期阶段被调用，用于初始化中断处理机制。这个函数的目的是设置剧本的中断处理能力，以确保在系统启动过程中，硬件中断能够被正确的接收和处理。
     *
     * 1. 初始化中断描述符(irq_desc)数组：
     * 2. 配置中断默认属性：
     * 3. 初始化中断亲和性：设置中断处理的默认CPU亲和性，以优化中断处理的性能
     * 4. 调用架构特定的早期中断初始化函数
     * 5. 注册早期中断处理程序：
     */
	early_irq_init();

    /**
     * 继 early_irq_init 之后，继续完成中断系统的初始化工作。主要任务包括：
     * 1. 初始化中断向量
     * 2. 设置中断控制器
     * 3. 配置中断处理程序
     * 4. 初始化ISA IRQs
     * 5. 初始化APIC
     * 6. 初始化I/O APIC：
     * 7. 分配中断：在某些情况下，init_IRQ可能会分配中断给特定的设备或驱动程序
     * 8. 初始化软中断：
     * 9. 设置中断亲和性：设置哪些CPU处理哪些中断，以优化中断处理性能。
     * 10. 注册表中断处理回调：注册一些重要的中断处理回调，例如时钟中断回调，用于调度和时间管理
     */
	init_IRQ();

    /**
     * 用于初始化时钟处理的函数。时钟处理是内核中非常重要的一部分，它负责周期性的产生时钟中断（也称为计时器中断），这些中断用于驱动内核的调度器、更新系统事件、处理定时器和超时等。
     * 执行的一些关键任务：
     * 1. 初始化时钟中断处理程序：设置时钟中断的回调函数，这些函数将在每次时钟中断发生时候被调用
     * 2. 配置时钟中断频率：根据系统的硬件和配置，设置时钟中断的频率，这将决定调度器的精度和时钟中断的速率
     * 3. 初始化定时器和超时管理：
     * 4. 设置时钟事件设备：
     * 5. 配置时钟源：
     * 6. 初始化高精度时钟：
     * 7. 注册时钟和计时器相关的sysctls：
     * 8. 初始化时间管理：
     */
	tick_init();

    /**
     * 初始化RCU机制，但与通常的RCU初始化不同，它不使用CPU频率(hz)来控制RCU的使用。RCU是一种用于读取共享数据结构的机制，它允许多个读取操作在不阻塞数据结构的情况下进行，从而提高系统的并发性能。
     *
     * 在Linux中，RCU用于实现无锁的共享数据访问，它通过读取数据的副本来避免直接访问共享数据，从而避免了数据竞争的问题。RCU通常在CPU频率较低的系统上使用，因为它可以减少不必要的CPU活动，从而节省能源。
     *
     * rcu_init_nohz 函数的调用通常发生在系统启动时候，或者在需要初始化RCU机制的情况下。这个函数确保了RCU机制的正确设置，使得系统能够以一种高效且节能的方式进行数据共享。
     */
	rcu_init_nohz();

    /**
     * 用于初始化内核定时器。
     *
     * 内核定时器负责调度和管理各种定时任务，包括但不限于内核线程、内核服务、驱动程序中的定时事件等。
     *
     * 定时器在内核中的作用包括：
     * 1. 内核线程调度：内核线程可以设置定时器来唤醒自己执行定时任务。
     * 2. 定时任务执行：内核中的一些服务和驱动程序需要定时执行任务，定时器可以确保这些任务按时执行
     * 3. 超时处理：在等待某些事件时候，可以使用定时器来设置超时，以避免系统长时间等待。
     *
     * 主要职责是：
     * 1. 初始化内核定时器列表，确保定时器可以正确的被添加到列表中
     * 2. 设置定时器的回调函数，即当定时器到期时需要执行的函数
     * 3. 配置定时器的超时时间和触发方式
     * 4. 启动内核定时器服务，确保定时器可以被内核定时器线程正确处理。
     */
	init_timers();

    /**
     * 用于初始化顺序读-复制-更新（Sequenced Read-Copy-Update, SRCU）机制。
     *
     * SRCU是一种用于处理并发访问共享数据结构的同步机制，它允许多个读取操作在不阻塞数据结构的情况下并发进行，同时允许单个写操作来更新数据结构
     *
     * SRCU机制主要用于哪些需要频繁读取但较少更新的场景，它通过维护多个数据结构副本来实现高效的读取操作，同时通过序列号来确保写操作的安全性。SRCU通常用于那些对性能要求较高的系统中，因为它可以减少锁的使用，从而提高系统的并发性能。
     *
     * srcu_init函数的主要职责包括：
     * 1. 初始化SRCU控制结构：为SRCU机制创建和初始化必要的控制结构，这些结构用于管理数据结构的多个副本和序列号。
     * 2. 配置SRCU参数：设置SRCU机制的参数，如副本的数量、更新策略等
     * 3. 注册回调函数：注册当SRCU完成数据结构更新时候需要执行的回调函数，这些函数通常用于清理或重新初始化数据结构副本。
     *
     * 使用SRCU时，读取操作不需要任何特殊的同步操作，因为它们直接访问当前的副本。而写操作则需要通过特定的SRCU接口来执行，以确保在更新数据结构时候不会影响正在进行的读取操作。
     */
	srcu_init();

    /**
     * 内核中用于初始化高精度定时器(High-Resolution Timers，简称 HRTimers)的函数。
     *
     * 高精度定时器是一种定时器机制，它允许以纳秒级别的精度来设置定时器的超时时间，这笔传统的定时器（通常以毫秒为单位）具有更高的精度。
     *
     * 高精度定时器主要用于需要非常精确时间控制的场景，例如：音频和视频同步、高精度测量、时间戳等。HRTimers通过使用内核的时钟源来实现高精度的时间度量，这些时钟源可以是CPU内部的定时器或者外部的高精度时钟。
     *
     * 此函数的主要任务包括：
     * 1. 初始化HRTimers相关的数据结构：
     * 2. 配置时钟源：
     * 3. 注册回调函数：
     * 4. 启动HRTimers服务：
     */
	hrtimers_init();

    /**
     * softirq_init 是一个用于初始化软中断系统的函数。软中断是Linux内核中一种异步事件处理机制，它允许内核在处理硬件中断时候，将一些可以延迟处理的任务推迟到硬件中断处理完毕后再执行。这样做可以减少硬件中断处理的延迟，提高系统的响应性。
     *
     * softirq_init函数的主要任务包括：
     * 1. 初始化软中断处理队列：
     * 2. 注册软中断处理函数：
     * 3. 配置软中断优先级：
     * 4. 启动软中断处理机制：
     */
	softirq_init();

    /**
     * 时间保持是内核用来跟踪时间流式的机制，它对于调度、计时器、时钟中断等都是非常重要的。
     *
     * timekeeping_init函数通常在内核启动时候被调用，用于初始化时间保持的基础措施。这个函数会设置内核的时钟源，配置时钟中断，以及初始化与时间相关的其它数据结构。
     */
	timekeeping_init();

    /**
     * time_init负责初始化内核中与时间管理相关的部分。
     *
     * 主要任务包括：
     * 1. 初始化系统时间：
     * 2. 初始化定时器：
     * 3. 初始化时钟事件设备：
     * 4. 初始化时钟源：
     * 5. 配置时间服务：
     * 6. 初始化与时间有关的其它内核子系统：
     */
	time_init();

	/* This must be after timekeeping is initialized */
    /**
     * 初始化随机数生成器的函数。
     */
	random_init();

	/* These make use of the fully initialized rng */
    /**
     * 内存管理有关，内存屏障。
     */
	kfence_init();

    /**
     * 初始化栈保护 canary 的值。这个值用于防止栈溢出攻击，这时一种常见的安全漏洞，攻击者可以通过溢出栈上的缓存区来覆盖函数的返回地址，从而执行恶意代码。
     *
     * canary机制的工作原理是：在函数的返回地址之前放置一个随机值(即：canary)，如果发生栈溢出，这个值很可能会被覆盖。函数返回前，会检查这个值是否被修改，如果发现值改变，则表明栈被溢出了，程序可以采取相应的安全措施。
     *
     * 此函数在内核启动时候被调用，生成一个随机的 canary 值。这个值通常是基于内核的随机数生成器和当前的CPU时间戳计数器（TSC）来生成，以确保其随机性和不可预测性。
     *
     * canary值被设置在当前进程的 task_struct 结构中的 stack_canary 字段，并且在每个CPU的栈上拥有相应的副本，以便在处理中断时候使用。这个值在内核的整个生命周期中保持不变，并且对于每个新创建的进程，都会生成一个新的随机 canary 值。
     *
     * 这种保护机制是GCC编译器 -fstack-protector 选项的一部分，并且可以在linux内核配置选项 CONFIG_CC_STACKPROTECTOR 中启用。启用栈保护可以显著提高系统的安全性，防止栈溢出攻击。
     */
	boot_init_stack_canary();

    /**
     * Linux内核中与性能监控相关的一个初始化函数，它负责设置性能事件子系统。这个子系统允许用户空间程序监控和测量各种硬件和软件时间，如CPU周期、指令数、缓存命中和失效等。这些时间对于性能分析和优化至关重要。
     *
     * 在Linux内核启动过程中，perf_event_init函数会被调用来初始化perf_events子系统。这个函数会注册不同的性能监控单元（PMUs）以及相关的硬件和软件支持。这包括设置硬件计数器、初始化软件事件、注册跟踪点和断点等。
     * 1. 注册软件事件PMU，用于监控软件定义的事件。
     * 2. 注册CPU时钟PMU，用于监控CPU时钟周期
     * 3. 注册任务时钟PMU，用于监控特定任务的时钟周期
     * 4. 调用perf_tp_register函数来注册跟踪点PMU，用于监控内核中的跟踪点事件。
     * 5. 调用 init_hw_breakpoint 函数来初始化硬件断点支持
     * 6. 调用架构特定的初始化函数（如 init_hw_perf_events），这些函数会根据具体的硬件平台注册额外的PMUs
     */
	perf_event_init();

    /**
     * 与性能分析和系统监控有关。
     *
     * 此函数包括：
     * 1. 初始化性能计数器
     * 2. 注册性能监控事件
     * 3. 设置性能监控策略
     * 4. 初始化相关的数据结构
     * 5. 配置性能监控接口
     */
	profile_init();

    /**
     * 负责设置内核的函数调用机制，特别是针对多核系统中的跨核函数调用。这个函数在内核启动中被调用，以确保相关的数据结构和机制被正确初始化。
     * 1. 初始化 call_function_data 结构体，这是一个静态分配的结构体，用于存储与跨核函数调用相关的数据
     * 2. 初始化 call_function_single_data数组，这个数组的大小和系统中的CPU核心数量NR_CPUS相等，每个元素都指向一个call_function_data结构体实例
     */
	call_function_init();
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	early_boot_irqs_disabled = false;
	local_irq_enable();

	kmem_cache_init_late();

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

    /**
     * 用于初始化锁验证器的函数，这个函数是内核启动过程中的一个步骤，其主要作用是设置和初始化内核中的锁调试和死锁检验机制。
     *
     * 根据搜索结果 lockdep_init 的实现相当简单，它主要初始化了两个hash表 list_head，并设置 lockdep_initialized 全局变量为1。这个函数是内核锁验证器的入口点。
     *
     * 验证锁的作用是在锁的使用过程中检测潜在问题，如死锁和不正确的锁顺序。
     */
	lockdep_init();

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
    /**
     * Linux 内核中用于检测锁定机制正确性的自测试工具。它作为内核启动过程中的一部分运行，目的是在系统启动时候检查常见的锁定错误，确保调试机制能够正确的检测到这些问题。
     *
     * 测试包括但不限于：
     * 1. 死锁检测：
     * 2. 自旋锁和读写锁调试：
     * 3. 互斥锁调试：
     * 4. RCU使用检测：
     */
	locking_selftest();

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
    /**
     * 常与内存加密功能有关。内存加密是一种安全特性，用于在物理内存中加密敏感数据，以防止未受权的访问或数据泄露。
     *
     * 函数可能会执行以下任务：
     * 1. 注册加密驱动：将内存加密驱动程序注册到内核中
     * 2. 初始化加密算法：根据系统配置，初始化将用于加密和解密数据的算法
     * 3. 配置加密参数：设置加密过程中需要的参数，如：密钥、加密模式等
     * 4. 分配必要的资源：将内存加密分配必要的内存资源或硬件资源
     * 5. 设置回调函数：为内存访问设置回调函数，以在数据被加载到内存或从内存中溢出时候自动进行加密或解密。
     */
	mem_encrypt_init();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	setup_per_cpu_pageset();

    /**
     * 初始化NUMA策略
     *
     * NUMA策略可以控制进程如何与NUMA节点交互，例如，它可以决定进程应该在哪些NUMA节点上运行，以及它们应该访问哪些内存区域。
     */
	numa_policy_init();

    /**
     * 内核中用于初始化ACPI早期阶段的函数。ACPI是一种标准，它允许操作系统控制计算机的硬件配置和电源管理。
     *
     * 这个函数主要任务包括：
     * 1. 初始化ACPI子系统
     * 2. 初始化ACPI表
     * 3. 初始化ACPI事件系统
     * 4. 初始化ACPI操作区域
     * 5. 启用ACPI子系统
     */
	acpi_early_init();

    /**
     * 在早期的jiffy计数器初始化之后，对后期体系结构特定的计时器进行初始化。这个函数通常在内核启动的较晚阶段调用，用于完成对某些硬件计时器的配置，这些计时器对于系统的定时操作至关重要。
     */
	if (late_time_init)
		late_time_init();

    /**
     * 负责初始化调度时钟。调度时钟是内核用来测量时间流逝的一个关键组件，它对于调度器来说非常重要，因为调度器需要准确跟踪进程的执行事件，以便作出合理的调度策略。
     */
	sched_clock_init();

    /**
     * 用于校准延迟循环。这个函数主要用于确定CPU的执行速度，以便内核可以准确的计算出执行特定数量的空操作所需的事件。这对于精确的毫秒级延迟和定时器非常重要。
     *
     * 校准过程如下：
     * 1. 使用已知频率的外部时钟源或CPU内部的计时器来测量一个固定数量的循环所需的时间
     * 2. 根据测量结果调整循环计数，以便在实际使用中能够产生准确的延迟
     * 3. 存储校准结果，供内核中的其它部分使用，例如：在实现udelay（毫秒延迟）函数时。
     */
	calibrate_delay();

    /**
     * 它负责初始化pid（进程ID）管理系统
     *
     * PID管理通常使用IDR（ID映射器，一种数据结构用于管理动态分配ID）来实现。idr可以看作一种特殊的内存分配器，它允许内核动态的分配和释放ID，同时保证分配的ID是唯一的。
     * pid_idr_init的主要任务：
     * 1. 初始化IDR数据结构：设置IDR的大小、范围和其它相关参数
     * 2. 注册与PID管理相关的回调函数：这些回调函数会在分配和释放PID时候被调用
     * 3. 设置PID管理的初始状态：例如，初始化一些用于跟踪已分配PID的数据结构。
     *
     * 在多核体系中，PID管理可能还需要是线程安全的。
     */
	pid_idr_init();
    /**
     * anon_vma_init 负责初始化匿名虚拟内存区域的管理系统。在Linux内核中，内存管理是一个核心功能，而匿名VMA是进程地址空间中用于追踪匿名页的一种数据结构。
     *
     * 匿名页是那些不再磁盘上的页，它们通常用于存储程序的栈、堆以及由malloc等函数分配的动态内存。这些内存页不需要从磁盘加载，也不需要在系统崩溃后恢复，因此它们是匿名的。
     *
     * anon_vma_init 函数的主要任务包括：
     * 1. 初始化anon-vma的相关数据结构：内核可能包括初始化用于管理annon-vma的链表、散列表或其它数据结构
     * 2. 设置annon-vma的回收策略：内核可能需要回收不再使用的匿名页以释放内存
     * 3. 初始化与annon-vma相关的锁和同步机制：为了确保多线程环境下的内存管理操作是安全的
     * 4. 注册annon-vma相关的回调函数：这些回调函数可能用于处理内存分配、回收和其它内存管理事件
     * 5. 初始化内存回收器的相关参数：如果内存回收器需要与annon-vma交互，annon_vma_init可能会设置相关的参数
     */
	anon_vma_init();
#ifdef CONFIG_X86
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif

    /**
     * 用于初始化线程栈缓存的函数。在多线程环境中，线程栈是每个线程分配的一块内存区域，用于存储局部变量、函数参数和调用栈。线程栈缓存的目的是优化线程栈的分配和释放过程，通过缓存一部分线程栈来减少内存分配的开销，特别是在高并发系统中。
     *
     * 函数的主要任务包括：
     * 1. 初始化缓存结构：设置用于存储预分配线程栈的缓存结构。
     * 2. 设置缓存大小：
     * 3. 同步机制：
     * 4. 注册回调：
     * 5. 配置回收策略：
     * 6. 性能优化：
     */
	thread_stack_cache_init();

    /**
     * 与进程凭证管理有关
     *
     * 凭证信息包括了用户ID、组ID以及其它安全相关的属性，它们是Linux内核安全模型的一部分，用于确定哪些操作可以被进程执行。
     * cred_init函数的作用是初始化凭证相关的数据结构，这可能包括：
     * 1. 初始化凭证缓存：
     * 2. 设置默认凭证：
     * 3. 初始化与凭证相关的锁：
     * 4. 注册凭证管理的回调
     * 5. 设置凭证验证机制：
     */
	cred_init();

    /**
     * 负责设置内核中用于处理fork系统调用所需的基础设施。fork是一个基本的UNIX系统调用，用于创建一个与父进程几乎完全相同的子进程。
     *
     * fork_init函数的主要任务包括：
     * 1. 初始化进程创建所需的数据结构
     * 2. 配置fork调用的默认行为
     * 3. 注册与fork相关的回调
     * 4. 设置信号处理
     * 5. 初始化子进程的凭证和属性
     * 6. 配置内存管理：
     * 7. 初始化或配置其它相关子系统
     */
	fork_init();

    /**
     * 负责初始化与进程相关的缓存。
     *
     * 此函数主要任务包括：
     * 1. 初始化进程描述符缓存
     * 2. 初始化任务结构体缓存
     * 3. 配置缓存参数：
     */
	proc_caches_init();

    /**
     * 用于初始化 UTS 命名空间
     *
     * 与Linux操作系统中的UTS(UNIX Time-Sharing)命名空间有关。
     *
     * UTS命名空间用于隔离系统的主机名和网络信息服务域名。通过此函数为新的进程设置独立的UTS命名空间，从而允许每个进程拥有自己的主机名和NIS域名，而不影响到系统的其它部分。
     *
     */
	uts_ns_init();

    /**
     * 初始化与密钥有关的系统
     *
     * 空 。。。
     */
	key_init();

    /**
     * 负责启动安全框架的初始化过程。用以确保安全子系统和服务在系统完全运行之前被正确设置。
     */
	security_init();

    /**
     * 负责初始化内核调试系统。
     *
     * 常在内核安全框架初始化之后和虚拟文件系统初始化之前调用
     *
     * 主要作用包括：
     * 1. 设置系统控制台，这是用户与系统交互的主要接口，允许输入命令和查看系统信息
     * 2. 初始化调试写缓存，这使得调试信息可以被写入缓存区，并通过串口或其它方式输出
     * 3. 启用内核调试特性，如调用kernel_doublefault_init 来启用特定的调试功能。
     */
	dbg_late_init();

    /**
     * 用于初始化网络命名空间。
     *
     * 网络命名空间是Linux内核的一种隔离机制，允许每个命名空间拥有独立的网络堆栈，包括网络设备、路由表、IP地址等。
     * 这种机制在容器技术中非常有用，因为它可以为每个容器提供隔离的网络环境。
     *
     * 此函数的主要作用是设置和初始化内核网络系统。这包括初始化默认的网络命名空间，以及注册网络相关的操作和钩子。这个函数通常在内核启动的早期阶段被调用，以确保网络子系统在系统启动时候准备好。
     */
	net_ns_init();

    /**
     * 用于初始化虚拟文件系统（Virtual File System VFS）缓存的函数。
     *
     * VFS是Linux内核中的一个抽象层，它允许内核以统一的方式处理各种不同类型的文件系统。
     *
     * 此函数的主要任务是设置内核中用于提高文件系统性能的各种缓存机制。
     *
     * 以下是此函数的一些关键点：
     * 1. 初始化时机：确保文件系统操作之前缓存系统已经准备就绪
     * 2. 缓存类型：此函数会初始化多种类型缓存，包括但不限于：
     *      1. dentry缓存：用于缓存文件系统的目录项（dentry），以减少对磁盘的访问次数
     *      2. inode缓存：缓存文件系统中的inode信息，同样是为了减少磁盘I/O操作
     *      3. 文件对象缓存：可能包括对打开文件的缓存，以快速访问频繁使用的文件
     * 3. 性能优化：通过这些缓存机制，内核可以更快的响应文件系统操作请求，因为许多操作可以直接在内存中完成，而不需要访问磁盘
     * 4. 动态调整：在某些情况下，VFS缓存的大小和行为可能会根据系统运行时候的性能数据动态调整
     * 5. 内存管理：vfs_caches_init还涉及到内存管理方面的工作，确保缓存使用的内存被合理分配和回收
     * 6. 模块化设计：VFS的技术允许不同文件系统实现自己的缓存策略，同时vfs_caches_init提供了一个统一的初始化入口
     * 7. 错误处理：此函数还需要处理初始化过程中可能出现的错误，确保缓存系统稳定可靠
     * 8. 依赖关系：vfs_caches_init的执行可能依赖于内核其它部分的初始化，例如：内存管理系统和调度器
     * 9. 可配执性：内核配置选项可能允许开发者或系统管理员调整VFS缓存的行为，以适应特定的性能需求或硬件环境
     */
	vfs_caches_init();

    /**
     * 负责初始化页缓存（Page Cache）。
     *
     * 页缓存是内核中用来存储文件数据的一种缓存机制，它位于用户空间和文件系统之间，可以显著提高文件访问的性能。
     * 当文件数据被读取时，它会首先加载到页缓存中，随后对相同文件数据的访问就可以直接从缓存中获取，而不需要每次都访问磁盘
     *
     * pacgecache_init函数的主要任务包括：
     * 1. 初始化页缓存的数据结构：设置页缓存所需的各种内核数据结构，例如：用于跟踪缓存页的链表、哈希表等
     * 2. 注册相关的内核模块和钩子：这可能包括设置与页缓存相关的内核模块，以及注册在页缓存操作时需要调用的函数
     * 3. 配置页缓存的参数：根据内核的配置和启动参数，设置页缓存的大小、行为等
     * 4. 内存分配：为页缓存分配必要的内存资源
     * 5. 设置页回收机制：初始化内核的页回收机制，以确保当系统内存不足时，页缓存可以释放内存给其它用途
     * 6. 初始化与页缓存相关的统计信息：设置用于监控页缓存使用情况的计数器和统计数据结构
     * 页缓存的声明周期管理包括其产生和释放。产生页缓存的两种主要方式是：
     * 1. Buffered I/O：在这种模式下，数据首先被复制到用户空间的缓存区，然后从用户空间复制到内核的页缓存中
     * 2. Memory-Mapped I/O：数据直接映射到用户空间，绕过了内核的页缓存
     *
     * 页缓存的释放到将脏页写回到磁盘，并将不再需要的页从缓存中溢出。这个过程可以通过内核的回收机制自动进行，页可以通过显示的操作触发，通过 /proc/sys/vm/drop_caches控制
     *
     * 页缓存对于提高系统性能至关重要，但同时也需要仔细管理，以避免过度占用内存或导致性能问题。
     */
	pagecache_init();

    /**
     * 用于初始化信号处理机制的函数。
     *
     * 信号是Linux内核提供的一种异步事件通知机制，用于处理来自操作系统或另一个进程的事件通知。信号可以用于进程间通信（IPC），或者用于通知进程发生了哪些需要处理的事件，如用户中断（Ctrl + C）或硬件异常。
     *
     * 主要作用包括：
     * 1. 初始化信号表：为每个进程创建信号表，并初始化相关数据结构，如信号掩码（signal mask）和待处理信号集合
     * 2. 设置默认信号处理行为：为常见的信号设置默认的处理函数，例如：为SIGINT（中断信号）设置默认的处理函数，通常会导致进程终止。
     * 3. 初始化信号处理相关的内核数据结构：者可能包括信号队列、信号处理函数指针等
     * 4. 配置信号处理参数：根据系统配置和启动参数，设置信号处理的相关参数，如信号栈的大小等
     * 5. 注册信号处理相关的系统调用：初始化与信号处理相关的系统调用，如：kill、sigaction、sigprocmask等
     * 6. 初始化信号处理的线程或任务：在多线程环境中，可能需要为信号处理创建专门的线程或任务
     * 7. 设置信号处理的优先级：确保信号处理能够即时响应，可能需要设置信号处理任务的优先级。
     *
     * 信号处理是Linux内核中一个复杂但非常重要的部分，它涉及到进程管理、系统调用、内核同步等多个方面。正确的初始化信号处理机制对于保证系统稳定性和响应能力至关重要。
     *
     * 由于signals_init是内核内部的函数，其具体实现细节可能会随着Linux内核版本的不同而有所变化。
     */
	signals_init();

    /**
     * 初始化 seq_file 结构
     *
     * seq_file是内核提供的一种用于序列化访问数据的机制，通常用于实现/proc文件系统下的文件，它允许内核以一种高效的方式向用户空间提供数据。
     *
     * seq_file机制是为了方便内核开发者编写可扩展的、基于回调的文件读取操作。
     *
     * 用法：
     * static struct seq_operations my_seq_ops = {
     *      .start = my_start,
     *      .next  = my_next,
     *      .stop  = my_stop,
     *      .show  = my_show
     *      };
     *
     * static int __init my_init(void)
     * {
     *      struct proc_dir_entry *my_proc_entry;
     *      seq_file_init(&my_seq_file, &my_seq_ops);
     *      // 其他初始化代码...
     *      my_proc_entry = proc_create("my_proc_file", 0, NULL, &my_seq_fops);
     *
     *      // 检查 my_proc_entry 是否创建成功等...
     *
     *      return 0;
     * }
     *
     * 在这个例子中，seq_file_init 宏初始化了一个 seq_file 结构，这个结构随后被用于创建一个 proc 文件。my_seq_ops 结构体定义了序列化访问数据所需的操作，包括开始读取（start）、读取下一项（next）、停止读取（stop）和显示数据（show）的回调函数。
     */
	seq_file_init();

    /**
     * 初始化 /proc 文件系统相关的根目录
     *
     * /proc是 Linux内核提供的一种虚拟文件系统，它用于内核与用户之间的信息交换。包含了系统运行时候的大量信息，比如：进程信息、内存使用情况、设备状态等。
     *
     * 用户和应用程序可以通过读取 /proc 下的文件来获取这些信息。
     */
	proc_root_init();

    /**
     * 初始化 nsfs 虚拟文件系统，此文件系统用于管理Linux内核中的网络名称空间
     *
     * nfs主要特点：
     * 1. 网络名称空间是Linux内核提供的一种隔离网络环境的机制，让不同的进程或容器拥有自己独立的网络设置，如IP地址、路由表、防火墙规则等
     * 2. nsfs文件系统作为网络名称空间的接口，为用户空间的程序提供了访问和管理网络名称空间的方法
     * 3. 通过nsfs，用户可以列出系统中存在的网络名称空间、切换到指定的网络名称空间、查看和修改该网络名称空间的网络配置等
     * 4. nsfs作为一个虚拟文件系统，挂载在/sys/kernel/debug/ns 目录下。可以使用 ls、cd等常见的文件操作命令来管理网络名称空间。
     */
	nsfs_init();

    /**
     * 用于初始化CPU集(cgroups)子系统的功能函数。CPU集是Linux控制组（cgroup）的一个特性，它允许系统管理员或用户对进程进行分组，并控制这些组能够使用的资源，如CPU时间、内存等
     *
     * 此函数主要作用包括：
     * 1. 初始化CPU集数据结构：
     * 2. 注册CPU集文件系统：
     * 3. 设置默认的CPU集配置：
     * 4. 初始化相关的内核钩子：
     * 5. 配置CPU集相关的内核参数：
     * 6. 创建CPU集相关的内核线程或工作队列：
     * 7. 注册CPU集相关的系统调用：
     */
	cpuset_init();

    /**
     * cgroup_init 是一个负责初始化控制组（cgroup）子系统的函数。
     *
     * 函数主要任务：
     * 1. 初始化cgroup框架
     * 2. 注册cgroup文件系统
     * 3. 设置默认的cgroup
     * 4. 设置cgroup相关的内核参数
     * 5. 初始化cgroup相关的子系统
     * 6. 注册cgroup相关的钩子和回调
     * 7. 创建cgroup相关的内核线程或工作队列
     * 8. 注册cgroup相关的系统调用
     */
	cgroup_init();

    /**
     * 是一个用于早期初始化任务统计信息的函数。任务统计是内核提供的一种机制，用于收集和报告系统中任务（进程）的统计信息。这些信息可以用于监控系统性能、分析进程行为、调试问题等。
     *
     * taskstats_init_early 函数的主要作用包括：
     * 1. 初始化统计数据结构：
     * 2. 注册统计钩子：
     * 3. 配置统计参数：
     * 4. 初始化定时器：
     * 5. 创建统计相关的内核线程或工作队列：
     * 6. 注册系统调用：
     */
	taskstats_init_early();

    /**
     * 用于初始化延迟记账子系统的函数。
     *
     * 此函数主要作用包括：
     * 1. 初始化延迟记账数据结构：
     * 2. 注册延迟记账钩子：
     * 3. 配置延迟记账参数：
     * 4. 初始化定时器：
     * 5. 创建延迟记账相关的内核线程或工作队列：
     * 6. 注册系统调用：
     */
	delayacct_init();

    /**
     * 空实现
     */
	check_bugs();

    /**
     * 负责初始化高级配置和电源接口（ACPI）子系统。ACPI是一种行业标准的硬件描述语言，用于操作系统与计算机硬件之间的交互，特别是与电源管理和配置相关的方面。
     *
     * 以下是 acpi_subsystem_init 函数的一些关键职责：
     * 1. 初始化ACPI数据结构：
     * 2. 解析ACPI表：
     * 3. 注册ACPI驱动：
     * 4. 配置电源管理：
     * 5. 初始化ACPI事件处理：
     * 6. 启动ACPI内核线程：
     * 7. 注册ACPI相关的系统调用：
     * 8. 初始化热插拔支持：
     * 9. 配置ACPI调试选项：
     */
	acpi_subsystem_init();

    /**
     * 空实现？
     */
	arch_post_acpi_subsys_init();

    /**
     * 用于初始化 KCSAN（Kernel Concurrency Sanitizer）工具。
     * KCSAN是谷歌开发并开源的一种工具，用于检测Linux内核中的并发错误，如竟态条件、死锁和数据竞争。它通过在内核中的共享变量和锁上插入检查代码，检测并记录并发访问的情况，并在错误发生时候生成报告。
     *
     * 函数主要功能包括：
     * 1. 创建一个名为 __kcsan_enable的全局变量，并将其初始化为1，这个变量用于控制KCSAN工具的开启和关闭。
     * 2. 如果 __kcsan_enable 变量值为0，则 KCSAN 工具处于关闭状态，不会进行任何并发错误检测；如果变量值为1，则工具处于开启状态，会进行并发错误检测。
     * 3. 该函数还会注册一个sysctl_intvec_handler，这个handler会在系统控制变量发生变化时候被触发。当__kcsan_enabled变量的值改变时候，handler会根据新的值来决定是否开启或关闭KCSAN工具。
     *
     * KCSAN使用编译时插桩和运行时检测的方法来查找竟态条件。它通过设置观察点和随机延迟来增加观察到静态的机会。
     *
     * KCSAN已经在2019年底合入Linux内核主线？
     */
	kcsan_init();

	/* Do the rest non-__init'ed, we're now alive */
    /**
     * 此函数在内核初始化的最后阶段被调用。这个函数的主要目的是启动剩余的非 __init 标记的初始化代码，这些代码通常不能在内核的早期阶段执行，因为它们依赖于完整的内核服务和子系统
     *
     * arch_call_rest_init 函数的主要工作包括：
     * 1. 创建内核线程：arch_call_rest_init会创建两个重要的内核线程，kernel_init和kthreadd。kernel_init是内核的初始化线程，通常是拥有PID 1 的第一个用户空间进程的父进程。kthreadd是内核线程管理器，负责创建和管理其它的内核线程
     * 2. 初始化调度器：在kthreadd创建之后，arch_call_rest_init会通过调用schedule_preempt_disabled来启动内核的调度器，这允许内核开始调度其它线程。
     * 3. 等待kthreadd就绪：在kernel_init线程开始执行之前，它需要等待kthreadd完全初始化完成。这时通过一个完成变量（如 kthreadd_done）来实现的，kernel_init会等待这个变量被设置，然后才能继续执行。
     * 4. 设置CPU和内存策略：kernel_init线程被配置为可以在任何CPU上运行，并且可以分配任何节点的内存页。
     * 5. 执行剩余的初始化：一旦kthreadd就绪，kernel_init线程就会继续执行剩余的初始化工作，包括执行initcall级别的函数、设置内存管理、初始化文件系统、挂载根文件系统、启动用户空间的init进程等。
     * 6. 系统状态转换：在kernel_init执行完所有初始化之后，内核会将系统状态设置为SYSTEM_RUNNING，表示系统已经完全启动进入运行时状态。
     *
     * arch_call_rest_init 是内核启动过程中的一个关键步骤，它确保来内核的调度器、内核线程和用户空间进程能够正确启动和运行。通过这个函数，Linux内核完成了从启动阶段到完全运行的过渡。
     */
	arch_call_rest_init();

    /**
     * 这个函数目的是放置编译器对函数调用进行尾部调用优化（tail call optimization,TCO）。尾部调用优化是编译器在编译期间对特定函数调用进行优化的一种技术，它允许。
     * 1. 调试目的：在调试时候，保持函数调用的完整栈跟踪可能更有帮助，防止优化可以让调试器更容易追踪函数调用。
     * 2. 资源清理：如果函数在退出之前需要执行一些清理工作（如释放资源或调用exit函数），尾部调用优化可能会绕过这些清理代码
     * 3. 控制流：在某些复杂的控制流中，放置尾部调用优化可以确保代码按预期顺序执行。
     */
	prevent_tail_call_optimization();
}

/* Call all constructor functions linked into the kernel. */
static void __init do_ctors(void)
{
/*
 * For UML, the constructors have already been called by the
 * normal setup code as it's just a normal ELF binary, so we
 * cannot do it again - but we do need CONFIG_CONSTRUCTORS
 * even on UML for modules.
 */
#if defined(CONFIG_CONSTRUCTORS) && !defined(CONFIG_UML)
	ctor_fn_t *fn = (ctor_fn_t *) __ctors_start;

	for (; fn < (ctor_fn_t *) __ctors_end; fn++)
		(*fn)();
#endif
}

#ifdef CONFIG_KALLSYMS
struct blacklist_entry {
	struct list_head next;
	char *buf;
};

static __initdata_or_module LIST_HEAD(blacklisted_initcalls);

static int __init initcall_blacklist(char *str)
{
	char *str_entry;
	struct blacklist_entry *entry;

	/* str argument is a comma-separated list of functions */
	do {
		str_entry = strsep(&str, ",");
		if (str_entry) {
			pr_debug("blacklisting initcall %s\n", str_entry);
			entry = memblock_alloc(sizeof(*entry),
					       SMP_CACHE_BYTES);
			if (!entry)
				panic("%s: Failed to allocate %zu bytes\n",
				      __func__, sizeof(*entry));
			entry->buf = memblock_alloc(strlen(str_entry) + 1,
						    SMP_CACHE_BYTES);
			if (!entry->buf)
				panic("%s: Failed to allocate %zu bytes\n",
				      __func__, strlen(str_entry) + 1);
			strcpy(entry->buf, str_entry);
			list_add(&entry->next, &blacklisted_initcalls);
		}
	} while (str_entry);

	return 1;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	struct blacklist_entry *entry;
	char fn_name[KSYM_SYMBOL_LEN];
	unsigned long addr;

	if (list_empty(&blacklisted_initcalls))
		return false;

	addr = (unsigned long) dereference_function_descriptor(fn);
	sprint_symbol_no_offset(fn_name, addr);

	/*
	 * fn will be "function_name [module_name]" where [module_name] is not
	 * displayed for built-in init functions.  Strip off the [module_name].
	 */
	strreplace(fn_name, ' ', '\0');

	list_for_each_entry(entry, &blacklisted_initcalls, next) {
		if (!strcmp(fn_name, entry->buf)) {
			pr_debug("initcall %s blacklisted\n", fn_name);
			return true;
		}
	}

	return false;
}
#else
static int __init initcall_blacklist(char *str)
{
	pr_warn("initcall_blacklist requires CONFIG_KALLSYMS\n");
	return 0;
}

static bool __init_or_module initcall_blacklisted(initcall_t fn)
{
	return false;
}
#endif
__setup("initcall_blacklist=", initcall_blacklist);

static __init_or_module void
trace_initcall_start_cb(void *data, initcall_t fn)
{
	ktime_t *calltime = data;

	printk(KERN_DEBUG "calling  %pS @ %i\n", fn, task_pid_nr(current));
	*calltime = ktime_get();
}

static __init_or_module void
trace_initcall_finish_cb(void *data, initcall_t fn, int ret)
{
	ktime_t rettime, *calltime = data;

	rettime = ktime_get();
	printk(KERN_DEBUG "initcall %pS returned %d after %lld usecs\n",
		 fn, ret, (unsigned long long)ktime_us_delta(rettime, *calltime));
}

static ktime_t initcall_calltime;

#ifdef TRACEPOINTS_ENABLED
static void __init initcall_debug_enable(void)
{
	int ret;

	ret = register_trace_initcall_start(trace_initcall_start_cb,
					    &initcall_calltime);
	ret |= register_trace_initcall_finish(trace_initcall_finish_cb,
					      &initcall_calltime);
	WARN(ret, "Failed to register initcall tracepoints\n");
}
# define do_trace_initcall_start	trace_initcall_start
# define do_trace_initcall_finish	trace_initcall_finish
#else
static inline void do_trace_initcall_start(initcall_t fn)
{
	if (!initcall_debug)
		return;
	trace_initcall_start_cb(&initcall_calltime, fn);
}
static inline void do_trace_initcall_finish(initcall_t fn, int ret)
{
	if (!initcall_debug)
		return;
	trace_initcall_finish_cb(&initcall_calltime, fn, ret);
}
#endif /* !TRACEPOINTS_ENABLED */

int __init_or_module do_one_initcall(initcall_t fn)
{
	int count = preempt_count();
	char msgbuf[64];
	int ret;

	if (initcall_blacklisted(fn))
		return -EPERM;

	do_trace_initcall_start(fn);
	ret = fn();
	do_trace_initcall_finish(fn, ret);

	msgbuf[0] = 0;

	if (preempt_count() != count) {
		sprintf(msgbuf, "preemption imbalance ");
		preempt_count_set(count);
	}
	if (irqs_disabled()) {
		strlcat(msgbuf, "disabled interrupts ", sizeof(msgbuf));
		local_irq_enable();
	}
	WARN(msgbuf[0], "initcall %pS returned with %s\n", fn, msgbuf);

	add_latent_entropy();
	return ret;
}


extern initcall_entry_t __initcall_start[];
extern initcall_entry_t __initcall0_start[];
extern initcall_entry_t __initcall1_start[];
extern initcall_entry_t __initcall2_start[];
extern initcall_entry_t __initcall3_start[];
extern initcall_entry_t __initcall4_start[];
extern initcall_entry_t __initcall5_start[];
extern initcall_entry_t __initcall6_start[];
extern initcall_entry_t __initcall7_start[];
extern initcall_entry_t __initcall_end[];

static initcall_entry_t *initcall_levels[] __initdata = {
	__initcall0_start,
	__initcall1_start,
	__initcall2_start,
	__initcall3_start,
	__initcall4_start,
	__initcall5_start,
	__initcall6_start,
	__initcall7_start,
	__initcall_end,
};

/* Keep these in sync with initcalls in include/linux/init.h */
static const char *initcall_level_names[] __initdata = {
	"pure",
	"core",
	"postcore",
	"arch",
	"subsys",
	"fs",
	"device",
	"late",
};

static int __init ignore_unknown_bootoption(char *param, char *val,
			       const char *unused, void *arg)
{
	return 0;
}

static void __init do_initcall_level(int level, char *command_line)
{
	initcall_entry_t *fn;

	parse_args(initcall_level_names[level],
		   command_line, __start___param,
		   __stop___param - __start___param,
		   level, level,
		   NULL, ignore_unknown_bootoption);

	trace_initcall_level(initcall_level_names[level]);
	for (fn = initcall_levels[level]; fn < initcall_levels[level+1]; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static void __init do_initcalls(void)
{
	int level;
	size_t len = saved_command_line_len + 1;
	char *command_line;

	command_line = kzalloc(len, GFP_KERNEL);
	if (!command_line)
		panic("%s: Failed to allocate %zu bytes\n", __func__, len);

	for (level = 0; level < ARRAY_SIZE(initcall_levels) - 1; level++) {
		/* Parser modifies command_line, restore it each time */
		strcpy(command_line, saved_command_line);
		do_initcall_level(level, command_line);
	}

	kfree(command_line);
}

/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	driver_init();
	init_irq_proc();
	do_ctors();
	do_initcalls();
}

static void __init do_pre_smp_initcalls(void)
{
	initcall_entry_t *fn;

	trace_initcall_level("early");
	for (fn = __initcall_start; fn < __initcall0_start; fn++)
		do_one_initcall(initcall_from_entry(fn));
}

static int run_init_process(const char *init_filename)
{
	const char *const *p;

	argv_init[0] = init_filename;
	pr_info("Run %s as init process\n", init_filename);
	pr_debug("  with arguments:\n");
	for (p = argv_init; *p; p++)
		pr_debug("    %s\n", *p);
	pr_debug("  with environment:\n");
	for (p = envp_init; *p; p++)
		pr_debug("    %s\n", *p);
	return kernel_execve(init_filename, argv_init, envp_init);
}

static int try_to_run_init_process(const char *init_filename)
{
	int ret;

	ret = run_init_process(init_filename);

	if (ret && ret != -ENOENT) {
		pr_err("Starting init: %s exists but couldn't execute it (error %d)\n",
		       init_filename, ret);
	}

	return ret;
}

static noinline void __init kernel_init_freeable(void);

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
bool rodata_enabled __ro_after_init = true;

#ifndef arch_parse_debug_rodata
static inline bool arch_parse_debug_rodata(char *str) { return false; }
#endif

static int __init set_debug_rodata(char *str)
{
	if (arch_parse_debug_rodata(str))
		return 0;

	if (str && !strcmp(str, "on"))
		rodata_enabled = true;
	else if (str && !strcmp(str, "off"))
		rodata_enabled = false;
	else
		pr_warn("Invalid option string for rodata: '%s'\n", str);
	return 0;
}
early_param("rodata", set_debug_rodata);
#endif

#ifdef CONFIG_STRICT_KERNEL_RWX
static void mark_readonly(void)
{
	if (rodata_enabled) {
		/*
		 * load_module() results in W+X mappings, which are cleaned
		 * up with call_rcu().  Let's make sure that queued work is
		 * flushed so that we don't hit false positives looking for
		 * insecure pages which are W+X.
		 */
		rcu_barrier();
		mark_rodata_ro();
		rodata_test();
	} else
		pr_info("Kernel memory protection disabled.\n");
}
#elif defined(CONFIG_ARCH_HAS_STRICT_KERNEL_RWX)
static inline void mark_readonly(void)
{
	pr_warn("Kernel memory protection not selected by kernel config.\n");
}
#else
static inline void mark_readonly(void)
{
	pr_warn("This architecture does not have kernel memory protection.\n");
}
#endif

void __weak free_initmem(void)
{
	free_initmem_default(POISON_FREE_INITMEM);
}

static int __ref kernel_init(void *unused)
{
	int ret;

	/*
	 * Wait until kthreadd is all set-up.
	 */
	wait_for_completion(&kthreadd_done);

	kernel_init_freeable();
	/* need to finish all async __init code before freeing the memory */
	async_synchronize_full();

	system_state = SYSTEM_FREEING_INITMEM;
	kprobe_free_init_mem();
	ftrace_free_init_mem();
	kgdb_free_init_mem();
	exit_boot_config();
	free_initmem();
	mark_readonly();

	/*
	 * Kernel mappings are now finalized - update the userspace page-table
	 * to finalize PTI.
	 */
	pti_finalize();

	system_state = SYSTEM_RUNNING;
	numa_default_policy();

	rcu_end_inkernel_boot();

	do_sysctl_args();

	if (ramdisk_execute_command) {
		ret = run_init_process(ramdisk_execute_command);
		if (!ret)
			return 0;
		pr_err("Failed to execute %s (error %d)\n",
		       ramdisk_execute_command, ret);
	}

	/*
	 * We try each of these until one succeeds.
	 *
	 * The Bourne shell can be used instead of init if we are
	 * trying to recover a really broken machine.
	 */
	if (execute_command) {
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}

	if (CONFIG_DEFAULT_INIT[0] != '\0') {
		ret = run_init_process(CONFIG_DEFAULT_INIT);
		if (ret)
			pr_err("Default init %s failed (error %d)\n",
			       CONFIG_DEFAULT_INIT, ret);
		else
			return 0;
	}

	if (!try_to_run_init_process("/sbin/init") ||
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;

	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}

/* Open /dev/console, for stdin/stdout/stderr, this should never fail */
void __init console_on_rootfs(void)
{
	struct file *file = filp_open("/dev/console", O_RDWR, 0);

	if (IS_ERR(file)) {
		pr_err("Warning: unable to open an initial console.\n");
		return;
	}
	init_dup(file);
	init_dup(file);
	init_dup(file);
	fput(file);
}

static noinline void __init kernel_init_freeable(void)
{
	/* Now the scheduler is fully set up and can do blocking allocations */
	gfp_allowed_mask = __GFP_BITS_MASK;

	/*
	 * init can allocate pages on any node
	 */
	set_mems_allowed(node_states[N_MEMORY]);

	cad_pid = get_pid(task_pid(current));

	smp_prepare_cpus(setup_max_cpus);

	workqueue_init();

	init_mm_internals();

	rcu_init_tasks_generic();
	do_pre_smp_initcalls();
	lockup_detector_init();

	smp_init();
	sched_init_smp();

	padata_init();
	page_alloc_init_late();
	/* Initialize page ext after all struct pages are initialized. */
	if (!early_page_ext_enabled())
		page_ext_init();

	do_basic_setup();

	kunit_run_all_tests();

	wait_for_initramfs();
	console_on_rootfs();

	/*
	 * check if there is an early userspace init.  If yes, let it do all
	 * the work
	 */
	if (init_eaccess(ramdisk_execute_command) != 0) {
		ramdisk_execute_command = NULL;
		prepare_namespace();
	}

	/*
	 * Ok, we have completed the initial bootup, and
	 * we're essentially up and running. Get rid of the
	 * initmem segments and start the user-mode stuff..
	 *
	 * rootfs is available now, try loading the public keys
	 * and default modules
	 */

	integrity_load_keys();
}
