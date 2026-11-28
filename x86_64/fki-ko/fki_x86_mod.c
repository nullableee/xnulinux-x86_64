// SPDX-License-Identifier: GPL-2.0-only
/*
 * FKI-X86 v1 host module: semantic services for the separate x86_64 XNU path.
 *
 * This is the first host-side implementation. The world switch (GPRs/stacks)
 * lives in xnu-ko/world_x86.S; this file owns the ring-0 system state each
 * world needs: CR3, IDT/GDT, TR, GS bases, syscall MSRs and XSAVE state.
 * Linux keeps its own IDT while XNU runs, so XNU interrupt sources are all
 * delivered through host calls.
 */
#include "fki.h"
#include "fki_internal.h"

#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/firmware.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/irqflags.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>

#include <asm/desc.h>
#include <asm/fpu/api.h>
#include <asm/msr.h>
#include <asm/ptrace.h>
#include <asm/processor.h>

/* Every CPU that can host XNU gets one wake word + completion. */
static const volatile unsigned int *x86_wake_word[NR_CPUS];
static struct completion x86_wake[NR_CPUS];
static DEFINE_PER_CPU(call_single_data_t, x86_csd);

/*
 * XNU is not built with -fcf-protection: _vstart begins with "push %rbp",
 * so the downcall's `call *%rax' would raise #CP with IBT enabled.
 *
 * CR4.CET is per-CPU and ring-0 writable. Drop it while the XNU world owns
 * the CPU and restore it on every upcall/leave. native_write_cr4() re-adds
 * pinned CR4 bits (including CET), so CR4 is written directly with MOV.
 */
#define FKI_X86_CR4_CET_BIT	23
#define FKI_X86_CR4_CET		(1UL << FKI_X86_CR4_CET_BIT)
static DEFINE_PER_CPU(unsigned long, x86_saved_cr4);
static bool x86_ibt_logged;

/*
 * native_write_cr4() re-adds "pinned" bits, including CR4.CET on this host:
 * the previous attempt produced "pinned CR4 bits changed: 0x800000!?" and
 * CET stayed on.  CR4 is ring-0 writable with MOV, so bypass that policy.
 */
static inline unsigned long fki_x86_read_cr4(void)
{
	unsigned long val;

	asm volatile ("mov %%cr4, %0" : "=r" (val));
	return val;
}

static inline void fki_x86_write_cr4(unsigned long val)
{
	asm volatile ("mov %0, %%cr4" : : "r" (val) : "memory");
}

static inline unsigned long fki_x86_ibt_off(void)
{
	unsigned long cr4 = fki_x86_read_cr4();

	if (cr4 & FKI_X86_CR4_CET)
		fki_x86_write_cr4(cr4 & ~FKI_X86_CR4_CET);
	return cr4;
}

static inline void fki_x86_ibt_restore(unsigned long cr4)
{
	unsigned long now;

	if (!(cr4 & FKI_X86_CR4_CET))
		return;
	now = fki_x86_read_cr4();
	if (!(now & FKI_X86_CR4_CET))
		fki_x86_write_cr4(now | FKI_X86_CR4_CET);
}

struct x86_desc_ptr {
	u16 limit;
	u64 base;
} __packed;

/*
 * This runs from the upcall after CR3 is Linux's but before
 * fki_x86_load_state_asm() restores Linux's GS base and IDT. %gs still holds
 * XNU's value, so a compiler-generated stack-canary read from %gs would fault
 * through XNU's IDT. Use raw asm (no paravirt callbacks, no %gs) and opt out
 * of stack protection.
 */
#define FKI_RAW_RDMSR(msr, dst)					\
	do {								\
		u32 fki_lo, fki_hi;					\
		asm volatile("rdmsr" : "=a" (fki_lo), "=d" (fki_hi)	\
		    : "c" (msr));					\
		(dst) = ((fki_u64)fki_hi << 32) | fki_lo;		\
	} while (0)

static void __attribute__((no_stack_protector))
x86_save_state(struct fki_x86_state *s)
{
	struct x86_desc_ptr idt, gdt;
	u16 tr = 0;

	/* Fine-grained breadcrumbs: the logger thread sees these. */
	fki_x86_phase_set(50, (unsigned long)s);
	asm volatile("mov %%cr3, %0" : "=r" (s->cr3));
	fki_x86_phase_set(51, s->cr3);
	asm volatile("sidt %0" : "=m" (idt));
	fki_x86_phase_set(52, idt.base);
	asm volatile("sgdt %0" : "=m" (gdt));
	fki_x86_phase_set(53, gdt.base);
	asm volatile("str %0" : "=m" (tr));
	fki_x86_phase_set(54, tr);
	s->idt_base = idt.base;
	s->idt_limit = idt.limit;
	s->gdt_base = gdt.base;
	s->gdt_limit = gdt.limit;
	s->tr = tr;
	FKI_RAW_RDMSR(MSR_GS_BASE, s->gs_base);
	fki_x86_phase_set(55, s->gs_base);
	FKI_RAW_RDMSR(MSR_KERNEL_GS_BASE, s->kernel_gs_base);
	fki_x86_phase_set(56, s->kernel_gs_base);
	FKI_RAW_RDMSR(MSR_STAR, s->star);
	fki_x86_phase_set(57, s->star);
	FKI_RAW_RDMSR(MSR_LSTAR, s->lstar);
	fki_x86_phase_set(58, s->lstar);
	FKI_RAW_RDMSR(MSR_CSTAR, s->cstar);
	fki_x86_phase_set(59, s->cstar);
	FKI_RAW_RDMSR(MSR_SYSCALL_MASK, s->sfmask);
	fki_x86_phase_set(60, s->sfmask);
}

extern void fki_x86_load_state_asm(const struct fki_x86_state *s);

static void x86_load_state(const struct fki_x86_state *s)
{
	struct x86_desc_ptr idt = { .limit = s->idt_limit, .base = s->idt_base };
	struct x86_desc_ptr gdt = { .limit = s->gdt_limit, .base = s->gdt_base };

	write_cr3(s->cr3);
	asm volatile ("lgdt %0" : : "m" (gdt) : "memory");
	asm volatile ("lidt %0" : : "m" (idt) : "memory");
	if (s->tr) {
		u16 cur_tr = 0;

		asm volatile ("str %0" : "=m" (cur_tr));
		if (cur_tr != s->tr)
			asm volatile ("ltr %w0" : : "r" (s->tr) : "memory");
	}
	wrmsrq(MSR_KERNEL_GS_BASE, s->kernel_gs_base);
	wrmsrq(MSR_GS_BASE, s->gs_base);
	wrmsrq(MSR_STAR, s->star);
	wrmsrq(MSR_LSTAR, s->lstar);
	wrmsrq(MSR_CSTAR, s->cstar);
	wrmsrq(MSR_SYSCALL_MASK, s->sfmask);
}

/* xsave/xrstor with all currently supported feature bits. The buffer belongs
 * to the world and must be 64-byte aligned; fki_x86_shared_alloc enforces it. */
static inline void x86_xsave(void *buf)
{
	__asm__ volatile ("xsave %0"
	    : "+m" (*(volatile char (*)[64])buf)
	    : "a" (0xffffffffU), "d" (0xffffffffU)
	    : "memory");
}

static inline void x86_xrstor(const void *buf)
{
	__asm__ volatile ("xrstor %0"
	    : : "m" (*(const volatile char (*)[64])buf),
	        "a" (0xffffffffU), "d" (0xffffffffU)
	    : "memory");
}

unsigned long fki_x86_enter_prep(const struct fki_x86_state *foreign,
    struct fki_x86_state *saved)
{
	unsigned long flags;

	if (!foreign)
		return 0;
	fki_x86_phase_set(2, 0);
	preempt_disable();
	local_irq_save(flags);
	x86_save_state(saved);
	/* Save Linux's FPU/CET state before disabling CET. */
	if (foreign->xsave_va && foreign->xsave_size && saved->xsave_va &&
	    saved->xsave_size)
		x86_xsave((void *)saved->xsave_va);
	this_cpu_write(x86_saved_cr4, fki_x86_ibt_off());
	fki_x86_phase_set(3, fki_x86_read_cr4());
	if (!x86_ibt_logged) {
		x86_ibt_logged = true;
		pr_info("fki-x86: XNU world IBT off: cr4 0x%lx -> 0x%lx\n",
		    this_cpu_read(x86_saved_cr4), fki_x86_read_cr4());
	}
	if (foreign->xsave_va && foreign->xsave_size)
		x86_xrstor((const void *)foreign->xsave_va);
	fki_x86_phase_set(4, 0);
	/*
	 * No fsynced trace here: preemption and IRQs are already off, so
	 * fki_debug_log()'s mutex/file I/O would sleep and trip
	 * "scheduling while atomic" (panic_on_warn makes that fatal).
	 * The phase breadcrumbs above are picked up by a kthread instead.
	 */
	return flags;
}
EXPORT_SYMBOL(fki_x86_enter);

void fki_x86_leave(unsigned long cookie, struct fki_x86_state *saved,
    struct fki_x86_state *foreign)
{
	if (!saved)
		return;
	/*
	 * The upcall switched CR3 to Linux but XNU's IDT is still loaded until
	 * fki_x86_load_state_asm() below. Mask interrupts before touching any
	 * state: a timer tick here would vector through XNU's handlers with
	 * Linux CR3 active and hang the CPU. fki_x86_enter_prep() left
	 * preemption disabled, and cookie restores the original IRQ flags at
	 * the end of this function.
	 */
	local_irq_disable();
	fki_x86_phase_set(30, 0);
	if (foreign) {
		fki_u64 prev_cr3 = foreign->cr3;

		fki_x86_phase_set(34, (unsigned long)foreign);
		x86_save_state(foreign);
		fki_x86_phase_set(35, foreign->cr3);
		if (prev_cr3)
			foreign->cr3 = prev_cr3;
	}
	fki_x86_phase_set(31, saved->cr3);
	fki_x86_load_state_asm(saved);
	/*
	 * The XSAVE buffers live in the Linux direct map, which XNU's page
	 * tables do not cover. Saving XNU's FPU state here, after CR3 is back
	 * to Linux, avoids a #PF under the XNU world (panic_on_warn made that
	 * a hard hang). Interrupts are still off and preemption still disabled.
	 */
	if (foreign && foreign->xsave_va && foreign->xsave_size)
		x86_xsave((void *)foreign->xsave_va);
	fki_x86_phase_set(36, 0);
	if (saved->xsave_va && saved->xsave_size)
		x86_xrstor((const void *)saved->xsave_va);
	fki_x86_ibt_restore(this_cpu_read(x86_saved_cr4));
	local_irq_restore(cookie);
	preempt_enable();
	fki_x86_phase_set(32, 0);
}

/*
 * Seed a world's XSAVE buffer with a sane FPU/SIMD state. The contiguous
 * regions come zeroed; restoring those would set MXCSR=0 (all SIMD exceptions
 * unmasked) before XNU has an IDT, so even ordinary memcpy can triple fault.
 */
void fki_x86_fpstate_save(void *buf)
{
	if (buf)
		x86_xsave(buf);
}
EXPORT_SYMBOL(fki_x86_fpstate_save);
EXPORT_SYMBOL(fki_x86_leave);

void fki_x86_swap_user_state(const struct fki_x86_state *load,
    struct fki_x86_state *save)
{
	unsigned long flags;

	local_irq_save(flags);
	if (save)
		x86_save_state(save);
	if (load)
		x86_load_state(load);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(fki_x86_swap_user_state);

/* ---- Letting Linux run while XNU is parked -------------------------------- */

static void x86_kick_fn(void *data)
{
	int cpu = (unsigned long)data;

	if (cpu >= 0 && cpu < NR_CPUS && x86_wake_word[cpu])
		complete(&x86_wake[cpu]);
}

void fki_x86_kick_cpu(int cpu)
{
	if (cpu < 0 || cpu >= nr_cpu_ids)
		return;
	if (x86_wake_word[cpu])
		complete(&x86_wake[cpu]);
	/* smp_call_function_single_async is safe from IRQ-off context. */
	smp_call_function_single_async(cpu, this_cpu_ptr(&x86_csd));
}
EXPORT_SYMBOL(fki_x86_kick_cpu);

/*
 * These helpers run from the Linux world after fki_x86_leave() has already
 * restored Linux's IRQ and preemption state.  The old version called
 * preempt_enable() here, driving preempt_count negative while sleeping; with
 * panic_on_warn that makes wait/schedule unreliable and can corrupt the host
 * scheduler.  The upcall's fki_x86_enter() re-disables both on return.
 */
void fki_x86_idle_until(fki_u64 counter_deadline, fki_u64 max_ns,
    const volatile unsigned int *wake)
{
	int cpu;

	might_sleep();
	cpu = smp_processor_id();
	x86_wake_word[cpu] = wake;
	if (wake && *wake) {
		x86_wake_word[cpu] = NULL;
		return;
	}
	reinit_completion(&x86_wake[cpu]);

	/* TODO(stage 3): arm an hrtimer at counter_deadline; for now the host
	 * wakes us from its own timer or from fki_x86_kick_cpu(). */
	wait_for_completion_timeout(&x86_wake[cpu],
	    usecs_to_jiffies(max_ns / NSEC_PER_USEC));
	(void)counter_deadline;
	x86_wake_word[cpu] = NULL;
}
EXPORT_SYMBOL(fki_x86_idle_until);

void fki_x86_yield(void)
{
	cond_resched();
}
EXPORT_SYMBOL(fki_x86_yield);

void fki_linux_runs_ext(void (*fn)(void *), void *arg)
{
	might_sleep();
	fn(arg);
}

/* ---- CPU discovery --------------------------------------------------------- */

int fki_x86_num_cpus(void)
{
	return num_online_cpus();
}
EXPORT_SYMBOL(fki_x86_num_cpus);

int fki_x86_cpu_apic_id(int cpu, fki_u64 *apic_id)
{
	if (!apic_id || cpu < 0 || cpu >= nr_cpu_ids)
		return -EINVAL;
	*apic_id = cpu_data(cpu).topo.initial_apicid;
	return 0;
}
EXPORT_SYMBOL(fki_x86_cpu_apic_id);

/* ---- Basic services -------------------------------------------------------- */

int fki_version(void)
{
	return FKI_X86_VERSION;
}
EXPORT_SYMBOL(fki_version);

void fki_log(const char *s, unsigned long len)
{
	pr_info("fki-x86: %.*s\n", (int)len, s);
}
EXPORT_SYMBOL(fki_log);

void fki_log_alert(const char *s, unsigned long len)
{
	pr_alert("fki-x86: %.*s\n", (int)len, s);
}
EXPORT_SYMBOL(fki_log_alert);

/*
 * dmesg/journald are useless when XNU wedges the box with interrupts off:
 * neither the reader nor the journal flusher gets scheduled. Append each
 * trace line to a plain file; kernel_write() makes it visible in the page
 * cache immediately, while avoiding an fsync that can stall with the world
 * switch in progress.
 */
#define FKI_DEBUG_PATH "/home/spotlight/xnu-boot.log"
static struct file *fki_debug_file;
static fki_u64 fki_debug_off;
static DEFINE_MUTEX(fki_debug_lock);

/*
 * World-switch breadcrumbs. The downcall runs with preemption and IRQs off,
 * and an early XNU fault can reset the box before dmesg is ever flushed. The
 * phase/arg pair is written with plain stores (safe from asm and atomic
 * context); a kthread on another CPU polls it and appends to the file trace.
 *
 * Phases:
 *   2 enter_prep, 3 ibt off, 4 xrstor done
 *   5 load_state before CR3, 6 after CR3, 7 MSRs done
 *   10 world_call back from enter, 11 before XNU entry, 12 XNU returned
 *   20 trampoline after CR3, 21 upcall entry, 22 upcall world found,
 *   23 upcall Linux world, 24 upcall back in XNU, 25 upcall abort
 *   30 leave entry, 31 before state load, 32 leave done
 *   34 leave_save_state, 35 leave_saved, 36 leave_xnu_xsaved
 *   40 xnu_hook_x86 entry
 *   50..60 x86_save_state steps (cr3/sidt/sgdt/str/MSRs)
 */
volatile unsigned long fki_x86_phase;
volatile unsigned long fki_x86_phase_arg;
volatile unsigned long xnu_site3_hook_pre;
/* Plain-store progress inside xnu_hook_x86(), readable live from another CPU
 * via /proc/fki_x86_live. 1 entry, 2 upcall line queued, 3 first site mark,
 * 4 verbose mark, 5 SITE_TAG case, 6 SITE_TAG mark done. */
volatile unsigned long fki_x86_hook_stage;
EXPORT_SYMBOL(fki_x86_phase);
EXPORT_SYMBOL(fki_x86_phase_arg);
EXPORT_SYMBOL(xnu_site3_hook_pre);
EXPORT_SYMBOL(fki_x86_hook_stage);

/* From xnu_hook_x86.c: upcalls are counted even when their log lines are
 * rate-limited, so a stable phase can be told apart from a long XNU run. */
extern unsigned long xnu_upcall_count;
extern unsigned long xnu_upcall_last;
extern unsigned long xnu_upcall_tag;

void fki_x86_phase_set(unsigned long phase, unsigned long arg)
{
	fki_x86_phase_arg = arg;
	/* Publish arg first; the logger only reads the phase after this. */
	smp_mb();
	fki_x86_phase = phase;
}
EXPORT_SYMBOL(fki_x86_phase_set);

static const char *fki_phase_name(unsigned long p)
{
	switch (p) {
	case 2:  return "enter_prep";
	case 3:  return "ibt_off";
	case 4:  return "xrstor";
	case 5:  return "load_pre_cr3";
	case 6:  return "load_post_cr3";
	case 7:  return "load_msrs";
	case 10: return "world_entered";
	case 11: return "before_vstart";
	case 12: return "vstart_returned";
	case 20: return "trampoline_cr3";
	case 21: return "upcall_entry";
	case 22: return "upcall_world";
	case 23: return "upcall_linux";
	case 24: return "upcall_xnu";
	case 25: return "upcall_abort";
	case 74: return "upcall_fields";
	case 75: return "upcall_hook";
	case 76: return "upcall_hooked";
	case 70: return "site3_pre_cr3";
	case 71: return "site3_post_cr3";
	case 72: return "site3_hook_read";
	case 73: return "site3_before_call";
	case 30: return "leave_entry";
	case 31: return "leave_pre_cr3";
	case 32: return "leave_done";
	case 33: return "leave_xsaved";
	case 34: return "leave_save_state";
	case 35: return "leave_saved";
	case 36: return "leave_xnu_xsaved";
	case 40: return "host_hook";
	case 50: return "save_enter";
	case 51: return "save_cr3";
	case 52: return "save_sidt";
	case 53: return "save_sgdt";
	case 54: return "save_str";
	case 55: return "save_gs_base";
	case 56: return "save_kernel_gs";
	case 57: return "save_star";
	case 58: return "save_lstar";
	case 59: return "save_cstar";
	case 60: return "save_sfmask";
	default: return "?";
	}
}

static unsigned int fki_trace_drain(void);
static unsigned int fki_trace_seq_snap(void);
static unsigned int fki_trace_drained_snap(void);

/*
 * An emergency reboot loses page-cache-only writes, which made a freshly
 * created xnu-boot.log look empty. Only the logger thread calls this, in
 * ordinary context on a different CPU; the upcall hook never syncs.
 */
static void fki_debug_sync(void)
{
	mutex_lock(&fki_debug_lock);
	if (fki_debug_file)
		vfs_fsync(fki_debug_file, 0);
	mutex_unlock(&fki_debug_lock);
}

static int fki_phase_logger(void *unused)
{
	unsigned long last = READ_ONCE(fki_x86_phase);
	unsigned int tick = 0, sync_tick = 0;

	while (!fki_thread_should_stop()) {
		unsigned long p = READ_ONCE(fki_x86_phase);

		/* Also log a stable phase every 100 ms: if XNU hangs inside a
		 * long run, the phase stops changing and a change-only logger
		 * would leave no trace at all. */
		if (p != last || ++tick >= 20) {
			char buf[256];
			int n = snprintf(buf, sizeof(buf),
			    "phase: %lu %s arg=0x%lx pre=0x%lx upcalls=%lu "
			    "last=0x%lx tag=0x%lx stage=%lu ring=%u/%u\n",
			    p, fki_phase_name(p), READ_ONCE(fki_x86_phase_arg),
			    READ_ONCE(xnu_site3_hook_pre),
			    READ_ONCE(xnu_upcall_count),
			    READ_ONCE(xnu_upcall_last),
			    READ_ONCE(xnu_upcall_tag),
			    READ_ONCE(fki_x86_hook_stage),
			    fki_trace_seq_snap(), fki_trace_drained_snap());

			if (n > 0)
				fki_debug_log(buf, min_t(int, n, sizeof(buf) - 1));
			last = p;
			tick = 0;
		}
		/* Drain hook lines from this CPU, never from the upcall CPU. */
		if (fki_trace_drain())
			fki_debug_sync();
		/* Phase lines also need flushing: a hard reset after a wedged
		 * run must leave the last known state on disk. */
		if (++sync_tick >= 20) {
			fki_debug_sync();
			sync_tick = 0;
		}
		fki_msleep(5);
	}
	return 0;
}

static int fki_debug_log_file(const char *s, unsigned long len)
{
	loff_t pos;
	ssize_t n;

	if (!s || !len)
		return 0;
	mutex_lock(&fki_debug_lock);
	if (!fki_debug_file) {
		mutex_unlock(&fki_debug_lock);
		return -ENOENT;
	}
	pos = fki_debug_off;
	n = kernel_write(fki_debug_file, s, len, &pos);
	if (n > 0)
		fki_debug_off += n;
	/* No vfs_fsync(): kernel_write() already makes the line visible in the
	 * page cache, and fsync() would hold this mutex across storage I/O. */
	mutex_unlock(&fki_debug_lock);
	return n < 0 ? n : 0;
}

/*
 * Upcall trace ring. xnu_hook_x86() runs with the foreign world's state live;
 * a mutex_lock() there can block on fki_debug_lock held by the phase logger
 * inside kernel_write(), wedging the single CPU that owns the run. The hook
 * now only reserves a slot and memcpy()s; the logger drains the ring in
 * ordinary context. Nothing here can sleep.
 */
#define FKI_TRACE_SLOTS	1024
#define FKI_TRACE_LINE	256
static char fki_trace_lines[FKI_TRACE_SLOTS][FKI_TRACE_LINE];
static u16 fki_trace_lens[FKI_TRACE_SLOTS];
static u8 fki_trace_ready[FKI_TRACE_SLOTS];
static atomic_t fki_trace_seq = ATOMIC_INIT(0);
static unsigned int fki_trace_drained;

void fki_trace_push(const char *s, unsigned long len)
{
	unsigned int slot;

	if (!s || !len)
		return;
	slot = (unsigned int)atomic_inc_return(&fki_trace_seq);
	slot &= FKI_TRACE_SLOTS - 1;
	if (len >= FKI_TRACE_LINE)
		len = FKI_TRACE_LINE - 1;
	memcpy(fki_trace_lines[slot], s, len);
	fki_trace_lens[slot] = (u16)len;
	smp_wmb();
	WRITE_ONCE(fki_trace_ready[slot], 1);
}
EXPORT_SYMBOL(fki_trace_push);

static unsigned int fki_trace_drain(void)
{
	unsigned int end = (unsigned int)atomic_read(&fki_trace_seq);
	unsigned int n = 0;

	while (fki_trace_drained < end) {
		unsigned int slot = fki_trace_drained & (FKI_TRACE_SLOTS - 1);

		if (!READ_ONCE(fki_trace_ready[slot]))
			break;
		fki_debug_log_file(fki_trace_lines[slot],
		    fki_trace_lens[slot]);
		WRITE_ONCE(fki_trace_ready[slot], 0);
		fki_trace_drained++;
		n++;
	}
	return n;
}

static unsigned int fki_trace_seq_snap(void)
{
	return (unsigned int)atomic_read(&fki_trace_seq);
}

static unsigned int fki_trace_drained_snap(void)
{
	return READ_ONCE(fki_trace_drained);
}

int fki_debug_log(const char *s, unsigned long len)
{
	if (!s || !len)
		return 0;
	/*
	 * World-switch code can call this with preemption/IRQs disabled;
	 * mutex_lock() and kernel_write() would schedule there and panic the
	 * host with panic_on_warn. Emit to printk instead; the file trace is
	 * only for callers in ordinary context.
	 */
	if (preempt_count() || irqs_disabled()) {
		printk(KERN_INFO "fki-x86: %.*s\n", (int)len, s);
		return 0;
	}
	return fki_debug_log_file(s, len);
}
EXPORT_SYMBOL(fki_debug_log);

static void fki_debug_init(void)
{
	fki_debug_file = filp_open(FKI_DEBUG_PATH,
	    O_WRONLY | O_CREAT | O_APPEND | O_LARGEFILE, 0600);
	if (IS_ERR(fki_debug_file)) {
		pr_warn("fki-x86: cannot open %s for tracing\n", FKI_DEBUG_PATH);
		fki_debug_file = NULL;
		return;
	}
	fki_debug_off = i_size_read(file_inode(fki_debug_file));
}

static void fki_debug_exit(void)
{
	if (fki_debug_file)
		filp_close(fki_debug_file, NULL);
	fki_debug_file = NULL;
}

fki_u64 fki_counter_frequency(void)
{
	return NSEC_PER_SEC;
}
EXPORT_SYMBOL(fki_counter_frequency);

fki_u64 fki_counter(void)
{
	return ktime_get_ns();
}
EXPORT_SYMBOL(fki_counter);

void fki_random(void *buf, unsigned long len)
{
	get_random_bytes(buf, len);
}
EXPORT_SYMBOL(fki_random);

void fki_realtime(fki_u64 *sec, fki_u64 *nsec)
{
	struct timespec64 ts;

	ktime_get_real_ts64(&ts);
	*sec = ts.tv_sec;
	*nsec = ts.tv_nsec;
}
EXPORT_SYMBOL(fki_realtime);

int fki_bind_cpu(int cpu)
{
	return set_cpus_allowed_ptr(current, cpumask_of(cpu));
}
EXPORT_SYMBOL(fki_bind_cpu);

void fki_msleep(unsigned int ms)
{
	msleep(ms);
}
EXPORT_SYMBOL(fki_msleep);

/* ---- Firmware blobs (the kernel collection, ramdisk, trust cache) ---------- */

int fki_blob_get(const char *name, const void **data, unsigned long *size,
    void **handle)
{
	const struct firmware *fw;
	int err = request_firmware(&fw, name, NULL);

	if (err)
		return err;
	*data = fw->data;
	*size = fw->size;
	*handle = (void *)fw;
	return 0;
}
EXPORT_SYMBOL(fki_blob_get);

void fki_blob_put(void *handle)
{
	release_firmware(handle);
}
EXPORT_SYMBOL(fki_blob_put);

/* ---- Host files (block devices, console, keystore) ------------------------ */

void *fki_file_open(const char *path, int writable, fki_u64 *size)
{
	struct file *f = filp_open(path,
	    (writable ? O_RDWR : O_RDONLY) | O_LARGEFILE, 0);

	if (IS_ERR(f))
		return NULL;
	if (size)
		*size = i_size_read(f->f_mapping->host);
	return f;
}
EXPORT_SYMBOL(fki_file_open);

#define FKI_FILE_CHUNK (256UL << 10)

struct fki_file_args {
	void *file;
	int write;
	void *buf;
	unsigned long len;
	fki_u64 off;
	long ret;
};

static long fki_file_rw_body(void *file, int write, void *buf,
    unsigned long len, fki_u64 off)
{
	struct file *f = file;
	unsigned long done = 0;
	long ret = 0;
	void *bounce;

	bounce = kvmalloc(min(len, FKI_FILE_CHUNK), GFP_KERNEL);
	if (!bounce)
		return -ENOMEM;
	while (done < len) {
		unsigned long n = min(len - done, FKI_FILE_CHUNK);
		loff_t pos = off + done;
		ssize_t r;

		if (write) {
			memcpy(bounce, (char *)buf + done, n);
			r = kernel_write(f, bounce, n, &pos);
		} else {
			r = kernel_read(f, bounce, n, &pos);
			if (r > 0)
				memcpy((char *)buf + done, bounce, r);
		}
		if (r < 0) {
			ret = r;
			break;
		}
		done += r;
		if ((unsigned long)r < n)
			break;
	}
	kvfree(bounce);
	return ret < 0 && !done ? ret : (long)done;
}

static void fki_file_rw_thunk(void *p)
{
	struct fki_file_args *a = p;

	a->ret = fki_file_rw_body(a->file, a->write, a->buf, a->len, a->off);
}

long fki_file_rw(void *file, int write, void *buf, unsigned long len,
    fki_u64 off)
{
	struct fki_file_args a = { file, write, buf, len, off, -EIO };

	if (!file)
		return -EBADF;
	fki_linux_runs_ext(fki_file_rw_thunk, &a);
	return a.ret;
}
EXPORT_SYMBOL(fki_file_rw);

long fki_file_pwrite(void *file, const void *buf, unsigned long len,
    fki_u64 off)
{
	loff_t pos = off;

	if (!file)
		return -EBADF;
	return kernel_write(file, buf, len, &pos);
}
EXPORT_SYMBOL(fki_file_pwrite);

void fki_file_close(void *file)
{
	if (file)
		filp_close(file, NULL);
}
EXPORT_SYMBOL(fki_file_close);

/* ---- Memory ---------------------------------------------------------------- */

/*
 * dma_alloc_coherent(NULL, ...) dereferences a struct device on current
 * kernels, and the requested regions are far larger than MAX_ORDER anyway.
 * alloc_contig_pages() gives the contiguous PFNs the foreign kernel's page
 * tables need; page_address() is only used by the host to fill the region.
 * XNU maps these pages itself with non-NX entries after the CR3 switch, so
 * set_memory_x() and the kallsyms lookup are unnecessary.
 */
int fki_x86_shared_alloc(unsigned long size, struct fki_region *r)
{
	struct page *page;
	unsigned long nr_pages;

	if (!r || !size)
		return -EINVAL;
	nr_pages = PFN_UP(size);
	/* XNU's boot_args stores kaddr/MemoryMap as 32-bit physical addresses,
	 * so every region handed to it must come from ZONE_DMA32. */
	pr_info("fki-x86: alloc %lu contiguous pages on node %d\n",
	    nr_pages, numa_node_id());
	/* alloc_contig_pages() does not accept NUMA_NO_NODE: it indexes
	 * node_zonelist(nid) directly. */
	page = alloc_contig_pages_noprof(nr_pages,
	    GFP_KERNEL | GFP_DMA32 | __GFP_ZERO, numa_node_id(), NULL);
	if (!page)
		return -ENOMEM;
	r->va = page_address(page);
	r->pa = page_to_phys(page);
	pr_info("fki-x86:   va=%p pa=0x%llx\n", r->va,
	    (unsigned long long)r->pa);
	r->size = nr_pages << PAGE_SHIFT;
	r->handle = page;
	return 0;
}
EXPORT_SYMBOL(fki_x86_shared_alloc);

void fki_x86_shared_free(struct fki_region *r)
{
	struct page *page;
	unsigned long nr_pages;

	if (!r || !r->va)
		return;
	page = r->handle;
	nr_pages = r->size >> PAGE_SHIFT;
	if (page && nr_pages)
		free_contig_range(page_to_pfn(page), nr_pages);
	memset(r, 0, sizeof(*r));
}
EXPORT_SYMBOL(fki_x86_shared_free);

int fki_region_alloc(unsigned long size, struct fki_region *r)
{
	return fki_x86_shared_alloc(size, r);
}
EXPORT_SYMBOL(fki_region_alloc);

void fki_region_free(struct fki_region *r)
{
	fki_x86_shared_free(r);
}
EXPORT_SYMBOL(fki_region_free);

fki_u64 fki_phys_peek(fki_u64 pa)
{
	void __iomem *p = ioremap(pa, sizeof(u64));
	fki_u64 v = 0;

	if (p) {
		v = readq(p);
		iounmap(p);
	}
	return v;
}
EXPORT_SYMBOL(fki_phys_peek);

int fki_contig_alloc(unsigned long size, struct fki_region *r)
{
	return fki_x86_shared_alloc(size, r);
}
EXPORT_SYMBOL(fki_contig_alloc);

void fki_contig_free(struct fki_region *r)
{
	fki_x86_shared_free(r);
}
EXPORT_SYMBOL(fki_contig_free);

/* ---- Faults ---------------------------------------------------------------- */

struct x86_fault_handler {
	unsigned long lo, hi;
	int (*fn)(struct fki_x86_regs *regs, void *arg);
	void *arg;
};
static struct x86_fault_handler x86_fault;

static void x86_fill_regs(struct fki_x86_regs *out, struct pt_regs *in,
    unsigned long vector)
{
	out->vector = vector;
	out->rip = in->ip;
	out->rflags = in->flags;
	out->cr2 = read_cr2();
	out->error_code = in->orig_ax;
	out->rax = in->ax;
	out->rbx = in->bx;
	out->rcx = in->cx;
	out->rdx = in->dx;
	out->rsi = in->si;
	out->rdi = in->di;
	out->rbp = in->bp;
	out->rsp = in->sp;
	out->r8 = in->r8;
	out->r9 = in->r9;
	out->r10 = in->r10;
	out->r11 = in->r11;
	out->r12 = in->r12;
	out->r13 = in->r13;
	out->r14 = in->r14;
	out->r15 = in->r15;
}

unsigned long fki_x86_regs_pc(const struct fki_x86_regs *regs)
{
	return regs->rip;
}
EXPORT_SYMBOL(fki_x86_regs_pc);

void fki_x86_regs_set_pc(struct fki_x86_regs *regs, unsigned long pc)
{
	regs->rip = pc;
}
EXPORT_SYMBOL(fki_x86_regs_set_pc);

void fki_x86_regs_set_reg(struct fki_x86_regs *regs, unsigned int n,
    unsigned long v)
{
	static unsigned short offset[] = {
		offsetof(struct fki_x86_regs, rax), offsetof(struct fki_x86_regs, rbx),
		offsetof(struct fki_x86_regs, rcx), offsetof(struct fki_x86_regs, rdx),
		offsetof(struct fki_x86_regs, rsi), offsetof(struct fki_x86_regs, rdi),
		offsetof(struct fki_x86_regs, rbp), offsetof(struct fki_x86_regs, rsp),
		offsetof(struct fki_x86_regs, r8),  offsetof(struct fki_x86_regs, r9),
		offsetof(struct fki_x86_regs, r10), offsetof(struct fki_x86_regs, r11),
		offsetof(struct fki_x86_regs, r12), offsetof(struct fki_x86_regs, r13),
		offsetof(struct fki_x86_regs, r14), offsetof(struct fki_x86_regs, r15),
	};

	if (n < ARRAY_SIZE(offset))
		*(unsigned long *)((char *)regs + offset[n]) = v;
}
EXPORT_SYMBOL(fki_x86_regs_set_reg);

int fki_x86_fault_register(unsigned long lo, unsigned long hi,
    int (*handler)(struct fki_x86_regs *regs, void *arg), void *arg)
{
	if (!handler || x86_fault.fn)
		return -EBUSY;
	x86_fault.lo = lo;
	x86_fault.hi = hi;
	x86_fault.fn = handler;
	x86_fault.arg = arg;
	/*
	 * TODO(stage 3): install kprobes on do_page_fault/do_general_protection/
	 * do_trap and call x86_fill_regs() from their pre_handlers. The current
	 * ABI is in place; hooking Linux's fault entries is the remaining work.
	 */
	return 0;
}
EXPORT_SYMBOL(fki_x86_fault_register);

void fki_x86_fault_unregister(void)
{
	memset(&x86_fault, 0, sizeof(x86_fault));
}
EXPORT_SYMBOL(fki_x86_fault_unregister);

/* ---- Thread helpers -------------------------------------------------------- */

struct x86_thread {
	struct task_struct *task;
	int (*fn)(void *);
	void *arg;
};

static int x86_thread_fn(void *data)
{
	struct x86_thread *t = data;
	int ret;

	while (!kthread_should_stop()) {
		ret = t->fn(t->arg);
		if (ret < 0)
			msleep(100);
	}
	return 0;
}

void *fki_thread_start(int (*fn)(void *), void *arg, int cpu,
    const char *name)
{
	struct x86_thread *t = kzalloc(sizeof(*t), GFP_KERNEL);

	if (!t)
		return NULL;
	t->fn = fn;
	t->arg = arg;
	t->task = kthread_create(x86_thread_fn, t, "%s", name);
	if (IS_ERR(t->task)) {
		kfree(t);
		return NULL;
	}
	if (cpu >= 0)
		kthread_bind(t->task, cpu);
	wake_up_process(t->task);
	return t;
}
EXPORT_SYMBOL(fki_thread_start);

void fki_thread_stop(void *thread)
{
	struct x86_thread *t = thread;

	if (!t)
		return;
	kthread_stop(t->task);
	kfree(t);
}
EXPORT_SYMBOL(fki_thread_stop);

int fki_thread_should_stop(void)
{
	return kthread_should_stop();
}
EXPORT_SYMBOL(fki_thread_should_stop);

void fki_thread_wait(const volatile unsigned long *flag)
{
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (READ_ONCE(*flag) || kthread_should_stop())
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
}
EXPORT_SYMBOL(fki_thread_wait);

void fki_thread_wake(void *thread)
{
	if (thread)
		wake_up_process(thread);
}
EXPORT_SYMBOL(fki_thread_wake);

static void *fki_phase_thread;

/*
 * Live snapshot for a wedged insmod: plain stores only, no I/O in the hook,
 * and readable from any other CPU even when the file logger is stuck.
 */
static int fki_live_show(struct seq_file *m, void *v)
{
	seq_printf(m,
	    "phase=%lu phase_arg=0x%lx hook_stage=%lu "
	    "upcalls=%lu last=0x%lx tag=0x%lx ring=%u/%u\n",
	    READ_ONCE(fki_x86_phase), READ_ONCE(fki_x86_phase_arg),
	    READ_ONCE(fki_x86_hook_stage), READ_ONCE(xnu_upcall_count),
	    READ_ONCE(xnu_upcall_last), READ_ONCE(xnu_upcall_tag),
	    fki_trace_seq_snap(), fki_trace_drained_snap());
	return 0;
}

static int fki_live_open(struct inode *inode, struct file *file)
{
	return single_open(file, fki_live_show, NULL);
}

static const struct proc_ops fki_live_ops = {
	.proc_open	= fki_live_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init fki_x86_init(void)
{
	int cpu, logger_cpu;

	for_each_possible_cpu(cpu) {
		init_completion(&x86_wake[cpu]);
		INIT_CSD(&per_cpu(x86_csd, cpu), x86_kick_fn,
		    (void *)(unsigned long)cpu);
	}
	fki_hostcall_init();
	fki_debug_init();
	/* The file is append-only, so tag each run with the build that wrote it. */
	{
		const char *mark =
		    "fki-x86: BUILD v2 tag/ring phase trace\n";

		fki_debug_log(mark, strlen(mark));
		/* Make the freshly created file survive an emergency reboot. */
		fki_debug_sync();
	}
	proc_create("fki_x86_live", 0444, NULL, &fki_live_ops);
	/*
	 * Keep the phase logger off the CPU that insmod (and therefore the
	 * hosted run) uses; that CPU runs with IRQs off while we are in XNU.
	 */
	logger_cpu = cpumask_any_but(cpu_online_mask, smp_processor_id());
	if (logger_cpu < nr_cpu_ids)
		fki_phase_thread = fki_thread_start(fki_phase_logger, NULL,
		    logger_cpu, "fki-phase");
	fki_x86_phase_set(1, 0);
	pr_info("fki-x86: FKI-X86 v%d ready\n", FKI_X86_VERSION);
	return 0;
}

static void __exit fki_x86_exit(void)
{
	remove_proc_entry("fki_x86_live", NULL);
	fki_x86_phase_set(0, 0);
	if (fki_phase_thread)
		fki_thread_stop(fki_phase_thread);
	fki_phase_thread = NULL;
	fki_debug_exit();
	fki_hostcall_exit();
	pr_info("fki-x86: unloaded\n");
}

module_init(fki_x86_init);
module_exit(fki_x86_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Foreign kernel interface for the x86_64 XNU path");
