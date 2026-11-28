/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Linux-world handler for XNU's upcalls (x86_64 path).
 *
 * world_x86.S switches to Linux's CR3/IDT/stack before calling xnu_hook_x86().
 * A non-zero return ends the hosted run; zero resumes XNU. This file is the
 * x86 counterpart of xnu-ko/xnu_main.c's xnu_hook_body().
 */
#include "fki.h"
#include "fki_internal.h"

#include "../include/linux64_abi_x86_64.h"

#include <linux/kernel.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/hardirq.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");

/*
 * With kprintf_probe enabled every _kprintf in XNU becomes an upcall.  A
 * boot-time kprintf loop can otherwise do thousands of file writes per
 * second and bury insmod under writeback/reclaim pressure.  Cap the log
 * rate while still returning from every upcall normally.
 */
#define KPRINTF_LOG_INTERVAL	(HZ / 20)	/* at most 20 log lines/sec */
#define UPCALL_TRACE_MAX	400

static unsigned long n_fault, n_user_enter, n_panic, n_assert;
static unsigned long last_kprintf_log, n_upcall_trace;
static xnu_hook_translate_fn hook_translate;
extern volatile unsigned long fki_x86_hook_stage;

/* Seen by the phase logger even when KPRINTF lines are rate-limited. */
unsigned long xnu_upcall_count;
unsigned long xnu_upcall_last;
/* Last SITE_TAG id, visible in the phase line even if the ring is stuck. */
unsigned long xnu_upcall_tag;
/* Set by the upcall trampoline: the XNU call site that made this upcall. */
unsigned long xnu_upcall_ret;
EXPORT_SYMBOL(xnu_upcall_ret);

/*
 * The upcall switches to Linux's CR3 before running here. Any argument that
 * points into XNU's address space must be translated to the host alias first.
 */
static unsigned long hx(unsigned long va)
{
	return hook_translate ? (unsigned long)hook_translate(va) : va;
}

int xnu_hook_set_translate(xnu_hook_translate_fn fn)
{
	hook_translate = fn;
	return 0;
}
EXPORT_SYMBOL(xnu_hook_set_translate);

/* SITE_TAG markers go only to the lock-free ring; the logger thread writes
 * them to xnu-boot.log. No printk() here: the observed hang at tag 0x48 was
 * between the upcall line (already in the ring) and this marker, i.e. inside
 * the KERN_DEBUG printk() that used to run first. Console output in the
 * foreign-world upcall path is not safe. */
static void site_trace(const char *what, unsigned long a1)
{
	char b[96];
	int n = snprintf(b, sizeof(b), "%s a1=0x%lx\n", what, a1);

	if (n > 0)
		fki_trace_push(b, min_t(int, n, sizeof(b) - 1));
}

static const char *fault_name(unsigned long v)
{
	switch (v) {
	case 6:  return "#UD";
	case 10: return "#TS";
	case 11: return "#NP";
	case 12: return "#SS";
	case 13: return "#GP";
	case 14: return "#PF";
	default: return "exception";
	}
}

long xnu_hook_x86(unsigned long call, unsigned long a1, unsigned long a2)
{
	char buf[256], sbuf[128];
	int n;
	int log_upcall = 1;
	int site_tag = call == LINUX64_CALL_SITE_TAG;

	xnu_upcall_last = call;
	xnu_upcall_count++;
	if (site_tag)
		xnu_upcall_tag = a1;
	fki_x86_hook_stage = 1;

	/*
	 * Compact file trace of every upcall. The rate limit below only
	 * gates the verbose dmesg line: when XNU wedges right after a kprintf
	 * we still need the exact call site and the format string that was
	 * printed last. Cap the total so a noisy later boot cannot flood the
	 * log.
	 */
	if (n_upcall_trace < UPCALL_TRACE_MAX) {
		n_upcall_trace++;
		if (call == LINUX64_CALL_KPRINTF) {
			const char *p = (const char *)(uintptr_t)hx(a1);

			if (p)
				strscpy(sbuf, p, sizeof(sbuf));
			else
				sbuf[0] = '\0';
			n = snprintf(buf, sizeof(buf),
			    "upcall#%lu call=%lu ret=0x%lx kp=[%s]\n",
			    xnu_upcall_count, call, xnu_upcall_ret, sbuf);
		} else {
			n = snprintf(buf, sizeof(buf),
			    "upcall#%lu call=%lu ret=0x%lx "
			    "a1=0x%lx a2=0x%lx\n",
			    xnu_upcall_count, call, xnu_upcall_ret, a1, a2);
		}
		if (n > 0) {
			/* Nothing in the upcall path may take fki_debug_lock,
			 * call kernel_write() or printk(): the logger can own
			 * the mutex while the foreign world is live here. */
			fki_trace_push(buf, min_t(int, n, sizeof(buf) - 1));
		}
	}
	fki_x86_hook_stage = 2;

	/* Fine-grained breadcrumbs for the SITE_TAG path: a tag can be logged
	 * on entry and still wedge before the exit marker below. */
	if (site_tag) {
		site_trace("hook: upcall logged", a1);
		fki_x86_hook_stage = 3;
	}

	if (call == LINUX64_CALL_KPRINTF) {
		const char *p = (const char *)(uintptr_t)hx(a1);

		/* The vstart breadcrumbs from patch 0012 are only a handful of
		 * KPRINTF upcalls. Never rate-limit them: losing them makes the
		 * early-boot trace useless while a noisy kprintf() loop still
		 * gets capped below. */
		if (p && !strncmp(p, "xnu: ", 5)) {
			log_upcall = 1;
			last_kprintf_log = jiffies;
		} else if (time_before(jiffies,
		    last_kprintf_log + KPRINTF_LOG_INTERVAL)) {
			log_upcall = 0;
		} else {
			last_kprintf_log = jiffies;
		}
	}

	fki_x86_phase_set(40, call);
	/*
	 * SITE_TAG already has two ring markers ("upcall logged" and
	 * "verbose done"/"site tag done"). Keep the noisy pr_info() pair
	 * below for other calls only.
	 */
	if (log_upcall && !site_tag) {
		pr_info("upcall: call=%lu a1=0x%lx a2=0x%lx "
		    "preempt=0x%x nmi=%d irqoff=%d\n",
		    call, a1, a2, preempt_count(), (int)in_nmi(),
		    (int)irqs_disabled());
		/* Linux world with IRQs/preemption on: safe to write to file. */
		n = snprintf(buf, sizeof(buf),
		    "upcall: call=%lu a1=0x%lx a2=0x%lx\n", call, a1, a2);
		if (n > 0)
			fki_trace_push(buf, min_t(int, n, sizeof(buf) - 1));
	}
	if (site_tag) {
		site_trace("hook: verbose done", a1);
		fki_x86_hook_stage = 4;
	}

	switch (call) {
	case LINUX64_CALL_IDLE:
		/* a1 = ns to the next XNU timer, a2 = pending-IPI word */
		fki_x86_idle_until(a1, 1000000000ULL,
		    (const volatile unsigned int *)(uintptr_t)hx(a2));
		return 0;

	case LINUX64_CALL_PREEMPTED:
		fki_x86_yield();
		return 0;

	case LINUX64_CALL_RANDOM:
		if (a1 && a2)
			get_random_bytes((void *)(uintptr_t)hx(a1), (unsigned int)a2);
		return 0;

	case LINUX64_CALL_WALLCLOCK: {
		struct timespec64 ts;

		if (a1) {
			fki_u64 *out = (fki_u64 *)(uintptr_t)hx(a1);

			ktime_get_real_ts64(&ts);
			out[0] = (fki_u64)ts.tv_sec;
			out[1] = (fki_u64)ts.tv_nsec;
		}
		return 0;
	}

	case LINUX64_CALL_CONSOLE_WRITE: {
		const char *s = (const char *)(uintptr_t)hx(a1);
		unsigned long i;

		for (i = 0; s && i < a2; i++) {
			if (s[i] == '\r' || s[i] == '\0')
				continue;
			printk(KERN_INFO "xnu: %c", s[i]);
		}
		return 0;
	}

	case LINUX64_CALL_KPRINTF: {
		char kbuf[256];
		const char *s = (const char *)(uintptr_t)hx(a1);

		if (!s || !log_upcall)
			return 0;
		strscpy(kbuf, s, sizeof(kbuf));
		printk(KERN_INFO "xnu] %s\n", kbuf);
		return 0;
	}

	case LINUX64_CALL_ASSERT: {
		struct linux64_assert_info *ai =
		    (struct linux64_assert_info *)(uintptr_t)hx(a1);
		const char *file = ai && ai->file
		    ? (const char *)(uintptr_t)hx((unsigned long)ai->file) : "?";
		const char *expr = ai && ai->expr
		    ? (const char *)(uintptr_t)hx((unsigned long)ai->expr) : "?";

		n_assert++;
		pr_alert("xnu: assertion failed at %s:%ld: %s\n",
		    file, ai ? ai->line : 0, expr);
		return 1;
	}

	case LINUX64_CALL_PANIC:
		n_panic++;
		pr_alert("xnu: panic: %s\n",
		    a1 ? (const char *)(uintptr_t)hx(a1) : "(no message)");
		return 1;

	case LINUX64_CALL_FAULT: {
		const struct linux64_x86_fault *f =
		    (const struct linux64_x86_fault *)(uintptr_t)hx(a1);

		n_fault++;
		if (!f)
			return 1;
		pr_alert("xnu: unhandled %s: vector %llu error 0x%llx "
		    "cr2 0x%llx rip 0x%llx rsp 0x%llx rflags 0x%llx\n",
		    fault_name(f->vector), (unsigned long long)f->vector,
		    (unsigned long long)f->error_code,
		    (unsigned long long)f->cr2, (unsigned long long)f->rip,
		    (unsigned long long)f->rsp, (unsigned long long)f->rflags);
		/* No host page-fault repair yet: end the run with a clear trace. */
		return 1;
	}

	case LINUX64_CALL_USER_ENTER:
		n_user_enter++;
		if (n_user_enter == 1)
			pr_info("xnu: first user entry at 0x%lx\n", a1);
		return 0;

	case LINUX64_CALL_CPU_START:
	case LINUX64_CALL_CPU_HALT:
	case LINUX64_CALL_IPI:
		/* These are handled by fki_x86_kick_cpu() on the host side. */
		return 0;

	case LINUX64_CALL_SITE_TAG:
		/* Host-only breadcrumb from a patched XNU site. */
		fki_x86_hook_stage = 5;
		site_trace("site tag done", a1);
		fki_x86_hook_stage = 6;
		return 0;

	default:
		pr_warn_once("xnu: unhandled host call %lu\n", call);
		return 0;
	}
}
EXPORT_SYMBOL(xnu_hook_x86);

unsigned long xnu_hook_x86_fault_count(void)
{
	return n_fault;
}
EXPORT_SYMBOL(xnu_hook_x86_fault_count);
