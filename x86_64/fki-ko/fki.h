/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * Foreign kernel interface, x86_64 edition (FKI-X86), version 1.
 *
 * Derived from fki-ko/fki.h (FKI v0) but kept separate so the ARM64 host layer
 * and the x86_64 host layer can evolve independently. It is semantic and
 * shaped like a hypervisor interface: plain integer types and opaque handles,
 * no Linux structure crosses it. A foreign module includes this header only.
 *
 * ARM64-only services (PAC keys, TTBR/TCR windows, PSTATE/ESR fault contexts)
 * are intentionally absent. x86_64 adds CR3/IDT/GDT/TR/MSR and #PF/#GP state.
 */
#ifndef _LINUX_FKI_X86_H
#define _LINUX_FKI_X86_H

#define FKI_X86_VERSION 2

#ifndef __KERNEL__
#include <stdint.h>
typedef uint64_t fki_u64;
#else
#include <linux/types.h>
typedef u64 fki_u64;
#endif

/* Physically contiguous memory; va is the host linear-map alias, pa its contiguous physical base. */
struct fki_region {
	void *va;
	fki_u64 pa;
	fki_u64 size;
	void *handle;
};

#ifdef __cplusplus
extern "C" {
#endif
int fki_version(void);
void fki_log(const char *s, unsigned long len);
void fki_log_alert(const char *s, unsigned long len);	/* KERN_ALERT: on the console even when it is quiet */
/* Synchronous page-cache trace: visible immediately, no fsync stall. */
int fki_debug_log(const char *s, unsigned long len);
/*
 * Lock-free phase breadcrumbs for atomic context. A helper thread pinned away
 * from the XNU CPU flushes them to the file trace, so the last phase is
 * visible even when the world switch wedges with interrupts off.
 * world_x86.S/fki_x86_state.S store the phase with a plain RIP-relative MOV.
 */
extern volatile unsigned long fki_x86_phase;
extern volatile unsigned long fki_x86_phase_arg;
/* site3 snapshot of _linux64_hook before the CR3 switch (diagnostic). */
extern volatile unsigned long xnu_site3_hook_pre;
void fki_x86_phase_set(unsigned long phase, unsigned long arg);
/* Fill a zeroed XSAVE buffer with a sane FPU/SIMD state for a foreign world. */
void fki_x86_fpstate_save(void *buf);
int fki_region_alloc(unsigned long size, struct fki_region *r);
void fki_region_free(struct fki_region *r);
/* A named blob from the firmware search path. */
int fki_blob_get(const char *name, const void **data, unsigned long *size, void **handle);
void fki_blob_put(void *handle);
fki_u64 fki_counter_frequency(void);
fki_u64 fki_counter(void);
void fki_random(void *buf, unsigned long len);
/*
 * Physically contiguous memory with real physical addresses (for a foreign kernel whose own page tables
 * the hardware walks). va is a kernel linear-map address (RW, not executable); size rounds up to a page.
 */
int fki_contig_alloc(unsigned long size, struct fki_region *r);
void fki_contig_free(struct fki_region *r);
/*
 * Called from inside fki_x86_enter() (preemption and IRQs off): let Linux run (IRQs and preemption on)
 * until the counter reaches deadline or max_ns pass, or fki_kick_cpu() is called for this CPU, then return with them off
 * again. Not at all if *wake (when given) is already nonzero: the kicker sets it before kicking.
 */
void fki_idle_until(fki_u64 counter_deadline, fki_u64 max_ns, const volatile unsigned int *wake);
/*
 * Called from inside fki_x86_enter() while the hosted kernel is busy: let Linux take its pending interrupts and
 * reschedule if it must (RCU, other tasks on this CPU), then return with IRQs and preemption off again.
 */
void fki_yield(void);
/* The host's wall clock (UTC): seconds and nanoseconds since 1970. */
void fki_realtime(fki_u64 *sec, fki_u64 *nsec);
/*
 * A virtual Ethernet link to Linux (the netdev "xnu0"): send one frame (header included, no FCS); receive the next
 * frame Linux sent (its length, 0 when none waits); how many frames wait.
 */
long fki_net_send(const void *frame, unsigned long len);
long fki_net_recv(void *buf, unsigned long len);
long fki_net_pending(void);
/* Keep the calling task on one CPU. */
int fki_bind_cpu(int cpu);
/* CPUs: how many are online (from ordinary Linux context). */
int fki_num_cpus(void);
/* Make the foreign kernel on a CPU look at its pending work: wake its idle call, or interrupt it (interrupts may be off) */
void fki_kick_cpu(int cpu);
/*
 * A helper kernel thread bound to one CPU: fn(arg) runs until it returns or fki_thread_stop() is called;
 * fn should loop on !fki_thread_should_stop() and sleep with fki_msleep().
 */
void *fki_thread_start(int (*fn)(void *), void *arg, int cpu, const char *name);
void fki_thread_stop(void *thread);
int fki_thread_should_stop(void);
/* In a helper thread: sleep until *flag is non-zero or the thread is told to stop; fki_thread_wake() wakes it (callable
 * with interrupts off, after setting the flag) */
void fki_thread_wait(const volatile unsigned long *flag);
void fki_thread_wake(void *thread);
void fki_msleep(unsigned int ms);
/* Read 8 bytes of RAM by physical address (debugging: walking a foreign page table). */
fki_u64 fki_phys_peek(fki_u64 pa);
/*
 * A host file as backing store (a foreign block device's image). fki_file_open is called from ordinary Linux context
 * and returns an opaque handle (NULL on failure) and the file's size. fki_file_rw is called from inside fki_x86_enter():
 * it lets Linux run (IRQs and preemption on) for the I/O, copies through a Linux bounce buffer to or from buf
 * (with IRQs off again), and returns the bytes moved or a negative errno.
 */
void *fki_file_open(const char *path, int writable, fki_u64 *size);
long fki_file_rw(void *file, int write, void *buf, unsigned long len, fki_u64 off);
void fki_file_close(void *file);
/* Write to a host file from ordinary Linux context (a host thread, not inside fki_x86_enter()); bytes written or -errno. */
long fki_file_pwrite(void *file, const void *buf, unsigned long len, fki_u64 off);
/* Lockless trace push from the upcall hook: memcpy into a ring slot, no
 * mutex, no file I/O, safe with IRQs/preemption off. The phase logger kthread
 * drains the ring to the boot log. */
void fki_trace_push(const char *s, unsigned long len);
/*
 * A host call (from inside fki_x86_enter()): len bytes at req to the Linux service reading /dev/xnu-hostcall, its reply into
 * reply (at most max bytes). Returns the reply's length or a negative errno (-ETIMEDOUT: no service answered).
 */
long fki_hostcall(const void *req, unsigned long len, void *reply, unsigned long max);

/* ---- FKI-X86 v1 additions ------------------------------------------------ */

/* x86_64 system state that belongs to one world (Linux or hosted XNU). */
struct fki_x86_state {
	fki_u64 cr3;
	fki_u64 idt_base;
	fki_u64 gdt_base;
	fki_u64 idt_limit;
	fki_u64 gdt_limit;
	fki_u64 tr;
	fki_u64 gs_base;            /* MSR_IA32_GS_BASE */
	fki_u64 kernel_gs_base;     /* MSR_IA32_KERNEL_GS_BASE */
	fki_u64 star;
	fki_u64 lstar;
	fki_u64 cstar;
	fki_u64 sfmask;
	fki_u64 xsave_va;           /* caller-owned buffer */
	fki_u64 xsave_size;
};

/* Enter/leave a foreign context on this CPU: no preemption, no IRQs.
 * The FP/SIMD/XSAVE state of the current task is saved first. */
unsigned long fki_x86_enter(const struct fki_x86_state *foreign, struct fki_x86_state *saved);
void fki_x86_leave(unsigned long cookie, struct fki_x86_state *saved, struct fki_x86_state *foreign);
/* Swap only the GS-base pair and syscall MSRs (caller is already in the foreign world). */
void fki_x86_swap_user_state(const struct fki_x86_state *load, struct fki_x86_state *save);

/* Give Linux a slice of this CPU. Called from the Linux world, after fki_x86_leave():
 * preemption and IRQs are already on, and the next fki_x86_enter() disables them again.
 * Do not toggle preempt_count here: doing so underflows it and corrupts the host scheduler. */
void fki_x86_idle_until(fki_u64 counter_deadline, fki_u64 max_ns, const volatile unsigned int *wake);
void fki_x86_yield(void);

/* CPUs are identified by their APIC ID, not by MPIDR. */
int fki_x86_num_cpus(void);
int fki_x86_cpu_apic_id(int cpu, fki_u64 *apic_id);
/* Wake a CPU whose hosted kernel is idle or spinning with interrupts off. */
void fki_x86_kick_cpu(int cpu);

/* Optional Linux-side fault hook. The active path is the XNU trap patch in
 * patches/0006: XNU owns its IDT while running, so faults reach kernel_trap()
 * and are upcalled to xnu_hook_x86() with a struct linux64_x86_fault. These
 * helpers remain available for faults taken on Linux's own IDT. */
struct fki_x86_regs {
	fki_u64 rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15;
	fki_u64 rip, rflags, cr2, error_code;
	fki_u64 vector;
};
unsigned long fki_x86_regs_pc(const struct fki_x86_regs *regs);
void fki_x86_regs_set_pc(struct fki_x86_regs *regs, unsigned long pc);
void fki_x86_regs_set_reg(struct fki_x86_regs *regs, unsigned int n, unsigned long v);
int fki_x86_fault_register(unsigned long lo, unsigned long hi,
    int (*handler)(struct fki_x86_regs *regs, void *arg), void *arg);
void fki_x86_fault_unregister(void);

/* Allocate physically contiguous, executable memory that is mapped in both the
 * Linux and the hosted-XNU page tables (the shared world page, boot args, KC). */
int fki_x86_shared_alloc(unsigned long size, struct fki_region *r);
void fki_x86_shared_free(struct fki_region *r);

#ifdef __cplusplus
}
#endif
#endif
