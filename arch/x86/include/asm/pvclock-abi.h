#ifndef _ASM_X86_PVCLOCK_ABI_H
#define _ASM_X86_PVCLOCK_ABI_H
#ifndef __ASSEMBLY__

/*
 * These structs MUST NOT be changed.
 * They are the ABI between hypervisor and guest OS.
 * Both Xen and KVM are using this.
 *
 * pvclock_vcpu_time_info holds the system time and the tsc timestamp
 * of the last update. So the guest can use the tsc delta to get a
 * more precise system time.  There is one per virtual cpu.
 *
 * pvclock_wall_clock references the point in time when the system
 * time was zero (usually boot time), thus the guest calculates the
 * current wall clock by adding the system time.
 *
 * Protocol for the "version" fields is: hypervisor raises it (making
 * it uneven) before it starts updating the fields and raises it again
 * (making it even) when it is done.  Thus the guest can make sure the
 * time values it got are consistent by checking the version before
 * and after reading them.
 */

struct pvclock_vcpu_time_info {
    u32   version;              // 同pvclock_wall_clock，检验数据可用性
    u32   pad0;
    u64   tsc_timestamp;        // 为guest设置的tsc(rdtsc + tsc_offset)。在kvm_guest_time_update中会和system_time一起被更新，表示记录system_time时的时间戳
                                // 但指令间还是有时间差，可以计算delta然后加到system_time
    u64   system_time;          // 最近一次从host读到的时间，作为guest的墙上时间。host通过ktime_get_ts从当前注册的时间源获取该时间
                                // system_time = kernel_ns + v->kvm->arch.kvmclock_offset
                                // 系统启动后的时间减去VM init的时间，即VM init后到现在的时间
    u32   tsc_to_system_mul;    // 时钟频率，1nanosecond对应的cycle数(固定在1GHZ)
    s8    tsc_shift;            // guests must shift
    u8    flags;
    u8    pad[2];
} __attribute__((__packed__)); /* 32 bytes */

struct pvclock_wall_clock {
    u32   version;               // 检验数据可用性
    u32   sec;
    u32   nsec;
} __attribute__((__packed__));

#define PVCLOCK_TSC_STABLE_BIT	(1 << 0)
#define PVCLOCK_GUEST_STOPPED	(1 << 1)
/* PVCLOCK_COUNTS_FROM_ZERO broke ABI and can't be used anymore. */
#define PVCLOCK_COUNTS_FROM_ZERO (1 << 2)
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_PVCLOCK_ABI_H */
