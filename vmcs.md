# vmcs 解析
## 一，vmcs结构介绍以及存取
---
* ** vmcs **

```
//vmcs结构体定义
 struct vmcs {
  u32 revision_id;
  u32 abort;
  char data[0];
};
```
```
//为嵌套虚拟化vmcs
 struct __packed vmcs12 {
	/* According to the Intel spec, a VMCS region must start with the
	 * following two fields. Then follow implementation-specific data.
	 */
	u32 revision_id;
	u32 abort;
	u32 launch_state; /* set to 0 by VMCLEAR, to 1 by VMLAUNCH */
	u32 padding[7]; /* room for future expansion */
	...
	}
```
* vmcs的存取
vmcs_writel function()

```
static __always_inline void __vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;
	//#define ASM_VMX_VMWRITE_RAX_RDX   ".byte 0x0f, 0x79, 0xd0"
	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}
```
_vmcs_readl function()

```
  static __always_inline unsigned long __vmcs_readl(unsigned long field)
{
	unsigned long value;
	// #define ASM_VMX_VMREAD_RDX_RAX    ".byte 0x0f, 0x78, 0xd0"
	asm volatile (__ex_clear(ASM_VMX_VMREAD_RDX_RAX, "%0")
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}
```

struct kvm  defined in kvm_host.h

```
struct kvm {
	spinlock_t mmu_lock;//多cpu，多线程并行要保证mmu调度正确性
	struct mutex slots_lock;//内存的锁
	struct mm_struct *mm; /* userspace tied to this vm 指向qemu 用户态进程？？*/
	/*kvm_mem_slots是kvm内存管理相关的主要数据结构，用来表示虚拟机
	GPA和HPA的映射关系。一个kvm_mem_slot表示一段内存区域(slot)的映射关系，struct kvm_memslots 包含了一个 kvm_mem_slot的数组，对应虚拟机使用的所有的内存区域*/
	struct kvm_memslots *memslots[KVM_ADDRESS_SPACE_NUM];
	struct srcu_struct srcu;//没有搞懂这是什么？
	struct srcu_struct irq_srcu;
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];//define the maximum number of vcpus a vm can have
	/*
	 * created_vcpus is protected by kvm->lock, and is incremented
	 * at the beginning of KVM_CREATE_VCPU.  online_vcpus is only
	 * incremented after storing the kvm_vcpu pointer in vcpus,
	 * and is accessed atomically.
	 */
	atomic_t online_vcpus;//online cpu 的数量
	int created_vcpus;//在调用KVM_CREATE_VCPU增加
	int last_boosted_vcpu;
	struct list_head vm_list;
	struct mutex lock;
	/*
	虚拟机中包括的IO总线结构体数组，一条总线对应一个kvm_io_bus结构体，如ISA总线、PCI总线*/
	struct kvm_io_bus *buses[KVM_NR_BUSES];//
	//事件通道相关
    #ifdef CONFIG_HAVE_KVM_EVENTFD
	struct {
		spinlock_t        lock;
		struct list_head  items;
		struct list_head  resampler_list;
		struct mutex      resampler_lock;
	} irqfds;
	struct list_head ioeventfds;
    #endif
	struct kvm_vm_stat stat;//虚拟机运行时的状态信息，比如页表，mmu
	struct kvm_arch arch;//结构相关的比如 x86
	atomic_t users_count;//引用计数
    #ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;//
	spinlock_t ring_lock;
	struct list_head coalesced_zones;
    #endif
	struct mutex irq_lock;
    #ifdef CONFIG_HAVE_KVM_IRQCHIP
	/*
	 * Update side is protected by irq_lock.
	 */
	struct kvm_irq_routing_table __rcu *irq_routing;
    #endif
    #ifdef CONFIG_HAVE_KVM_IRQFD
	struct hlist_head irq_ack_notifier_list;
    #endif
    #if defined(CONFIG_MMU_NOTIFIER) &&     defined(KVM_ARCH_WANT_MMU_NOTIFIER)
    //mmu通知连
	struct mmu_notifier mmu_notifier;
	unsigned long mmu_notifier_seq;
	long mmu_notifier_count;
    #endif
	long tlbs_dirty;//dirty的tlb的数量
	struct list_head devices;
	struct dentry *debugfs_dentry;
	struct kvm_stat_data **debugfs_stat_data;};
```
## 二，创建vcpu的流程
** 1. 基本流程 **
kvm_vm_ioctl() //kvm ioctl vm指令的入口->
kvm_vm_ioctl_create_vcpu()//为虚拟机创建vcpu的ioctl调用入口->
kvm_arch_vcpu_create()//创建vcpu结构，与架构相关对于x86最后调用vmx_create_cpu
kvm_arch_vcpu_setup()//设置vcpu的结构
create_vcpu_fd()//为新创建出的vcpu创建对应的fd

** 2.代码注释 **

1. struct kvm_vcpu

```
struct kvm_vcpu {
	struct kvm *kvm;//pointer指向虚拟机对应的kvm结构
    #ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
    #endif
	int cpu;
	int vcpu_id;//唯一标示一个vcpu
	int srcu_idx;// ??
	int mode;
	unsigned long requests;
	unsigned long guest_debug;
	int pre_pcpu;
	struct list_head blocked_vcpu_list;
	struct mutex mutex;
	struct kvm_run *run;//执行虚拟机对应的kvm_run结构
	int fpu_active;
	int guest_fpu_loaded, guest_xcr0_loaded;
	unsigned char fpu_counter;
	struct swait_queue_head wq;
	struct pid *pid;
	int sigset_active;
	sigset_t sigset;//信号
	struct kvm_vcpu_stat stat;//vcpu状态信息
	unsigned int halt_poll_ns;
	bool valid_wakeup;
	//mmio相关部分
	#ifdef CONFIG_HAS_IOMEM
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_cur_fragment;
	int mmio_nr_fragments;
	struct kvm_mmio_fragment mmio_fragments[KVM_MAX_MMIO_FRAGMENTS];
    #endif
    #ifdef CONFIG_KVM_ASYNC_PF
	struct {
		u32 queued;
		struct list_head queue;
		struct list_head done;
		spinlock_t lock;
	} async_pf;
    #endif
    #ifdef CONFIG_HAVE_KVM_CPU_RELAX_INTERCEPT
	/*
	 * Cpu relax intercept or pause loop exit optimization
	 * in_spin_loop: set when a vcpu does a pause loop exit
	 *  or cpu relax intercepted.
	 * dy_eligible: indicates whether vcpu is eligible for directed yield.
	 */
	struct {
		bool in_spin_loop;
		bool dy_eligible;
	} spin_loop;
#endif
	bool preempted;
	struct kvm_vcpu_arch arch;//架构相关部分，包括寄存器，apic，mmu相关的架构
};
```

2.  创建vcpu kvm_vm_ioctl()-->kvm_vm_ioctl_create_vcpu():

kvm_vm_ioctl()

```
/* * 为虚拟机创建VCPU的ioctl调用的入口函数，本质为创建vcpu结构并初始化，并将其填入kvm结构中。*/
static long kvm_vm_ioctl(struct file *filp,  unsigned int ioctl, unsigned long arg)
{  struct kvm *kvm = filp->private_data;
	void __user *argp = (void __user *)arg;
	int r;
	if (kvm->mm != current->mm)
		return -EIO;
	switch (ioctl) {
	case KVM_CREATE_VCPU:
		r = kvm_vm_ioctl_create_vcpu(kvm, arg);
		break;
	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region kvm_userspace_mem;
		r = -EFAULT;
		if (copy_from_user(&kvm_userspace_mem, argp,
						sizeof(kvm_userspace_mem)))
			goto out;
		r = kvm_vm_ioctl_set_memory_region(kvm, &kvm_userspace_mem);
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;
		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof(log)))
			goto out;
		r = kvm_vm_ioctl_get_dirty_log(kvm, &log);
		break;
	}
     #ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = kvm_vm_ioctl_register_coalesced_mmio(kvm, &zone);
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = -EFAULT;
		if (copy_from_user(&zone, argp, sizeof(zone)))
			goto out;
		r = kvm_vm_ioctl_unregister_coalesced_mmio(kvm, &zone);
		break;
	}
    #endif
	case KVM_IRQFD: {
		struct kvm_irqfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = kvm_irqfd(kvm, &data);
		break;
	}
	case KVM_IOEVENTFD: {
		struct kvm_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof(data)))
			goto out;
		r = kvm_ioeventfd(kvm, &data);
		break;
	}
  #ifdef CONFIG_HAVE_KVM_MSI
	case KVM_SIGNAL_MSI: {
		struct kvm_msi msi;
		r = -EFAULT;
		if (copy_from_user(&msi, argp, sizeof(msi)))
			goto out;
		r = kvm_send_userspace_msi(kvm, &msi);
		break;
	}
  #endif
  #ifdef __KVM_HAVE_IRQ_LINE
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level irq_event;
		r = -EFAULT;
		if (copy_from_user(&irq_event, argp, sizeof(irq_event)))
			goto out;

		r = kvm_vm_ioctl_irq_line(kvm, &irq_event,
					ioctl == KVM_IRQ_LINE_STATUS);
		if (r)
			goto out;

		r = -EFAULT;
		if (ioctl == KVM_IRQ_LINE_STATUS) {
			if (copy_to_user(argp, &irq_event, sizeof(irq_event)))
				goto out;
		}

		r = 0;
		break;
	}
   #endif
   #ifdef CONFIG_HAVE_KVM_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing routing;
		struct kvm_irq_routing __user *urouting;
		struct kvm_irq_routing_entry *entries = NULL;
		r = -EFAULT;
		if (copy_from_user(&routing, argp, sizeof(routing)))
			goto out;
		r = -EINVAL;
		if (routing.nr > KVM_MAX_IRQ_ROUTES)
			goto out;
		if (routing.flags)
			goto out;
		if (routing.nr) {
			r = -ENOMEM;
			entries = vmalloc(routing.nr * sizeof(*entries));
			if (!entries)
				goto out;
			r = -EFAULT;
			urouting = argp;
			if (copy_from_user(entries, urouting->entries,
					   routing.nr * sizeof(*entries)))
				goto out_free_irq_routing;
		}
		r = kvm_set_irq_routing(kvm, entries, routing.nr,
					routing.flags);
     out_free_irq_routing:
		vfree(entries);
		break;
	}  
	#endif /* CONFIG_HAVE_KVM_IRQ_ROUTING */
	 case KVM_CREATE_DEVICE: {
		struct kvm_create_device cd;

		r = -EFAULT;
		if (copy_from_user(&cd, argp, sizeof(cd)))
			goto out;

		r = kvm_ioctl_create_device(kvm, &cd);
		if (r)
			goto out;

		r = -EFAULT;
		if (copy_to_user(argp, &cd, sizeof(cd)))
			goto out;

		r = 0;
		break;
	}
	case KVM_CHECK_EXTENSION:
		r = kvm_vm_ioctl_check_extension_generic(kvm, arg);
		break;
	default:
		r = kvm_arch_vm_ioctl(filp, ioctl, arg);
	}
out:
	return r;
}
 #ifdef CONFIG_KVM_COMPAT
struct compat_kvm_dirty_log {
	__u32 slot;
	__u32 padding1;
	union {
		compat_uptr_t dirty_bitmap; /* one bit per page */
		__u64 padding2;
	};
};
```

kvm_vm_ioctl_create_vcpu()

```
/*创建一些vcpu，为虚拟机创建vcpu的ioctl调用的入口函数，创建vcpu结构并且初始化，并且将其填入kvm的结构.*/
static int kvm_vm_ioctl_create_vcpu(struct kvm *kvm, u32 id)
{
	int r;
	struct kvm_vcpu *vcpu;//定义一个vcpu pointer
	if (id >= KVM_MAX_VCPU_ID)
		return -EINVAL;//id已经超过了定义的最大的vcpu，id的话，返回失败
	mutex_lock(&kvm->lock);
	if (kvm->created_vcpus == KVM_MAX_VCPUS) {
		mutex_unlock(&kvm->lock);//如果创建的vcpu数量已经超过了KVM_MAX_VCPUS定义的最大的数量
		return -EINVAL;//创建失败
	}
	kvm->created_vcpus++;//kvm结构体中追踪创建的vcpu数量的create_vcpus加一
	mutex_unlock(&kvm->lock);
	vcpu = kvm_arch_vcpu_create(kvm, id);//创建vcpu结构，对于intel x86最终调用vmx_create_vcpu
	if (IS_ERR(vcpu)) {
		r = PTR_ERR(vcpu);
		goto vcpu_decrement;//vcpu创建失败
	}
	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);
	  /* 
     * 设置vcpu结构，主要调用kvm_x86_ops->vcpu_load，KVM虚拟机VCPU数据结构载入物理CPU，
     * 并进行虚拟机mmu相关设置，比如进行ept页表的相关初始工作或影子页表
     * 相关的设置。
     */
	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		goto vcpu_destroy;

	mutex_lock(&kvm->lock);
	//监测分配的vcpu id是否已经存在
	if (kvm_get_vcpu_by_id(kvm, id)) {
		r = -EEXIST;
		goto unlock_vcpu_destroy;
	}
	   /*
     * kvm->vcpus[]数组包括该vm的所有vcpu，定义为KVM_MAX_VCPUS大小的数组。
     * 在kvm结构初始化时，其中所有成员都初始化为0，在vcpu还没有
     * 分配之前，如果不为0，那就是bug了。
     */
	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);
	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);
	r = create_vcpu_fd(vcpu); // 为新创建的vcpu创建对应的fd，以便于后续通过该fd进行ioctl操作
	if (r < 0) {
		kvm_put_kvm(kvm);//fd创建不成功，free 一个vm
		goto unlock_vcpu_destroy;
	}
	// 将新创建的vcpu填入kvm->vcpus[]数组中
	kvm->vcpus[atomic_read(&kvm->online_vcpus)] = vcpu;
	/*
	 * Pairs with smp_rmb() in kvm_get_vcpu.  Write kvm->vcpus
	 * before kvm->online_vcpu's incremented value.
	 */
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);//原子性增加online_vcpus的数量
	mutex_unlock(&kvm->lock);
	kvm_arch_vcpu_postcreate(vcpu); // 架构相关的善后工作，比如再次调用vcpu_load，以及tsc相关处理
	return r;
    unlock_vcpu_destroy:
	mutex_unlock(&kvm->lock);
    vcpu_destroy:
	kvm_arch_vcpu_destroy(vcpu);
    vcpu_decrement:
	mutex_lock(&kvm->lock);
	kvm->created_vcpus--;//减少created_vcpus的数量
	mutex_unlock(&kvm->lock);
	return r;
}
```

** kvm_vm_ioctl()-->kvm_vm_ioctl_create_vcpu()-->kvm_arch_vcpu_create()-->kvm_x86_ops->vcpu_create()-->vmx_create_vcpu(): **

```
//Intel x86架构中创建并初始化vcpu中架构相关部分
static struct kvm_vcpu *vmx_create_vcpu(struct kvm *kvm, unsigned int id)
{
	int err;
	//分配vcpu_vmx结构体，其中包括VMX技术硬件信息
	struct vcpu_vmx *vmx = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	int cpu;
	if (!vmx)
		return ERR_PTR(-ENOMEM);

	vmx->vpid = allocate_vpid();//分配vpid，vpid是vcpu的唯一标示
   // 初始化vmx中的vcpu的结构
	err = kvm_vcpu_init(&vmx->vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	err = -ENOMEM;

	/*
	 * If PML is turned on, failure on enabling PML just results in failure
	 * of creating the vcpu, therefore we can simplify PML logic (by
	 * avoiding dealing with cases, such as enabling PML partially on vcpus
	 * for the guest, etc.
	 */
	if (enable_pml) {
		vmx->pml_pg = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!vmx->pml_pg)
			goto uninit_vcpu;
	}
  //分配guest的msr寄存器保护区
	vmx->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	BUILD_BUG_ON(ARRAY_SIZE(vmx_msr_index) * sizeof(vmx->guest_msrs[0])
		     > PAGE_SIZE);

	if (!vmx->guest_msrs)
		goto free_pml;

	vmx->loaded_vmcs = &vmx->vmcs01;
	vmx->loaded_vmcs->vmcs = alloc_vmcs();//为vcpu，分配vmcs
	if (!vmx->loaded_vmcs->vmcs)
		goto free_msrs;
		//是否设置了vmm_exclusive
	if (!vmm_exclusive)
	//VMXON指令用于开启VMX模式
		kvm_cpu_vmxon(__pa(per_cpu(vmxarea, raw_smp_processor_id())));
	loaded_vmcs_init(vmx->loaded_vmcs)；//初始化vmcs
	if (!vmm_exclusive)
		kvm_cpu_vmxoff();
   //当前cpu
	cpu = get_cpu();
	vmx_vcpu_load(&vmx->vcpu, cpu);//KVM虚拟机VCPU数据结构载入物理cpu
	vmx->vcpu.cpu = cpu;
	//设置vmx相关信息
	err = vmx_vcpu_setup(vmx);
	vmx_vcpu_put(&vmx->vcpu);
	put_cpu();
	if (err)
		goto free_vmcs;
	if (cpu_need_virtualize_apic_accesses(&vmx->vcpu)) {
		err = alloc_apic_access_page(kvm);
		if (err)
			goto free_vmcs;
	}
   //是否支持ept
	if (enable_ept) {
		if (!kvm->arch.ept_identity_map_addr)
			kvm->arch.ept_identity_map_addr =
				VMX_EPT_IDENTITY_PAGETABLE_ADDR;
		err = init_rmode_identity_map(kvm);
		if (err)
			goto free_vmcs;
	}

	if (nested) {
		nested_vmx_setup_ctls_msrs(vmx);
		vmx->nested.vpid02 = allocate_vpid();
	}

	vmx->nested.posted_intr_nv = -1;
	vmx->nested.current_vmptr = -1ull;
	vmx->nested.current_vmcs12 = NULL;

	vmx->msr_ia32_feature_control_valid_bits = FEATURE_CONTROL_LOCKED;

	return &vmx->vcpu;

free_vmcs:
	free_vpid(vmx->nested.vpid02);
	free_loaded_vmcs(vmx->loaded_vmcs);
free_msrs:
	kfree(vmx->guest_msrs);
free_pml:
	vmx_destroy_pml_buffer(vmx);
uninit_vcpu:
	kvm_vcpu_uninit(&vmx->vcpu);
free_vcpu:
	free_vpid(vmx->vpid);
	kmem_cache_free(kvm_vcpu_cache, vmx);
	return ERR_PTR(err);
}

static void __init vmx_check_processor_compat(void *rtn)
{
	struct vmcs_config vmcs_conf;

	*(int *)rtn = 0;
	if (setup_vmcs_config(&vmcs_conf) < 0)
		*(int *)rtn = -EIO;
	if (memcmp(&vmcs_config, &vmcs_conf, sizeof(struct vmcs_config)) != 0) {
		printk(KERN_ERR "kvm: CPU %d feature inconsistency!\n",
				smp_processor_id());
		*(int *)rtn = -EIO;
	}
}

static int get_ept_level(void)
{
	return VMX_EPT_DEFAULT_GAW + 1;
}
```
** kvm_vm_ioctl()-->kvm_vm_ioctl_create_vcpu()-->kvm_arch_vcpu_setup(): **

kvm_arch_vcpu_setup()


