#include "Driver.h"
#include "poolmanager.h"
#include "Globals.h"
#include "cpuid.h"
#include "ntapi.h"
#include "mtrr.h"
#include "EPT.h"
#include "AllocateMem.h"
#include "msr.h"
#include "vmcs.h"
#include "crx.h"
#include "hypervisor_routines.h"
#include "vmm.h"

EXTERN_C void vmx_save_state();



typedef enum _SYSTEM_INFORMATION_CLASS 
{
	SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_to_opt_(SystemInformationLength, *ReturnLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG Reserved1;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE ParentProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



void free_vmm_context()
{
	//if (g_vmm_context != nullptr)
	{
		// POOL MANAGER
		if (g_vmm_context.pool_manager != nullptr)
		{
			pool_manager::uninitialize();
			free_pool(g_vmm_context.pool_manager);
		}

		// VCPU TABLE
		if (g_vmm_context.vcpu != nullptr)
		{
			for (unsigned int i = 0; i < g_vmm_context.processor_count; i++)
			{
				// VCPU
				//if (g_vmm_context.vcpu[i] != nullptr)
				{
					// VCPU VMM STACK
					//if (g_vmm_context.vcpu_table[i]->vmm_stack != nullptr)
					//{
					//	free_pool(g_vmm_context.vcpu_table[i]->vmm_stack);
					//}

					// IO BITMAP A
					if (g_vmm_context.vcpu[i].vcpu_bitmaps.io_bitmap_a != nullptr)
					{
						free_pool(g_vmm_context.vcpu[i].vcpu_bitmaps.io_bitmap_a);
					}

					// IO BITMAP B
					if (g_vmm_context.vcpu[i].vcpu_bitmaps.io_bitmap_b != nullptr)
					{
						free_pool(g_vmm_context.vcpu[i].vcpu_bitmaps.io_bitmap_b);
					}

					// EPT_STATE
					if (g_vmm_context.vcpu[i].ept_state != nullptr)
					{
						// EPT POINTER
						if (g_vmm_context.vcpu[i].ept_state->ept_pointer != nullptr)
						{
							free_pool(g_vmm_context.vcpu[i].ept_state->ept_pointer);
						}
						// EPT PAGE TABLE
						if (g_vmm_context.vcpu[i].ept_state->ept_page_table != nullptr)
						{
							free_pool(g_vmm_context.vcpu[i].ept_state->ept_page_table);
						}

						free_pool(g_vmm_context.vcpu[i].ept_state);
					}

					//free_pool(g_vmm_context.vcpu_table[i]);
				}
			}
			free_pool(g_vmm_context.vcpu);
		}

		//free_pool(g_vmm_context);
	}

	//g_vmm_context = nullptr;
}

//分配g_vmm_context上下文
bool allocate_vmm_context()
{
	__cpuid_info cpuid_reg = { 0 };

	//
	// Allocate virtual cpu context for every logical core
	// 为每个逻辑处理器分配虚拟 CPU 上下文
	//
	//g_vmm_context.processor_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	g_vmm_context.processor_count = KeQueryActiveProcessorCount(NULL);
	auto const arr_size = sizeof(__vcpu) * g_vmm_context.processor_count;
	g_vmm_context.vcpu = allocate_pool<__vcpu*>(arr_size);
	if (g_vmm_context.vcpu == nullptr)
	{
		DbgPrint("[memproc_core] vCPU结构体分配失败.\n");
		return false;
	}
	RtlSecureZeroMemory(g_vmm_context.vcpu, arr_size);

	//
	// Build mtrr map for physcial memory caching informations
	// 构建 mtrr 映射来存储物理内存缓存信息
	//
	ept::build_mtrr_map();

	//提前在guest里分配了内存
	if (pool_manager::initialize() == false)
	{
		DbgPrint("[memproc_core] 预分配内存失败.\n");
		return false;
	}

	for (unsigned int iter = 0; iter < g_vmm_context.processor_count; iter++)
	{
		if (init_vcpu(&g_vmm_context.vcpu[iter]) == false)
		{
			DbgPrint("[memproc_core] 初始化vCPU失败.\n");
			return false;
		}
	}

	g_vmm_context.hv_presence = true;

	__cpuid((int*)&cpuid_reg.eax, 0);
	g_vmm_context.highest_basic_leaf = cpuid_reg.eax;

	//创建host页表
	//将所有物理内存映射到我们的地址空间
	create_host_page_tables();

	return true;
}

//分配vcpu结构内存
bool init_vcpu(__vcpu* vcpu)
{

	//vcpu->vmm_stack = allocate_pool<void*>(VMM_STACK_SIZE);
	//if (vcpu->vmm_stack == nullptr)
	//{
	//	LogError("vmm stack could not be allocated");
	//	return false;
	//}
	//RtlSecureZeroMemory(vcpu->vmm_stack, VMM_STACK_SIZE);

	vcpu->vcpu_bitmaps.io_bitmap_a = allocate_pool<unsigned __int8*>(PAGE_SIZE);
	if (vcpu->vcpu_bitmaps.io_bitmap_a == nullptr)
	{
		DbgPrint("[memproc_core] IO-bitmap 不能映射.");
		return false;
	}
	RtlSecureZeroMemory(vcpu->vcpu_bitmaps.io_bitmap_a, PAGE_SIZE);
	vcpu->vcpu_bitmaps.io_bitmap_a_physical = MmGetPhysicalAddress(vcpu->vcpu_bitmaps.io_bitmap_a).QuadPart;

	vcpu->vcpu_bitmaps.io_bitmap_b = allocate_pool<unsigned __int8*>(PAGE_SIZE);
	if (vcpu->vcpu_bitmaps.io_bitmap_b == nullptr)
	{
		DbgPrint("[memproc_core] IO-bitmap 不能映射.");
		return false;
	}
	RtlSecureZeroMemory(vcpu->vcpu_bitmaps.io_bitmap_b, PAGE_SIZE);
	vcpu->vcpu_bitmaps.io_bitmap_b_physical = MmGetPhysicalAddress(vcpu->vcpu_bitmaps.io_bitmap_b).QuadPart;

	//
	// Allocate ept state structure
	//
	vcpu->ept_state = allocate_pool<__ept_state>();
	if (vcpu->ept_state == nullptr)
	{
		DbgPrint("[memproc_core] Ept State 不能映射.");
		return false;
	}
	RtlSecureZeroMemory(vcpu->ept_state, sizeof(__ept_state));
	InitializeListHead(&vcpu->ept_state->hooked_page_list);

	RtlSecureZeroMemory(&vcpu->host_tss, sizeof(task_state_segment_64));
	RtlSecureZeroMemory(&vcpu->host_gdt, sizeof(segment_descriptor_32) * HOST_GDT_DESCRIPTOR_COUNT);
	RtlSecureZeroMemory(&vcpu->host_idt, sizeof(segment_descriptor_interrupt_gate_64) * HOST_IDT_DESCRIPTOR_COUNT);

	//
	// Initialize ept structure
	// 初始化 ept 结构
	//
	if (ept::initialize(*vcpu->ept_state) == false)
	{
		DbgPrint("[memproc_core] 初始化 Ept 结构失败.");
		return false;
	}

	DbgPrint("[memproc_core] vCPU %llX 初始化成功", vcpu);
	return true;
}

//调节控制寄存器 cr4 cr0来启用vmx模式
void adjust_control_registers()
{
	__cr4 cr4;
	__cr0 cr0;
	__cr_fixed cr_fixed;

	_disable();
	cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED0);
	cr0.all = __readcr0();
	cr0.all |= cr_fixed.split.low;
	cr_fixed.all = __readmsr(IA32_VMX_CR0_FIXED1);
	cr0.all &= cr_fixed.split.low;
	__writecr0(cr0.all);
	cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED0);
	cr4.all = __readcr4();
	cr4.all |= cr_fixed.split.low;
	cr_fixed.all = __readmsr(IA32_VMX_CR4_FIXED1);
	cr4.all &= cr_fixed.split.low;
	__writecr4(cr4.all);
	_enable();

	//设置IA32_FEATURE_CONTROL寄存器的bit0 bit2支持开启vmx模式
	__ia32_feature_control_msr feature_msr = { 0 };
	feature_msr.all = __readmsr(IA32_FEATURE_CONTROL);

	if (feature_msr.lock == 0)
	{
		feature_msr.vmxon_outside_smx = 1;
		feature_msr.lock = 1;

		__writemsr(IA32_FEATURE_CONTROL, feature_msr.all);
	}
}

extern "C" NTKERNELAPI void PsGetCurrentThreadProcess();
extern "C" NTKERNELAPI CHAR* PsGetProcessImageFileName(PEPROCESS Process);
void create_host_page_tables()
{
	NTSTATUS status;
	ULONG returnLength = 0;
	PVOID processInfo = NULL;

	// 第一次调用获取所需内存大小
	status = NtQuerySystemInformation(
		SystemProcessInformation,
		NULL,
		0,
		&returnLength
	);


	if (status != STATUS_INFO_LENGTH_MISMATCH) 
	{
		return;
	}

	// 分配非分页内存
	processInfo = ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		returnLength,
		'TAG1'
	);

	if (!processInfo) 
	{
		return;
	}

	// 第二次调用获取进程信息
	status = NtQuerySystemInformation(
		SystemProcessInformation,
		processInfo,
		returnLength,
		&returnLength
	);

	if (!NT_SUCCESS(status)) 
	{
		ExFreePool(processInfo);
		return;
	}

	// 遍历进程列表
	PSYSTEM_PROCESS_INFORMATION pEntry = (PSYSTEM_PROCESS_INFORMATION)processInfo;
	do 
	{
		if (pEntry->ImageName.Buffer != NULL)
		{
			PEPROCESS ep = NULL;
			NTSTATUS st = PsLookupProcessByProcessId((HANDLE)pEntry->ProcessId, &ep);

			char* pn = PsGetProcessImageFileName(ep);

			if (_stricmp(pn, "dwm.exe") == 0)
			{
				hv::ghv.system_cr3.flags = ((__nt_kprocess*)ep)->DirectoryTableBase;

				KAPC_STATE ApcState;
				KeStackAttachProcess(ep, &ApcState);
				hv::prepare_host_page_tables();
				KeUnstackDetachProcess(&ApcState);
				break;
			}
		}
		// 移动到下一个条目
		if (pEntry->NextEntryOffset == 0) break;
		pEntry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pEntry + pEntry->NextEntryOffset);
	} while (TRUE);

	// 清理资源
	if (processInfo) 
	{
		ExFreePool(processInfo);
	}
	return;
}

bool initalize_vcpu(unsigned int iter)
{
	unsigned __int64 processor_number = iter;
	__vcpu* vcpu = &g_vmm_context.vcpu[processor_number];

	//调节控制寄存器 cr4 cr0来启用vmx模式
	adjust_control_registers();
	//进入vmx模式
	if (!hv::enter_vmx_operation(vcpu->vmxon))  
	{
		DbgPrint("[memproc_core] vCPU %lld 无法设置虚拟化.", processor_number);
		return false;
	}

	if (!hv::load_vmcs_pointer(vcpu->vmcs))
	{
		DbgPrint("[memproc_core] 加载VMCS区域失败.\n");
		return false;
	}

	//创建host的idt和gdt
	hv::prepare_external_structures(vcpu);
	vcpu->vcpu_status.vmx_on = true;
	DbgPrint("[memproc_core] vCPU %lld 已经成功进入虚拟化操作模式.\n", processor_number);

	//配置vmcs区域
	fill_vmcs(vcpu, 0);
	vcpu->vcpu_status.vmm_launched = true;

	//从GUEST_RIP指定的位置继续执行
	//运行vm虚拟机
	if (!hv::vm_launch()) 
	{
		vcpu->vmexit_info.instruction_error = hv::vmread(VM_INSTRUCTION_ERROR);
		DbgPrint("[memproc_core] vCPU %lld 加载虚拟化失败", vcpu->vmexit_info.instruction_error);
		vcpu->vcpu_status.vmm_launched = false;
		vcpu->vcpu_status.vmx_on = false;
		//退出vmx模式
		__vmx_off();  
		return false;
	}

	DbgPrint("[memproc_core] vCPU %lld 加载虚拟化成功.\n", processor_number);
	return true;
}


// 启动 VT 的多核渲染 DPC 回调
VOID VtLoadProc( _In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	//ULONG uCpuNumber = KeGetCurrentProcessorNumber();
	//initalize_vcpu(uCpuNumber);

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}


bool vmm_init()
{
	if (allocate_vmm_context() == false)
	{
		DbgPrint("分配vmm上下文失败.\n");
		return false;
	}

	NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
	KeGenericCallDpc(VtLoadProc, NULL);
	KeStallExecutionProcessor(50);


	//我们需要在低于 DISPATCH_LEVEL 的 IRQL 下运行，以便 KeSetSystemAffinityThreadEx 立即生效
	//NT_ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	//// virtualize every cpu
	//for (unsigned int iter = 0; iter < g_vmm_context.processor_count; iter++)
	//{
	//	// restrict execution to the specified cpu
	//	auto const orig_affinity = KeSetSystemAffinityThreadEx(1ull << iter);

	//	if (!initalize_vcpu(iter)) {
	//		// TODO: handle this bruh -_-
	//		KeRevertToUserAffinityThreadEx(orig_affinity);
	//		outDebug("initalize_vcpu失败.\n");
	//		return false;
	//	}

	//	KeRevertToUserAffinityThreadEx(orig_affinity);
	//}
	//return true;

	return true;
}