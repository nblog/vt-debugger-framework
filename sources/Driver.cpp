#include "Driver.h"
#include "poolmanager.h"
#include "Globals.h"
#include "mtrr.h"
#include "ept.h"
#include "hypervisor_routines.h"
#include "vmm.h"
#include "hypervisor_gateway.h"
#include "interrupt.h"
#include "AsmCallset.h"
#include "vmexit_handler.h"
#include "vmcs.h"
#include "HookHelper.h"
#include "HookSystem.h"
#include "string.h"
#include "CreateDriver.h"

//控制码与用户层保持一致
#define ReadCtl  CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS) //读控制码
#define WriteCtl CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS) //写控制码
#define RWCtl    CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_BUFFERED,FILE_ANY_ACCESS) //读写控制码

enum vm_call_reasons
{
    VMCALL_TEST,
    VMCALL_VMXOFF,
    VMCALL_EPT_CC_HOOK,
    VMCALL_EPT_INT1_HOOK,
    VMCALL_EPT_RIP_HOOK,
    VMCALL_EPT_HOOK_FUNCTION,
    VMCALL_EPT_UNHOOK_FUNCTION,
    VMCALL_INVEPT_CONTEXT,
    VMCALL_DUMP_POOL_MANAGER,
    VMCALL_DUMP_VMCS_STATE,
    VMCALL_HIDE_HV_PRESENCE,
    VMCALL_UNHIDE_HV_PRESENCE,
    VMCALL_HIDE_SOFTWARE_BREAKPOINT,
    VMCALL_READ_SOFTWARE_BREAKPOINT,
    VMCALL_READ_EPT_FAKE_PAGE_MEMORY,
    VMCALL_WATCH_WRITES,
    VMCALL_WATCH_READS,
    VMCALL_WATCH_EXECUTES,
    VMCALL_WATCH_DELETE,
    VMCALL_GET_BREAKPOINT,
    VMCALL_INIT_OFFSET,
};

EXTERN_C
VOID Unload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_vmm_context.vcpu[0].vcpu_status.vmm_launched == true)
    {
        hvgt::ept_unhook();
        hvgt::vmoff(g_vmm_context.processor_count);
    }

    hv::disable_vmx_operation();
    free_vmm_context();

    DbgPrint("zxxx unload  %p \n", DriverObject);

    //先删除符号链接
    //再删除驱动设备
    if (DriverObject->DeviceObject)
    {
        UNICODE_STRING uzSymbolName;
        RtlInitUnicodeString(&uzSymbolName, L"\\??\\MemProc");
        IoDeleteSymbolicLink(&uzSymbolName);
        IoDeleteDevice(DriverObject->DeviceObject);
        DbgPrint("zxxx 删除符号链接 \n");
        DbgPrint("zxxx 删除驱动设备 \n");
    }

    DbgPrint("[memproc_core] 驱动卸载成功\n");
}

bool vmcall_internal(PVOID vmcallinfo)
{
    unsigned long ecode = 0;
    uint64_t boSuccess = false;
    __try 
    {
        boSuccess = __vm_call(((PVMCALLINFO)vmcallinfo)->command, (unsigned __int64)vmcallinfo, 0, 0);
        DbgPrint("[memproc_core] 执行vmcall 结果-> 0x%x", boSuccess);
    }
    __except (ecode = GetExceptionCode(), 1) 
    {
        DbgPrint("[memproc_core] 执行vmcall时遇到了错误 (error: 0x%X)", ecode);
    }
    return boSuccess;
}

//创建驱动对象并绑定符号链接
NTSTATUS CreateDevice(PDRIVER_OBJECT driver)
{
    NTSTATUS status;
    UNICODE_STRING MyDriver;	//驱动名称
    PDEVICE_OBJECT device;		//驱动设备
    RtlInitUnicodeString(&MyDriver, L"\\DEVICE\\MemProc");//初始化驱动名称

    //在驱动对象上创建驱动设备
    status = IoCreateDevice(driver, sizeof(driver->DriverExtension), &MyDriver, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);

    if (status == STATUS_SUCCESS)
    {
        KdPrint(("zxxx 驱动设备对象创建成功 \n"));
        //创建符合链接
        UNICODE_STRING uzSymbolName;
        RtlInitUnicodeString(&uzSymbolName, L"\\??\\MemProc"); //初始化符号链接 符号链接格式 L"\\??\\名字
        //为驱动设备绑定符号链接    后续不会使用驱动对象与内核交换，而是使用符号链接与内核交换
        status = IoCreateSymbolicLink(&uzSymbolName, &MyDriver);
        if (status == STATUS_SUCCESS)
        {
            KdPrint(("zxxx 符号链接创建成功 %wZ \n", &uzSymbolName));
        }
        else
        {
            KdPrint(("zxxx 符号链接创建失败 %wZ \n", &uzSymbolName));
        }
    }
    else
    {
        KdPrint(("zxxx 驱动设备对象创建失败 \n"));
        IoDeleteDevice(device);
    }
    return status;
}


void IRP_IO_Read(PIRP pirp)
{
    char* buff = (char*)pirp->AssociatedIrp.SystemBuffer;
    //获取R3传来的参数（控制码）
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(pirp);
    //将R0读取到的数据写入到向共享缓冲区
    char R0returnbuf[] = "zxxx R0 read data \n";
    ULONG len = sizeof(R0returnbuf);

    memcpy(buff, R0returnbuf,len);
    KdPrint(("zxxx IRP_IO_Read read data to SystemBuffer \n"));

    //每次IRP执行完了 要执行下面三行 作为返回结果
    pirp->IoStatus.Status = STATUS_SUCCESS;
    pirp->IoStatus.Information = len;  //共享缓冲区返回的长度
    IoCompleteRequest(pirp, IO_NO_INCREMENT);
}

//传入驱动设备的IRP事件
NTSTATUS IRP_CALL(PDEVICE_OBJECT device, PIRP pirp)
{
    device;
    DbgPrint(("zxxx 发生IRP事件 进入IRP函数 \n"));
    PIO_STACK_LOCATION irpStackL;
    irpStackL = IoGetCurrentIrpStackLocation(pirp);

    switch (irpStackL->MajorFunction)
    {
    case IRP_MJ_CREATE:
    {
        DbgPrint(("zxxx IRP_MJ_CREATE \n"));
        break;
    }
    case IRP_MJ_CLOSE:
    {
        DbgPrint(("zxxx IRP_MJ_CLOSE \n"));
        break;
    }
    case IRP_MJ_DEVICE_CONTROL:
    {
        DbgPrint(("zxxx IRP_MJ_DEVICE_CONTROL \n"));
        //取到的R3的控制码
        UINT32 CtlCode = irpStackL->Parameters.DeviceIoControl.IoControlCode;
        DbgPrint("zxxx IRP_MJ_DEVICE_CONTROL R0控制码:%X \n", CtlCode);


        if (CtlCode == ReadCtl)
        {
            DbgPrint("zxxx IRP_MJ_DEVICE_CONTROL ReadCtl R0控制码:%X \n", CtlCode);
            IRP_IO_Read(pirp); //这里写入到共享缓冲剂即可，打印R3访问共享缓冲区打印
            return STATUS_SUCCESS;
        }
        else if (CtlCode == WriteCtl)
        {
            DbgPrint("zxxx IRP_MJ_DEVICE_CONTROL WriteCtl R0控制码:%X \n", CtlCode);
            //取出R3缓冲区的数据
            //根据控制代码来选择使用AssociatedIrp.SystemBuffer的读缓冲区还是写缓冲区
            char* R3buff = (char*)pirp->AssociatedIrp.SystemBuffer;
            DbgPrint("zxxx IRP_MJ_DEVICE_CONTROL R0缓冲区:%s \n", R3buff);

        }
        else if (CtlCode == RWCtl)
        {
            DbgPrint("zxxx IRP_MJ_DEVICE_CONTROL RWCtl R0控制码:%X \n", CtlCode);
        }
        break;
    }
    }

    //注意 只要pirp这个对象发生变化 就要跟着下面这三行 
    pirp->IoStatus.Status = STATUS_SUCCESS;
    pirp->IoStatus.Information = 4;
    IoCompleteRequest(pirp, IO_NO_INCREMENT);
    DbgPrint(("zxxx 结束IRP事件 离开IRP函数 \n"));
    return STATUS_SUCCESS;
}

EXTERN_C
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = Unload;

    NTSTATUS nStatus = STATUS_SUCCESS;
    if (!hv::virtualization_support())
    {
        DbgPrint("[memproc_core] 此处理器不支持VT-x.\n");
        return STATUS_UNSUCCESSFUL;
    }

    hv::InitGlobalVariables();
    if (vmm_init() == false)
    {
        hv::disable_vmx_operation();
        free_vmm_context();
        DbgPrint("[memproc_core] 启动虚拟机失败.");
        return STATUS_UNSUCCESSFUL;
    }

    #define DIRECTORY_TABLE_BASE 0x028
    PEPROCESS Peprocess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)1337, &Peprocess);
    if (Peprocess != NULL)
    {
        ULONG64 cr3 = *(ULONG64*)((UCHAR*)Peprocess + DIRECTORY_TABLE_BASE);
        DbgPrint("cr3 is %lld\n", cr3);
        uint64_t result = __vm_call(VMCALL_TEST, cr3, 0x00007ff72b8aa000, 0);
        DbgPrint("[memproc_core] %lld\n", result);
    }
    else
    {
        DbgPrint("[memproc_core] 找不到CR3\n");
    }
    DbgPrint("[memproc_core] 驱动加载完成\n");

    DriverObject->MajorFunction[IRP_MJ_CREATE]          = IRP_CALL;	  //指定IRP事件函数
    DriverObject->MajorFunction[IRP_MJ_CLOSE]           = IRP_CALL;   //指定IRP事件函数
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]  = IRP_CALL;   //指定IRP事件函数
    Initialize_SystemHooks();
    //创建驱动设备
    CreateDevice(DriverObject);
	DriverObject->DriverUnload = Unload;
    return nStatus;
}


NTSTATUS CustomDriverEntry(
    _In_ PDRIVER_OBJECT  kdmapperParam1,
    _In_ PUNICODE_STRING kdmapperParam2
)
{

    UNREFERENCED_PARAMETER(kdmapperParam1);
    UNREFERENCED_PARAMETER(kdmapperParam2);


    DbgPrint("HelloWorld\n");


    return ioctl::create_driver(&DriverEntry);

}

bool InitOffset(PWINDOWS_STRUCT vmcallinfo)
{
    WINDOWS_STRUCT tmp_vmcallinfo = { 0 };

    if (sizeof(WINDOWS_STRUCT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(WINDOWS_STRUCT)))
    {
        //读取数据可能不完整
        return false;
    }

    hv::ghv.kpcr_pcrb_offset = 0x180;
    hv::ghv.kprcb_current_thread_offset = 0x8;
    ethread_offset::Cid = tmp_vmcallinfo.ethread_offset_Cid;
    return true;
}

PCLIENT_ID GuestCurrentThreadCid()
{
    size_t Thread = hv::current_guest_ethread();
    size_t ptr_Cid = Thread + ethread_offset::Cid;
    return (PCLIENT_ID)ptr_Cid;
}

bool SetBreakpoint(PVT_BREAK_POINT vmcallinfo, unsigned __int64 Type)
{
    int errorCode = 0;
    int status = 0;
    VT_BREAK_POINT tmp_vmcallinfo = { 0 };

    if (sizeof(VT_BREAK_POINT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
    {
        //读取数据可能不完整
        return false;
    }

    int outID = -1;
    if (ept::ept_watch_activate(tmp_vmcallinfo, Type, &outID, errorCode))
    {
        tmp_vmcallinfo.watchid = outID;

        if (sizeof(VT_BREAK_POINT) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
        {
            //写入数据可能不完整
            return false;
        }
        return true;
    }
    else
    {
        tmp_vmcallinfo.errorCode = errorCode;

        if (sizeof(VT_BREAK_POINT) != hv::write_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
        {
            //写入数据可能不完整
            return false;
        }
    }
    return false;
}

bool RemoveBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    VT_BREAK_POINT tmp_vmcallinfo = { 0 };

    if (sizeof(VT_BREAK_POINT) != hv::read_guest_virtual_memory(vmcallinfo, &tmp_vmcallinfo, sizeof(VT_BREAK_POINT)))
    {
        //读取数据可能不完整
        return false;
    }

    if (ept::ept_watch_deactivate(tmp_vmcallinfo, tmp_vmcallinfo.watchid) == 0)
    {
        return true;
    }

    return false;
}

