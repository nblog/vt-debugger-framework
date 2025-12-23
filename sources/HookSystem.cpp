#pragma warning( disable : 4201)
#include <ntifs.h>
#include "ntimage.h"
#include <array>
#include <ntddk.h>
#include "Driver.h"

#include "HookHelper.h"
#include "HookSystem.h"
#include "hypervisor_gateway.h"

PWCHAR PassProcessList[12] = 
{
    _T("system"),
    _T("Registry"),
    _T("csrss.exe"),
    _T("svchost.exe"),
    _T("services.exe"),
    _T("lsass.exe"),
    _T("explorer.exe"),
    _T("dwm.exe"),
    _T("dllhost.exe"),
    _T("smss.exe"),
    _T("WmiPrvSE.exe"),
    _T("ctfmon.exe"),
};

PCWCH protected_process_list[] = 
{
    L"cheatengine", L"HyperCE", L"x64dbg", L"x32dbg", L"ida", L"windbg"
};

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
    ULONG HardFaultCount;				 // since WIN7
    ULONG NumberOfThreadsHighWatermark;	 // since WIN7
    ULONGLONG CycleTime;				 // since WIN7
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey; // since VISTA (requires
    // SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;



using fnNtQuerySystemInformation = NTSTATUS(__stdcall*)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
fnNtQuerySystemInformation old_NtQuerySystemInformation = nullptr;


using fnObReferenceObjectByHandleWithTag = NTSTATUS(__stdcall*)(HANDLE Handle,
    ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag,
    PVOID* Object, POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0);
fnObReferenceObjectByHandleWithTag old_ObpReferenceObjectByHandleWithTag = nullptr;

extern "C" char* PsGetProcessImageFileName(PEPROCESS Process);

EXTERN_C NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS(NTAPI* OriginalNtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}


bool StringArrayContainsW(PCWCH str, PCWCH* arr, SIZE_T len)
{
    if (str == nullptr || arr == nullptr || len == 0)
        return false;

    for (SIZE_T i = 0; i < len; i++) {
        if (wcsstr(str, arr[i]) != nullptr)
            return true;
    }
    return false;
}

bool IsProtectedProcessW(PCWCH process)
{
    if (process == nullptr)
        return false;

    return StringArrayContainsW(
        process, protected_process_list, sizeof(protected_process_list) / sizeof(PCWCH));
}
bool IsProtectedProcessA(PCSZ process)
{
    if (process == nullptr)
        return false;

    ANSI_STRING process_ansi{ 0 };
    UNICODE_STRING process_unicode{ 0 };
    RtlInitAnsiString(&process_ansi, process);
    NTSTATUS status = RtlAnsiStringToUnicodeString(&process_unicode, &process_ansi, TRUE);
    if (!NT_SUCCESS(status))
        return false;

    bool result = IsProtectedProcessW(process_unicode.Buffer);
    RtlFreeUnicodeString(&process_unicode);
    return result;
}

uint8_t* FindObpReferenceObjectByHandleWithTag()
{
    auto const pObReferenceObjectByHandleWithTag =
        reinterpret_cast<uint8_t*>(ObReferenceObjectByHandleWithTag);

    for (size_t offset = 0; offset < 0x100; ++offset) {
        auto const curr = pObReferenceObjectByHandleWithTag + offset;

        if (*curr == 0xE8)
            return curr + 5 + *(int*)(curr + 1);
    }

    return nullptr;
}

//判断UNICODE字符串是否为空
BOOLEAN StrIsValid2(UNICODE_STRING filePath)
{
    if (filePath.Length == 0)
        return FALSE;
    else
        return TRUE;
}

//获取文件名称
bool GetModuleFileName(OUT WCHAR* fileName, IN PUNICODE_STRING filePath)
{
    if (filePath)
    {
        if (StrIsValid2(*filePath))
        {
            int Full_length = filePath->Length / sizeof(WCHAR);
            int i = Full_length - 1;

            while ((filePath->Buffer[i] != L'\\') && (i > 0))
            {
                i--;
            }

            if (filePath->Buffer[i] == L'\\')
            {
                int fileNameLen = Full_length - (i + 1);
                wcsncpy(fileName, &filePath->Buffer[i + 1], fileNameLen);
                return true;
            }
            else
            {
                //默认整个路径是文件名
                wcsncpy(fileName, &filePath->Buffer[i], Full_length);
                return true;
            }
        }
    }
    return false;
}

//获取进程名
NTSTATUS GetProcessName(IN PEPROCESS Process, OUT WCHAR* fileName)
{
    NTSTATUS Status;
    PUNICODE_STRING ImageFileName;
    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (NT_SUCCESS(Status))
    {
        if (GetModuleFileName(fileName, ImageFileName))
        {
            Status = STATUS_SUCCESS;
        }
        else
        {
            Status = STATUS_UNSUCCESSFUL;
        }

        if (ImageFileName)
        {
            ExFreePool(ImageFileName);
        }
    }
    return Status;
}

NTSTATUS ObpReferenceObjectByHandleWithTagHook(HANDLE Handle, ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, ULONG Tag, PVOID* Object,
    POBJECT_HANDLE_INFORMATION HandleInformation, __int64 a0)
{
    char* curr_process_name = PsGetProcessImageFileName(PsGetCurrentProcess());
    if (IsProtectedProcessA(curr_process_name))
    {
        return old_ObpReferenceObjectByHandleWithTag(Handle, DesiredAccess, ObjectType, KernelMode, Tag, Object, HandleInformation, a0);
    }

    return old_ObpReferenceObjectByHandleWithTag(Handle, DesiredAccess, ObjectType, AccessMode, Tag, Object, HandleInformation, a0);
}

NTSTATUS NtQuerySystemInformationHook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS stat = old_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (NT_SUCCESS(stat) && SystemInformationClass == SystemProcessInformation) 
    {
        PSYSTEM_PROCESS_INFORMATION prev = PSYSTEM_PROCESS_INFORMATION(SystemInformation);
        PSYSTEM_PROCESS_INFORMATION curr = PSYSTEM_PROCESS_INFORMATION((PUCHAR)prev + prev->NextEntryOffset);

        while (prev->NextEntryOffset != NULL) 
        {
            auto buffer = curr->ImageName.Buffer;
            if (buffer && IsProtectedProcessW(buffer)) 
            {
                if (curr->NextEntryOffset == 0)
                {
                    prev->NextEntryOffset = 0;
                }
                else
                {
                    prev->NextEntryOffset += curr->NextEntryOffset;
                }
                curr = prev;
            }
            prev = curr;
            curr = PSYSTEM_PROCESS_INFORMATION((PUCHAR)curr + curr->NextEntryOffset);
        }
    }

    return stat;
}


void Initialize_SystemHooks()
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
    const auto g_NtQuerySystemInformation = (uint8_t*)MmGetSystemRoutineAddress(&routineName);

	std::array a
	{
		SyscallInfo{0, "NtOpenProcess", HookedNtOpenProcess, (void**)&OriginalNtOpenProcess}
	};

	GetSsdt();

	if (GetNtSyscallNumbers(a))
	{
		if (HookNtSyscall(a[0].SyscallNumber, a[0].HookFunctionAddress, a[0].OriginalFunctionAddress))
		{
			DbgPrint("ssdt hook ok!");
		}
	}


    auto result = hvgt::hook_function(FindObpReferenceObjectByHandleWithTag(), ObpReferenceObjectByHandleWithTagHook, (void**)&old_ObpReferenceObjectByHandleWithTag);
    DbgPrint("[hv] ObReferenceObjectByHandleWithTag hook installed: %s.\n", result ? "success\n" : "failure\n");

    /*result = hvgt::hook_function(g_NtQuerySystemInformation, NtQuerySystemInformationHook, (void**)&old_NtQuerySystemInformation);
    DbgPrint("[hv] NtQuerySystemInformation hook installed: %s.\n", result ? "success\n" : "failure\n");
    DbgBreakPoint();*/

}