#pragma once


#include <ntifs.h>
#include "ntimage.h"
#include <array>
#include <ntddk.h>
#include "Driver.h"
#include "HookSystem.h"
#include "hypervisor_gateway.h"

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemModuleInformation = 11,
	SystemHandleInformation = 16,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemKernelDebuggerInformation = 35,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemSessionProcessInformation = 53,
	SystemExtendedProcessInformation = 57,
	SystemExtendedHandleInformation = 64,
	SystemCodeIntegrityInformation = 103,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemKernelDebuggerFlags = 163
} SYSTEM_INFORMATION_CLASS;

typedef struct _SSDT
{
	LONG* ServiceTable;
	PVOID CounterTable;
	ULONG64 SyscallsNumber;
	PVOID ArgumentTable;
}_SSDT, * _PSSDT;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE {
	PVOID 	Reserved1;
	PVOID 	Reserved2;
	PVOID 	ImageBaseAddress;
	ULONG 	ImageSize;
	ULONG 	Flags;
	unsigned short 	Id;
	unsigned short 	Rank;
	unsigned short 	Unknown;
	unsigned short 	NameOffset;
	unsigned char 	Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG                       ModulesCount;
	SYSTEM_MODULE_ENTRY         Modules[1];
	ULONG                       Count;
	SYSTEM_MODULE 	            Sys_Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



typedef struct 
{
	SHORT SyscallNumber;
	std::string_view SyscallName;
	PVOID HookFunctionAddress;
	PVOID* OriginalFunctionAddress;
} SyscallInfo;

BOOLEAN RtlStringContains(PSTRING Str, PSTRING SubStr, BOOLEAN CaseInsensitive);
BOOLEAN GetProcessInfo(CONST CHAR* Name, ULONG64& ImageSize, PVOID& ImageBase);
BOOLEAN GetSectionData(CONST CHAR* ImageName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress);
PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask);
BOOLEAN GetSsdt();
PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName);
SHORT GetSyscallNumber(PVOID FunctionAddress);
BOOLEAN HookNtSyscall(ULONG SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunction);
BOOLEAN GetNtSyscallNumbers(std::array<SyscallInfo, 1>& SyscallsToFind);