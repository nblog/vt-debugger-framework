#pragma warning( disable : 4201)
#include "HookHelper.h"


static _PSSDT NtTable;

EXTERN_C NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

BOOLEAN RtlStringContains(PSTRING Str, PSTRING SubStr, BOOLEAN CaseInsensitive)
{
	if (Str == NULL || SubStr == NULL || Str->Length < SubStr->Length)
		return FALSE;

	CONST USHORT NumCharsDiff = (Str->Length - SubStr->Length);
	STRING Slice = *Str;
	Slice.Length = SubStr->Length;

	for (USHORT i = 0; i <= NumCharsDiff; ++i, ++Slice.Buffer, Slice.MaximumLength -= 1)
	{
		if (RtlEqualString(&Slice, SubStr, CaseInsensitive))
			return TRUE;
	}
	return FALSE;
}

BOOLEAN GetProcessInfo(CONST CHAR* Name, ULONG64& ImageSize, PVOID& ImageBase)
{
	ULONG Bytes;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &Bytes);
	PSYSTEM_MODULE_INFORMATION Mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, Bytes, 'aa');
	if (Mods == NULL)
		return FALSE;

	RtlSecureZeroMemory(Mods, Bytes);

	Status = ZwQuerySystemInformation(SystemModuleInformation, Mods, Bytes, &Bytes);
	if (NT_SUCCESS(Status) == FALSE)
	{
		ExFreePoolWithTag(Mods, 'aa');
		return FALSE;
	}

	STRING TargetProcessName;
	RtlInitString(&TargetProcessName, Name);

	for (ULONG i = 0; i < Mods->ModulesCount; i++)
	{
		STRING CurrentModuleName;
		RtlInitString(&CurrentModuleName, (PCSZ)Mods->Modules[i].FullPathName);

		if (RtlStringContains(&CurrentModuleName, &TargetProcessName, TRUE) != NULL)
		{
			if (Mods->Modules[i].ImageSize != NULL)
			{
				ImageSize = Mods->Modules[i].ImageSize;
				ImageBase = Mods->Modules[i].ImageBase;
				ExFreePoolWithTag(Mods, 'aa');
				return TRUE;
			}
		}
	}

	ExFreePoolWithTag(Mods, 'aa');
	return FALSE;
}

BOOLEAN GetSectionData(CONST CHAR* ImageName, CONST CHAR* SectionName, ULONG64& SectionSize, PVOID& SectionBaseAddress)
{
	ULONG64 ImageSize = 0;
	PVOID ImageBase = 0;

	if (GetProcessInfo(ImageName, ImageSize, ImageBase) == FALSE)
		return FALSE;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
	PIMAGE_NT_HEADERS32 NtHeader = (PIMAGE_NT_HEADERS32)(DosHeader->e_lfanew + (ULONG64)ImageBase);
	ULONG NumSections = NtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

	STRING TargetSectionName;
	RtlInitString(&TargetSectionName, SectionName);

	for (ULONG i = 0; i < NumSections; i++)
	{
		STRING CurrentSectionName;
		RtlInitString(&CurrentSectionName, (PCSZ)Section->Name);
		if (CurrentSectionName.Length > 8)
			CurrentSectionName.Length = 8;

		if (RtlCompareString(&CurrentSectionName, &TargetSectionName, FALSE) == 0)
		{
			SectionSize = Section->Misc.VirtualSize;
			SectionBaseAddress = (PVOID)((ULONG64)ImageBase + (ULONG64)Section->VirtualAddress);

			return TRUE;
		}
		Section++;
	}

	return FALSE;
}
PVOID FindSignature(PVOID Memory, ULONG64 Size, PCSZ Pattern, PCSZ Mask)
{
	ULONG64 SigLength = strlen(Mask);
	if (SigLength > Size) return NULL;

	for (ULONG64 i = 0; i < Size - SigLength; i++)
	{
		BOOLEAN Found = TRUE;
		for (ULONG64 j = 0; j < SigLength; j++)
			Found &= Mask[j] == '?' || Pattern[j] == *((PCHAR)Memory + i + j);

		if (Found)
			return (PCHAR)Memory + i;
	}
	return NULL;
}
BOOLEAN GetSsdt()
{
	PVOID KernelTextSectionBase = 0;
	ULONG64 KernelTextSectionSize = 0;

	if (GetSectionData("ntoskrnl.exe", ".text", KernelTextSectionSize, KernelTextSectionBase) == FALSE)
		return FALSE;

	CONST CHAR* Pattern = "\x4C\x8D\x15\x00\x00\x00\x00\x4C\x8D\x1D\x00\x00\x00\x00\xF7";
	CONST CHAR* Mask = "xxx????xxx????x";

	ULONG64 KeServiceDescriptorTableShadowAddress = (ULONG64)FindSignature(KernelTextSectionBase, KernelTextSectionSize, Pattern, Mask);
	if (KeServiceDescriptorTableShadowAddress == NULL)
		return FALSE;

	NtTable = (_PSSDT)((*(ULONG*)(KeServiceDescriptorTableShadowAddress + 10)) + KeServiceDescriptorTableShadowAddress + 14);
	//Win32kTable = NtTable + 1;

	return TRUE;
}

PVOID GetExportedFunctionAddress(PEPROCESS TargetProcess, PVOID ModuleBase, CONST CHAR* ExportedFunctionName)
{
	KAPC_STATE State;
	PVOID FunctionAddress = 0;
	if (TargetProcess != NULL)
		KeStackAttachProcess((PRKPROCESS)TargetProcess, &State);

	do
	{
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
		PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(DosHeader->e_lfanew + (ULONG64)ModuleBase);
		IMAGE_DATA_DIRECTORY ImageDataDirectory = NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (ImageDataDirectory.Size == 0 || ImageDataDirectory.VirtualAddress == 0)
			break;

		PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModuleBase + ImageDataDirectory.VirtualAddress);
		ULONG* Address = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfFunctions);
		ULONG* Name = (ULONG*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNames);
		USHORT* Ordinal = (USHORT*)((ULONG64)ModuleBase + ExportDirectory->AddressOfNameOrdinals);

		STRING TargetExportedFunctionName;
		RtlInitString(&TargetExportedFunctionName, ExportedFunctionName);

		for (size_t i = 0; i < ExportDirectory->NumberOfFunctions; i++)
		{
			STRING CurrentExportedFunctionName;
			RtlInitString(&CurrentExportedFunctionName, (PCHAR)ModuleBase + Name[i]);

			if (RtlCompareString(&TargetExportedFunctionName, &CurrentExportedFunctionName, TRUE) == 0)
			{
				FunctionAddress = (PVOID)((ULONG64)ModuleBase + Address[Ordinal[i]]);
				break;
			}
		}

	} while (0);

	if (TargetProcess != NULL)
		KeUnstackDetachProcess(&State);

	return FunctionAddress;
}

SHORT GetSyscallNumber(PVOID FunctionAddress)
{
	return *(SHORT*)((ULONG64)FunctionAddress + 4);
}

BOOLEAN GetNtSyscallNumbers(std::array<SyscallInfo, 1>& SyscallsToFind)
{
	UNICODE_STRING knownDlls{};
	RtlInitUnicodeString(&knownDlls, LR"(\KnownDlls\ntdll.dll)");

	OBJECT_ATTRIBUTES objAttributes{};
	InitializeObjectAttributes(&objAttributes, &knownDlls, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	HANDLE section{};
	if (!NT_SUCCESS(ZwOpenSection(&section, SECTION_MAP_READ, &objAttributes)))
		return false;

	PVOID ntdllBase{};
	size_t ntdllSize{};
	LARGE_INTEGER sectionOffset{};
	if (!NT_SUCCESS(ZwMapViewOfSection(section, ZwCurrentProcess(), &ntdllBase, 0, 0, &sectionOffset, &ntdllSize, ViewShare, 0, PAGE_READONLY)))
	{
		ZwClose(section);
		return false;
	}

	auto status = true;
	for (auto& syscallInfo : SyscallsToFind)
	{
		if (syscallInfo.SyscallName == "NtQuerySystemTime")
		{
			const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, "NtAccessCheckByTypeAndAuditAlarm");
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress) + 1;
		}
		else
		{
			const auto functionAddress = GetExportedFunctionAddress(0, ntdllBase, syscallInfo.SyscallName.data());
			if (!functionAddress)
			{
				status = false;
				break;
			}

			syscallInfo.SyscallNumber = GetSyscallNumber(functionAddress);
		}

		DbgPrint("Syscall %s is equal: 0x%X", syscallInfo.SyscallName.data(), syscallInfo.SyscallNumber);
	}

	ZwClose(section);
	ZwUnmapViewOfSection(ZwCurrentProcess(), ntdllBase);

	return status;
}

BOOLEAN HookNtSyscall(ULONG SyscallIndex, PVOID NewFunctionAddress, PVOID* OriginFunction)
{
	if (SyscallIndex > NtTable->SyscallsNumber)
	{
		LogError("There is no such syscall");
		return FALSE;
	}

	static UCHAR KernelAlignIndex = 0;

	PVOID AddressOfTargetFunction = (PVOID)((ULONG64)NtTable->ServiceTable + (NtTable->ServiceTable[SyscallIndex] >> 4));
	return hvgt::hook_function(AddressOfTargetFunction, NewFunctionAddress, OriginFunction);
}