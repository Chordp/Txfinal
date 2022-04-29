#include <ntifs.h>
#include <ntdef.h>
#include <ntstatus.h>
#include <cstdint>
#include "Table.h"
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
void MdlCopyMemory(PVOID address,PVOID buffer,size_t size)
{
	__try
	{
		if (MmIsAddressValid((PVOID)address))
		{
			auto pMdl = IoAllocateMdl(address, size, FALSE, FALSE, nullptr);
			if (pMdl)
			{
				MmBuildMdlForNonPagedPool(pMdl);

				auto lock = MmMapLockedPagesSpecifyCache(pMdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);

				if (lock)
				{
					RtlCopyMemory(lock, buffer, size);
					MmUnmapLockedPages(lock, pMdl);
				}
				ExFreePool(pMdl);

			}
		}
	}
	__except (1)
	{

	}

}
VOID LoadImageNotify(
	_In_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	if (FullImageName != nullptr && MmIsAddressValid(FullImageName))
	{
		if (ProcessId == 0) //  «∑Ò ««˝∂Ø
		{
			auto ImageName = FullImageName->Buffer;
			if (wcsstr(ImageName, L"2022GameSafeRace.sys"))
			{
				auto PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x18a4;
				auto JmpAddress = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x19ea;
				char jmp[] = {
					0xe9,0x00,0x00,0x00,0x00
				};
				*(uint32_t*)(jmp + 1) = (ULONG64)(JmpAddress - PatchFree - 5);
				// patch free
				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));
				// patch vad∂œ¡¥
				PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x1aae;
				JmpAddress = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x1ac9;
				*(uint32_t*)(jmp + 1) = (ULONG64)(JmpAddress - PatchFree - 5);

				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));

				MdlCopyMemory(PatchFree, &jmp, sizeof(jmp));
				//patch table
				PatchFree = reinterpret_cast<uint8_t*>(ImageInfo->ImageBase) + 0x4030;

				MdlCopyMemory(PatchFree, Table, sizeof(Table));



			}
		}
	}
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	PsRemoveLoadImageNotifyRoutine(LoadImageNotify);
}

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	pDriverObj->DriverUnload = DriverUnload;
	auto status = PsSetLoadImageNotifyRoutine(LoadImageNotify);
	return status;
}