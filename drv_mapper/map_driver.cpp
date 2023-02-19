#include "map_driver.h"

typedef ULONG WIN32_PROTECTION_MASK;

#ifdef __cplusplus
extern "C"
{
#endif
	NTKERNELAPI NTSTATUS MmCreateSection(
		__deref_out PVOID *SectionObject,
		__in ACCESS_MASK DesiredAccess,
		__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
		__in PLARGE_INTEGER InputMaximumSize,
		__in WIN32_PROTECTION_MASK SectionPageProtection,
		__in ULONG AllocationAttributes,
		__in_opt HANDLE FileHandle,
		__in_opt PFILE_OBJECT FileObject
	);
#ifdef __cplusplus
}
#endif


BOOLEAN IsValidPe(PVOID PeData, SIZE_T PeSize)
{
	if (PeSize < 3)
	{
		return FALSE;
	}

	// 是否是PE文件
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)PeData;
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	// 是否是PE文件
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)((ULONG_PTR)PeData + DosHeader->e_lfanew);
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN FixIat(PVOID SectionData)
{
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)SectionData;
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)((ULONG_PTR)SectionData + DosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY *DataDirectory = NtHeader->OptionalHeader.DataDirectory;

	// 修复IAT
	ULONG ImportTableRva = DataDirectory[1].VirtualAddress;
	ULONG ImportTableSize = DataDirectory[1].Size;

	IMAGE_IMPORT_DESCRIPTOR *ImportTable = (IMAGE_IMPORT_DESCRIPTOR *)((PUCHAR)SectionData + ImportTableRva);

	for (int i = 0; ; i++)
	{
		if (ImportTable[i].Name == 0 && ImportTable[i].OriginalFirstThunk == 0)
		{
			break;
		}

		ImportTable[i].TimeDateStamp = -1;

		ULONG NameRva = ImportTable[i].Name;
		ULONG FirstThunkRva = ImportTable[i].FirstThunk;
		ULONG OrginalFirstThunkRva = ImportTable[i].OriginalFirstThunk;

		char *FuncName = (char *)SectionData + NameRva;

		IMAGE_THUNK_DATA *OriginalFirstThunkData = (IMAGE_THUNK_DATA *)((char *)SectionData + OrginalFirstThunkRva);
		ULONG_PTR *FirstThunkData = (ULONG_PTR *)((char *)SectionData + FirstThunkRva);

		for (int j = 0; ; j++)
		{
			if (OriginalFirstThunkData[j].u1.Ordinal == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL64(OriginalFirstThunkData[j].u1.Ordinal))
			{
				return FALSE;
			}
			else
			{
				IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)((char *)SectionData + OriginalFirstThunkData[j].u1.AddressOfData);

				ANSI_STRING asFuncName;
				UNICODE_STRING usFuncName = { 0 };

				RtlInitAnsiString(&asFuncName, ImportName->Name);
				RtlAnsiStringToUnicodeString(&usFuncName, &asFuncName, TRUE);

				PVOID FuncAddress = MmGetSystemRoutineAddress(&usFuncName);

				RtlFreeUnicodeString(&usFuncName);

				FirstThunkData[j] = (ULONG_PTR)FuncAddress;
			}
		}
	}
	return TRUE;
}

BOOLEAN FixBaseRelocation(PVOID SectionData)
{
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)SectionData;
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)((ULONG_PTR)SectionData + DosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY *DataDirectory = NtHeader->OptionalHeader.DataDirectory;

	ULONG_PTR ImageBase = NtHeader->OptionalHeader.ImageBase;

	// 修复重定位
	ULONG BrTableRva = DataDirectory[5].VirtualAddress;
	ULONG BrTableSize = DataDirectory[5].Size;

	IMAGE_BASE_RELOCATION *BaseRelocation = (IMAGE_BASE_RELOCATION *)((ULONG_PTR)SectionData + BrTableRva);

	int i = 0;
	while (true)
	{
		ULONG va = BaseRelocation->VirtualAddress;
		ULONG sob = BaseRelocation->SizeOfBlock;
		if (va == 0 || sob == 0)
			break;

		ULONG item_count = (sob - 8) / 2;
		USHORT *items = (USHORT *)((ULONG_PTR)BaseRelocation + 8);

		for (int j = 0; j < item_count; j++)
		{
			USHORT item = items[j];
			UCHAR type = item >> 12 & 0xf;
			USHORT offset = item & 0xfff;
			ULONG offset_rva = va + offset;

			if (type == IMAGE_REL_BASED_HIGHLOW)
			{
				ULONG *offset_val = (ULONG *)((ULONG_PTR)SectionData + offset_rva);
				*offset_val = (ULONG)SectionData + ((*offset_val) - ImageBase);
			}
			else if (type == IMAGE_REL_BASED_DIR64)
			{
				ULONG_PTR *offset_val = (ULONG_PTR *)((ULONG_PTR)SectionData + offset_rva);
				*offset_val = (ULONG_PTR)SectionData + ((*offset_val) - ImageBase);
			}
			else if (type != 0)
			{
				return FALSE;
			}
		}

		BaseRelocation = (IMAGE_BASE_RELOCATION *)((ULONG_PTR)BaseRelocation + sob);
		i++;
	}

	return TRUE;
}

NTSTATUS AllocSectionMemory(HANDLE *SectionHandle, PVOID *SectionData, SIZE_T Size)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES	soa;
	UNICODE_STRING		SectionName;
	HANDLE				Handle;
	PVOID				SectionAddress;

	LARGE_INTEGER		FileSize;
	FileSize.QuadPart = Size;

	*SectionHandle = (HANDLE)((LONG64)-1);
	*SectionData = NULL;

	InitializeObjectAttributes(
		&soa,
		NULL,
		NULL,
		NULL,
		NULL
	);

	Status = MmCreateSection(
		&Handle,
		SECTION_ALL_ACCESS,
		NULL,
		&FileSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL,
		NULL
	);

	if (!NT_SUCCESS(Status))
	{
		//DbgPrint("MmCreateSection失败.\n");
		return Status;
	}

	SIZE_T SpaceSize = 0;
	Status = MmMapViewInSystemSpace(Handle, &SectionAddress, &SpaceSize);

	if (!NT_SUCCESS(Status))
	{
		//DbgPrint("MmMapViewInSystemSpace - Faild.\n");
		NtClose(Handle);
		return Status;
	}

	*SectionHandle = Handle;
	*SectionData = SectionAddress;

	return Status;
}

VOID MapDriverCopy(PVOID PeData, SIZE_T PeSize, PVOID SectionAddress, SIZE_T Size)
{
	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)PeData;
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)((ULONG_PTR)PeData + DosHeader->e_lfanew);

	SIZE_T ImageSize = NtHeader->OptionalHeader.SizeOfImage;
	SIZE_T HeaderSize = NtHeader->OptionalHeader.SizeOfHeaders;

	RtlZeroMemory(SectionAddress, ImageSize);

	// 复制Header数据
	RtlCopyMemory(SectionAddress, PeData, HeaderSize);

	// 获取节区
	IMAGE_SECTION_HEADER *SectionHeader = (IMAGE_SECTION_HEADER *)((char *)&NtHeader->FileHeader + sizeof(IMAGE_FILE_HEADER) + NtHeader->FileHeader.SizeOfOptionalHeader);

	// 复制节区
	PUCHAR EmptyName[IMAGE_SIZEOF_SHORT_NAME] = { 0 };

	IMAGE_SECTION_HEADER *SectionHeaderTemp = SectionHeader;

	int i = 0;
	while (RtlCompareMemory(&SectionHeaderTemp->Name, EmptyName, IMAGE_SIZEOF_SHORT_NAME) != IMAGE_SIZEOF_SHORT_NAME)
	{
		ULONG VirtualAddress = SectionHeaderTemp->VirtualAddress;
		ULONG PointerToRawData = SectionHeaderTemp->PointerToRawData;
		ULONG SizeOfRawData = SectionHeaderTemp->SizeOfRawData;

		RtlCopyMemory((PUCHAR)SectionAddress + VirtualAddress, (PUCHAR)PeData + PointerToRawData, SizeOfRawData);

		i++;
		SectionHeaderTemp++;
	}
}

typedef NTSTATUS(*Fn_FxDriverEntry)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

BOOLEAN MapDriverInit(PVOID SysData, SIZE_T SysSize)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE SectionHandle;
	PVOID SectionData;

	if (!IsValidPe(SysData, SysSize))
	{
		DbgPrint("不是PE\n");
		return FALSE;
	}

	IMAGE_DOS_HEADER *DosHeader = (IMAGE_DOS_HEADER *)SysData;
	IMAGE_NT_HEADERS *NtHeader = (IMAGE_NT_HEADERS *)((ULONG_PTR)SysData + DosHeader->e_lfanew);

	SIZE_T ImageSize = NtHeader->OptionalHeader.SizeOfImage;

	Status = AllocSectionMemory(&SectionHandle, &SectionData, ImageSize);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("AllocSectionMemory 失败\n");
		return FALSE;
	}

	MapDriverCopy(SysData, SysSize, SectionData, ImageSize);

	if (!FixIat(SectionData))
	{
		NtClose(SectionHandle);
		DbgPrint("FixIat 失败\n");
		return FALSE;
	}

	if (!FixBaseRelocation(SectionData))
	{
		NtClose(SectionHandle);
		DbgPrint("FixBaseRelocation 失败\n");
		return FALSE;
	}

	Fn_FxDriverEntry ep = (Fn_FxDriverEntry)((ULONG_PTR)SectionData + NtHeader->OptionalHeader.AddressOfEntryPoint);
	ep(NULL, NULL);

	return TRUE;
}