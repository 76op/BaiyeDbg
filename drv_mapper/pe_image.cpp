#include "pe_image.h"

pe_image::pe_image() : 
	_dos_header{ nullptr },
	_nt_header{ nullptr },
	_section_data{ nullptr },
	_section_handle{ nullptr },
	_erase_header{ false }
{
}

pe_image::pe_image(void *section_data, HANDLE section_handle) :
	_dos_header{ nullptr },
	_nt_header{ nullptr },
	_section_data{ section_data },
	_section_handle{ section_handle },
	_erase_header{ false }
{
	this->_dos_header = (IMAGE_DOS_HEADER *)this->_section_data;
	this->_nt_header = (IMAGE_NT_HEADERS *)((ULONG_PTR)this->_section_data + this->_dos_header->e_lfanew);
}

pe_image::~pe_image()
{

}

uint32_t pe_image::image_size()
{
	return _image_size;
}

bool pe_image::allocate_section(size_t size)
{
	NTSTATUS			Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES	soa;
	UNICODE_STRING		SectionName;
	HANDLE				Handle;
	PVOID				SectionAddress;

	LARGE_INTEGER		FileSize;
	FileSize.QuadPart = size;

	this->_section_data = nullptr;
	this->_section_handle = nullptr;

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
		return false;
	}

	SIZE_T SpaceSize = 0;
	Status = MmMapViewInSystemSpace(Handle, &SectionAddress, &SpaceSize);

	if (!NT_SUCCESS(Status))
	{
		NtClose(Handle);
		return false;
	}

	this->_section_data = SectionAddress;
	this->_section_handle = Handle;

	return true;
}


bool pe_image::fix_iat()
{
	IMAGE_DATA_DIRECTORY *DataDirectory = this->_nt_header->OptionalHeader.DataDirectory;

	// 修复IAT
	ULONG ImportTableRva = DataDirectory[1].VirtualAddress;
	ULONG ImportTableSize = DataDirectory[1].Size;

	IMAGE_IMPORT_DESCRIPTOR *ImportTable = (IMAGE_IMPORT_DESCRIPTOR *)((PUCHAR)this->_section_data + ImportTableRva);

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

		char *FuncName = (char *)this->_section_data + NameRva;

		IMAGE_THUNK_DATA *OriginalFirstThunkData = (IMAGE_THUNK_DATA *)((char *)this->_section_data + OrginalFirstThunkRva);
		ULONG_PTR *FirstThunkData = (ULONG_PTR *)((char *)this->_section_data + FirstThunkRva);

		for (int j = 0; ; j++)
		{
			if (OriginalFirstThunkData[j].u1.Ordinal == 0)
				break;

			if (IMAGE_SNAP_BY_ORDINAL64(OriginalFirstThunkData[j].u1.Ordinal))
			{
				return false;
			}
			else
			{
				IMAGE_IMPORT_BY_NAME *ImportName = (IMAGE_IMPORT_BY_NAME *)((char *)this->_section_data + OriginalFirstThunkData[j].u1.AddressOfData);

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

	return true;
}

bool pe_image::fix_base_relocation()
{
	IMAGE_DATA_DIRECTORY *DataDirectory = this->_nt_header->OptionalHeader.DataDirectory;

	ULONG_PTR ImageBase = this->_nt_header->OptionalHeader.ImageBase;

	// 修复重定位
	ULONG BrTableRva = DataDirectory[5].VirtualAddress;
	ULONG BrTableSize = DataDirectory[5].Size;

	IMAGE_BASE_RELOCATION *BaseRelocation = (IMAGE_BASE_RELOCATION *)((ULONG_PTR)this->_section_data + BrTableRva);

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
				ULONG *offset_val = (ULONG *)((ULONG_PTR)this->_section_data + offset_rva);
				*offset_val = (ULONG)this->_section_data + ((*offset_val) - ImageBase);
			}
			else if (type == IMAGE_REL_BASED_DIR64)
			{
				ULONG_PTR *offset_val = (ULONG_PTR *)((ULONG_PTR)this->_section_data + offset_rva);
				*offset_val = (ULONG_PTR)this->_section_data + ((*offset_val) - ImageBase);
			}
			else if (type != 0)
			{
				return FALSE;
			}
		}

		BaseRelocation = (IMAGE_BASE_RELOCATION *)((ULONG_PTR)BaseRelocation + sob);
		i++;
	}

	return true;
}


bool pe_image::load(void *file_data, size_t file_size)
{
	if (file_size < 3)
	{
		return false;
	}

	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)file_data;
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	IMAGE_NT_HEADERS *nt_header = (IMAGE_NT_HEADERS *)((ULONG_PTR)file_data + dos_header->e_lfanew);
	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	SIZE_T image_size = nt_header->OptionalHeader.SizeOfImage;
	SIZE_T header_size = nt_header->OptionalHeader.SizeOfHeaders;

	this->_image_size = image_size;

	if (!allocate_section(image_size))
	{
		return false;
	}

	RtlZeroMemory(this->_section_data, image_size);

	// 复制Header数据
	RtlCopyMemory(this->_section_data, file_data, header_size);

	this->_dos_header = (IMAGE_DOS_HEADER *)this->_section_data;
	this->_nt_header = (IMAGE_NT_HEADERS *)((ULONG_PTR)this->_section_data + this->_dos_header->e_lfanew);

	// 获取节区
	IMAGE_SECTION_HEADER *pe_section_header =
		(IMAGE_SECTION_HEADER *)(
			(char *)&this->_nt_header->FileHeader +
			sizeof(IMAGE_FILE_HEADER) +
			this->_nt_header->FileHeader.SizeOfOptionalHeader
			);

	// 复制节区
	PUCHAR empty_name[IMAGE_SIZEOF_SHORT_NAME] = { 0 };

	IMAGE_SECTION_HEADER *pe_section_header_temp = pe_section_header;

	while (RtlCompareMemory(&pe_section_header_temp->Name, empty_name, IMAGE_SIZEOF_SHORT_NAME) != IMAGE_SIZEOF_SHORT_NAME)
	{
		ULONG VirtualAddress = pe_section_header_temp->VirtualAddress;
		ULONG PointerToRawData = pe_section_header_temp->PointerToRawData;
		ULONG SizeOfRawData = pe_section_header_temp->SizeOfRawData;

		RtlCopyMemory((PUCHAR)this->_section_data + VirtualAddress, (PUCHAR)file_data + PointerToRawData, SizeOfRawData);

		pe_section_header_temp++;
	}

	if (!this->fix_iat())
	{
		NtClose(this->_section_handle);

		this->_section_data = nullptr;
		this->_section_handle = nullptr;
		this->_dos_header = nullptr;
		this->_nt_header = nullptr;
		return false;
	}

	if (!this->fix_base_relocation())
	{
		NtClose(this->_section_handle);

		this->_section_data = nullptr;
		this->_section_handle = nullptr;
		this->_dos_header = nullptr;
		this->_nt_header = nullptr;
		return false;
	}

	return true;
}

void pe_image::unload()
{
	RtlZeroMemory(this->_section_data, this->_nt_header->OptionalHeader.SizeOfImage);
	MmUnmapViewInSystemSpace(this->_section_data);
	NtClose(this->_section_handle);

	this->_section_data = nullptr;
	this->_section_handle = nullptr;
	this->_dos_header = nullptr;
	this->_nt_header = nullptr;
}

Fn_DriverEntry pe_image::sys_ep()
{
	if (this->_erase_header)
	{
		return nullptr;
	}

	ULONG ep_rva = this->_nt_header->OptionalHeader.AddressOfEntryPoint;
	Fn_DriverEntry ep = (Fn_DriverEntry)((ULONG_PTR)this->_section_data + ep_rva);
	return ep;
}

void pe_image::erase_header()
{
	SIZE_T header_size = this->_nt_header->OptionalHeader.SizeOfHeaders;
	RtlZeroMemory(this->_section_data, header_size);
	this->_erase_header = true;
}

void *pe_image::section_data()
{
	return this->_section_data;
}

HANDLE pe_image::section_handle()
{
	return this->_section_handle;
}