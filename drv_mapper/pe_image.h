#pragma once
#include "_global.h"

typedef NTSTATUS(*Fn_DriverEntry)(
	void *Arg1,
	void *Arg2
	);

typedef NTSTATUS(*Fn_DriverUnload)(
	void *Arg1
	);

class pe_image
{
private:
	void *_section_data;
	HANDLE _section_handle;

	IMAGE_DOS_HEADER *_dos_header;
	IMAGE_NT_HEADERS *_nt_header;

	bool _erase_header;

	bool allocate_section(size_t size);

	bool fix_iat();
	bool fix_base_relocation();

	uint32_t _image_size;

public:
	pe_image();
	pe_image(void *section_data, HANDLE section_handle);
	~pe_image();

	uint32_t image_size();

	/// <summary>
	/// 申请节内存，将pe数据拉伸复制到节内存中
	/// </summary>
	/// <param name="file_data">pe文件数据，可以是r3的内存</param>
	/// <param name="file_size">pe文件大小</param>
	bool load(void *file_data, size_t file_size);

	void unload();

	void erase_header();

	void *section_data();
	HANDLE section_handle();

	Fn_DriverEntry sys_ep();
};

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