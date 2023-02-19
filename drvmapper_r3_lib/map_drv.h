#pragma once
#include <windows.h>
#include <string>

struct pe_file_t
{
	const void *file_data;
	size_t file_size;
};

struct pe_load_data_t
{
	void *section_data;
	size_t image_size;
	HANDLE section_handle;
	void *driver_unload;
};

class map_drv
{
private:
	static void create_directory(const std::wstring &dir);
	static int delete_directory(const  std::wstring &dir, bool del_subdir = true);

	/// <summary>
	/// 释放mapper drv
	/// </summary>
	/// <returns>drv路径</returns>
	static wchar_t *release_drv();

	/// <summary>
	/// 删除mapper drv
	/// </summary>
	/// <param name="drv_path">drv路径</param>
	static void delete_drv(wchar_t *drv_path);

	/// <summary>
	/// 加载mapper drv
	/// </summary>
	/// <param name="reg_id"注册id，用于删除注册表信息></param>
	/// <returns>是否成功</returns>
	static bool load_drv1(const wchar_t *mapperdrv_path, uint32_t *reg_id);

	/// <summary>
	/// 卸载mapper drv
	/// </summary>
	/// <param name="reg_id">注册id，用于删除注册表信息</param>
	/// <returns>是否成功</returns>
	static bool unload_drv1(const wchar_t *mapperdrv_path, uint32_t reg_id);

public:
	/// <summary>
	/// 加载被mapper驱动
	/// </summary>
	/// <param name="sys_data">驱动二进制数据</param>
	/// /// <param name="sys_size">驱动大小</param>
	/// <param name="load_data">加载后需要保存的数据</param>
	/// <returns>是否成功</returns>
	static bool load(const void *sys_data, size_t sys_size, pe_load_data_t *load_data);

	/// <summary>
	/// 卸载被mapp而驱动
	/// </summary>
	/// <param name="load_data">加载后需要保存的数据</param>
	/// <returns>是否成功</returns>
	static bool unload(pe_load_data_t *load_data);
};

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT *Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef VOID(*RtlInitUnicodeStringType)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef int (*type_RtlAdjustPrivilege)(int, bool, bool, bool *);
typedef int(*ZwLoadDriverType)(PUNICODE_STRING DriverServiceName);