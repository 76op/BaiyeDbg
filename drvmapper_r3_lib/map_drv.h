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
	/// �ͷ�mapper drv
	/// </summary>
	/// <returns>drv·��</returns>
	static wchar_t *release_drv();

	/// <summary>
	/// ɾ��mapper drv
	/// </summary>
	/// <param name="drv_path">drv·��</param>
	static void delete_drv(wchar_t *drv_path);

	/// <summary>
	/// ����mapper drv
	/// </summary>
	/// <param name="reg_id"ע��id������ɾ��ע�����Ϣ></param>
	/// <returns>�Ƿ�ɹ�</returns>
	static bool load_drv1(const wchar_t *mapperdrv_path, uint32_t *reg_id);

	/// <summary>
	/// ж��mapper drv
	/// </summary>
	/// <param name="reg_id">ע��id������ɾ��ע�����Ϣ</param>
	/// <returns>�Ƿ�ɹ�</returns>
	static bool unload_drv1(const wchar_t *mapperdrv_path, uint32_t reg_id);

public:
	/// <summary>
	/// ���ر�mapper����
	/// </summary>
	/// <param name="sys_data">��������������</param>
	/// /// <param name="sys_size">������С</param>
	/// <param name="load_data">���غ���Ҫ���������</param>
	/// <returns>�Ƿ�ɹ�</returns>
	static bool load(const void *sys_data, size_t sys_size, pe_load_data_t *load_data);

	/// <summary>
	/// ж�ر�mapp������
	/// </summary>
	/// <param name="load_data">���غ���Ҫ���������</param>
	/// <returns>�Ƿ�ɹ�</returns>
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