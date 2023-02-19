#include "map_drv.h"
#include "resource.h"

#include <shlobj_core.h>
#include <cstdlib>

using namespace std;

wchar_t *map_drv::release_drv()
{
	// 获取释放目录
	wchar_t cdst[512] = { 0 };
	SHGetSpecialFolderPathW(nullptr, cdst, CSIDL_APPDATA, false);

	// 创建伪装目录
	wstring dst = cdst;
	dst = dst + L"\\360";
	delete_directory(dst);
	create_directory(dst);

	wstring mapperdrv_path = dst + L"\\360Anti.sys";

	//MessageBox(NULL, mapperdrv_path.c_str(), 0, 0);

	
	// 资源大小
	DWORD  dwWrite = 0;

	// 创建文件
	HANDLE hFile = CreateFileW(
		mapperdrv_path.c_str(),
		GENERIC_WRITE,
		FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_HIDDEN ,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, L"创建map_drv文件失败", 0, 0);
		return nullptr;
	}

	// 查找资源文件中、加载资源到内存、得到资源大小
	HRSRC hrsc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_DRV_MAP_SYS1), L"DRV_MAP_SYS");

	if (!hrsc)
	{
		MessageBox(NULL, L"未找到DRV_MAP_SYS资源", 0, 0);
		CloseHandle(hFile);
		return nullptr;
	}

	HGLOBAL hG = LoadResource(NULL, hrsc);
	DWORD  dwSize = SizeofResource(NULL, hrsc);

	// 写入文件
	WriteFile(hFile, hG, dwSize, &dwWrite, NULL);
	CloseHandle(hFile);
	
	wchar_t *ret_path = new wchar_t[1024];
	memset(ret_path, 0, 1024 * sizeof(wchar_t));
	wcscpy_s(ret_path, 1024, mapperdrv_path.c_str());
	
	return ret_path;
}

void map_drv::delete_drv(wchar_t *drv_path)
{
	DeleteFile(drv_path);
	delete[] drv_path;
}

bool map_drv::load_drv1(const wchar_t *mapperdrv_path, uint32_t *reg_id)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll)
	{
		return false;
	}

	RtlInitUnicodeStringType RtlInitUnicodeString = (RtlInitUnicodeStringType)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	type_RtlAdjustPrivilege RtlAdjustPrivilege = (type_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
	ZwLoadDriverType ZwLoadDriver = (ZwLoadDriverType)GetProcAddress(hNtdll, "ZwLoadDriver");
	ZwLoadDriverType ZwUnloadDriver = (ZwLoadDriverType)GetProcAddress(hNtdll, "ZwUnloadDriver");

	FreeLibrary(hNtdll);


	if (!RtlInitUnicodeString)
	{
		return false;
	}

	if (!RtlAdjustPrivilege)
	{
		return false;
	}

	if (!ZwLoadDriver || !ZwUnloadDriver)
	{
		return false;
	}

	bool WasPrivilegeEnabled = FALSE;

	NTSTATUS st1 = RtlAdjustPrivilege(10,   // SE_LOAD_DRIVER_PRIVILEGE
		TRUE,
		FALSE,
		&WasPrivilegeEnabled);

	if ((st1 & 0x80000000) != 0)
	{
		return false;
	}


	NTSTATUS St = 0;
	BOOL bRet = FALSE;
	HKEY hKey;
	WCHAR chRegPath[MAX_PATH];
	WCHAR wcLoadDrv[MAX_PATH];
	WCHAR chImagePath[MAX_PATH] = L"\\??\\";
	UNICODE_STRING usStr;
	DWORD dwType;

	const wchar_t *chSysPath = mapperdrv_path;

	DWORD dwId = (DWORD)GetTickCount64();

	*reg_id = dwId;

	_snwprintf_s(chRegPath, RTL_NUMBER_OF(chRegPath) - 1, L"system\\currentcontrolset\\services\\%x", dwId);
	_snwprintf_s(wcLoadDrv, RTL_NUMBER_OF(wcLoadDrv) - 1, L"\\registry\\machine\\system\\currentcontrolset\\services\\%x", dwId);

	wcsncat_s(chImagePath, chSysPath, sizeof(chImagePath));
	MessageBox(NULL, chSysPath, NULL, 0);
	if (RegCreateKey(HKEY_LOCAL_MACHINE, chRegPath, &hKey) == ERROR_SUCCESS)
	{
		RegSetValueEx(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (LPBYTE)&chImagePath, wcslen(chImagePath) * 2);

		dwType = SERVICE_KERNEL_DRIVER;
		RegSetValueEx(hKey, L"Type", 0, REG_DWORD, (LPBYTE)&dwType, sizeof(DWORD));

		dwType = SERVICE_DEMAND_START;
		RegSetValueEx(hKey, L"Start", 0, REG_DWORD, (LPBYTE)&dwType, sizeof(DWORD));

		RegCloseKey(hKey);

		RtlInitUnicodeString(&usStr, wcLoadDrv);
		St = ZwLoadDriver(&usStr);

		if ((St & 0x80000000) != 0)
		{
			return false;
		}
	}

	return true;
}

bool map_drv::unload_drv1(const wchar_t *mapperdrv_path, uint32_t reg_id)
{
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll)
	{
		return false;
	}

	RtlInitUnicodeStringType RtlInitUnicodeString = (RtlInitUnicodeStringType)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	type_RtlAdjustPrivilege RtlAdjustPrivilege = (type_RtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
	ZwLoadDriverType ZwLoadDriver = (ZwLoadDriverType)GetProcAddress(hNtdll, "ZwLoadDriver");
	ZwLoadDriverType ZwUnloadDriver = (ZwLoadDriverType)GetProcAddress(hNtdll, "ZwUnloadDriver");

	FreeLibrary(hNtdll);


	if (!RtlInitUnicodeString)
	{
		return false;
	}

	if (!RtlAdjustPrivilege)
	{
		return false;
	}

	if (!ZwLoadDriver || !ZwUnloadDriver)
	{
		return false;
	}

	bool WasPrivilegeEnabled = FALSE;

	NTSTATUS st1 = RtlAdjustPrivilege(10,   // SE_LOAD_DRIVER_PRIVILEGE
		TRUE,
		FALSE,
		&WasPrivilegeEnabled);

	if ((st1 & 0x80000000) != 0)
	{
		return false;
	}

	NTSTATUS St = 0;
	BOOL bRet = FALSE;
	HKEY hKey;
	WCHAR chRegPath[MAX_PATH];
	WCHAR wcLoadDrv[MAX_PATH];
	WCHAR chImagePath[MAX_PATH] = L"\\??\\";
	UNICODE_STRING usStr;
	DWORD dwType;

	const wchar_t *chSysPath = mapperdrv_path;

	DWORD dwId = reg_id;

	_snwprintf_s(chRegPath, RTL_NUMBER_OF(chRegPath) - 1, L"system\\currentcontrolset\\services\\%x", dwId);
	_snwprintf_s(wcLoadDrv, RTL_NUMBER_OF(wcLoadDrv) - 1, L"\\registry\\machine\\system\\currentcontrolset\\services\\%x", dwId);

	RtlInitUnicodeString(&usStr, wcLoadDrv);
	St = ZwUnloadDriver(&usStr);

	RegDeleteKey(HKEY_LOCAL_MACHINE, chRegPath);

	if ((St & 0x80000000) != 0)
	{
		return false;
	}

	return true;
}

const WCHAR *symbol_name_md = L"\\\\.\\baiye_md";
#define IO_CTL_SYSLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 2048, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_CTL_SYSUNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 2049, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#include <fstream>
#include <iostream>
using namespace std;

bool map_drv::load(const void *sys_data, size_t sys_size, pe_load_data_t *load_data)
{
	wchar_t *mapperdrv_path = map_drv::release_drv();
	if (!mapperdrv_path) return false;

	uint32_t reg_id;
	if (!map_drv::load_drv1(mapperdrv_path, &reg_id))
	{
		MessageBox(NULL, L"加载MAP Driver失败", NULL, 0);
		map_drv::delete_drv(mapperdrv_path);
		return false;
	}

	HANDLE hDriver = NULL;

	// 打开驱动通讯
	hDriver = CreateFileW(symbol_name_md, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0); // IRP_MJ_CREATE
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		map_drv::unload_drv1(mapperdrv_path, reg_id);
		map_drv::delete_drv(mapperdrv_path);

		MessageBox(NULL, L"驱动通讯打开失败", NULL, 0);
		return false;
	}

	//// 读取文件
	//ifstream fin(sys_path, ios::binary);
	//fin.seekg(0, std::ios::end);
	//size_t file_size = fin.tellg();
	//fin.seekg(0, std::ios::beg);

	//char *file_data = new char[file_size];
	//fin.read(file_data, file_size);

	// 定义通讯数据
	pe_file_t pe_file{ sys_data , sys_size };


	pe_load_data_t pld;

	// 加载驱动
	DWORD Bytes;
	if (!DeviceIoControl(hDriver, IO_CTL_SYSLOAD,
		&pe_file, sizeof(pe_file_t), // 发送
		&pld, sizeof(pe_load_data_t), // 接收，不接收可以填NULL
		&Bytes, 0))
	{
		MessageBox(NULL, L"DeviceIoControl 加载驱动失败", NULL, 0);

		CloseHandle(hDriver); // IRP_MJ_CLOSE
		map_drv::unload_drv1(mapperdrv_path, reg_id);
		map_drv::delete_drv(mapperdrv_path);
		return false;
	}

	//// sys 加载完后删除文件数据
	//delete[] file_data;

	*load_data = pld;

	CloseHandle(hDriver); // IRP_MJ_CLOSE
	map_drv::unload_drv1(mapperdrv_path, reg_id);
	map_drv::delete_drv(mapperdrv_path);

	return true;
}


bool map_drv::unload(pe_load_data_t *load_data)
{
	wchar_t *mapperdrv_path = map_drv::release_drv();
	if (!mapperdrv_path) return false;

	uint32_t reg_id;
	if (!map_drv::load_drv1(mapperdrv_path, &reg_id))
	{
		map_drv::delete_drv(mapperdrv_path);
		return false;
	}

	HANDLE hDriver = NULL;

	// 打开驱动通讯
	hDriver = CreateFileW(symbol_name_md, GENERIC_ALL, 0, 0, OPEN_EXISTING, 0, 0); // IRP_MJ_CREATE
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		map_drv::unload_drv1(mapperdrv_path, reg_id);
		map_drv::delete_drv(mapperdrv_path);

		return false;
	}

	// 加载驱动
	DWORD Bytes;
	if (!DeviceIoControl(hDriver, IO_CTL_SYSUNLOAD,
		load_data, sizeof(pe_load_data_t), // 发送
		nullptr, 0, // 接收，不接收可以填NULL
		&Bytes, 0))
	{
		CloseHandle(hDriver); // IRP_MJ_CLOSE
		map_drv::unload_drv1(mapperdrv_path, reg_id);
		map_drv::delete_drv(mapperdrv_path);

		return false;
	}

	CloseHandle(hDriver); // IRP_MJ_CLOSE
	map_drv::unload_drv1(mapperdrv_path, reg_id);
	map_drv::delete_drv(mapperdrv_path);

	return true;
}

void map_drv::create_directory(const wstring &dir)
{
	if (CreateDirectoryW(dir.c_str(), NULL))
	{
		SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_HIDDEN);
	}
}

int map_drv::delete_directory(const wstring &dir, bool del_subdir)
{
	bool            bSubdirectory = false;       // Flag, indicating whether
											   // subdirectories have been found
	HANDLE           hFile;                       // Handle to directory
	wstring          strFilePath;                 // Filepath
	wstring          strPattern;                  // Pattern
	WIN32_FIND_DATAW FileInformation;             // File information


	strPattern = dir + L"\\*.*";
	hFile = FindFirstFileW(strPattern.c_str(), &FileInformation);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (FileInformation.cFileName[0] != '.')
			{
				strFilePath.erase();
				strFilePath = dir + L"\\" + FileInformation.cFileName;

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (del_subdir)
					{
						// Delete subdirectory
						int iRC = delete_directory(strFilePath, del_subdir);
						if (iRC)
							return iRC;
					}
					else
						bSubdirectory = true;
				}
				else
				{
					// Set file attributes
					if (SetFileAttributesW(strFilePath.c_str(),
						FILE_ATTRIBUTE_NORMAL) == FALSE)
						return GetLastError();

					// Delete file
					if (DeleteFileW(strFilePath.c_str()) == FALSE)
						return GetLastError();
				}
			}
		} while (FindNextFileW(hFile, &FileInformation) == TRUE);

		// Close handle
		FindClose(hFile);

		DWORD dwError = GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return dwError;
		else
		{
			if (!bSubdirectory)
			{
				// Set directory attributes
				if (SetFileAttributesW(dir.c_str(),
					FILE_ATTRIBUTE_NORMAL) == FALSE)
					return GetLastError();

				// Delete directory
				if (RemoveDirectoryW(dir.c_str()) == FALSE)
					return GetLastError();
			}
		}
	}

	return 0;
}