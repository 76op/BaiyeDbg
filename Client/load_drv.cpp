#include "pch.h"
#include "load_drv.h"
#include <map_drv.h>
#include "resource.h"

static pe_load_data_t load_data = { 0 };

bool load_drv::load()
{
	// ������Դ�ļ��С�������Դ���ڴ桢�õ���Դ��С
	HRSRC hrsc = FindResource(NULL, MAKEINTRESOURCE(IDR_DBG_SYS1), L"DBG_SYS");

	if (!hrsc)
	{
		MessageBox(NULL, L"δ�ҵ�DBG_SYS��Դ", 0, 0);
		return false;
	}

	HGLOBAL hG = LoadResource(NULL, hrsc);
	if (!hG) 
	{
		return false;
	}

	const void *sys_data = (const void *)LockResource(hG);
	size_t sys_size = SizeofResource(NULL, hrsc);

	return map_drv::load(sys_data, sys_size, &load_data);
}

void load_drv::unload()
{
	map_drv::unload(&load_data);
}