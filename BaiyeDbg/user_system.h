#pragma once

#include "hooklib.h"
#include <list>

/// <summary>
/// hook被调试进程r3的函数
/// </summary>

struct user_hook_t
{
	uint64_t process_id;

	void *original_va;
	void *original_pa;

	void *fake_va;
	void *fake_pa;
};

struct hook_page_t
{
	uint64_t original_pa;
	uint64_t fake_pa;
};


class user_system
{
private:
	static std::list<user_hook_t> *user_hooks;

	static user_hook_t *h_DbgUiRemoteBreakin;

public:
	static void initialize();
	static void destory();

	static void hook_r3(uint64_t process_id, void *address);
};

