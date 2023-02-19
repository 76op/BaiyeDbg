#pragma once
#include "hypercall.h"

#define EXEC_CODE_LENGTH 64

#pragma pack(push,1)
struct hook_opcodes_t
{
    uint8_t push;
    uint32_t low_part;
    uint8_t mov_rsp[4];
    uint32_t high_part;
    uint8_t ret;
};

struct jmp_opcodes_t
{
    void *bridge_addr;
    uint8_t orig[EXEC_CODE_LENGTH];
    //uint16_t mov;
    //uint64_t jmp_addr;
    //uint16_t jmp;
    uint8_t push;
    uint32_t low_part;
    uint8_t mov_rsp[4];
    uint32_t high_part;
    uint8_t ret;
};

//
// Usage:
// NtOpenProcessFn fn = (NtOpenProcessFn)vt_hook->hook_struct->jmp_opcodes.bridge_addr;
// return fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
//
struct hook_struct_t
{
    uint64_t addr;
    hook_opcodes_t hook_opcodes;
    uint8_t orig[sizeof(hook_opcodes_t)];
    jmp_opcodes_t jmp_opcodes;
    uint32_t exec_code_length;
};
#pragma pack(pop)

namespace hooklib
{
    hook_struct_t *hook_with_fake(void *original_api, void *fake_api, void *newfunc, uint32_t exec_code_length);

    void unhook(hook_struct_t *hook_struct, bool free = true);
}

namespace hyper
{
    // hook 时可能会出现多个函数在同一个页的问题
    // 该结构体用来解决这个问题
    struct page_ref_t
    {
        uint64_t original_va;     // 4kb对齐
        uint64_t fake_va;         // 4kb对齐

        uint64_t original_pa;
        uint64_t fake_pa;

        uint32_t ref_count;         // 引用计数
    };

	struct ept_hook_t
	{
		hook_struct_t *hook_struct;

		// hook 的函数地址
		uint64_t api_addr;

        hyper::page_ref_t *page_ref;

		void *bridge()
		{
			return this->hook_struct->jmp_opcodes.bridge_addr;
		}
	};

    ept_hook_t *hook(void *original_api, void *new_api);

    void unhook(ept_hook_t *ept_hook);
}

using hyper_hook_t = hyper::ept_hook_t;