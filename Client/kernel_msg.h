#pragma once
#include <cstdint>

enum class MSG_STATE
{
	NORMAL,
	OPEN_ERROR,
	OPENED,
	CLOSED,
};

struct add_debugger_t
{
	uint64_t debugger_pid;
	uint64_t debugee_pid;
};

struct hook_r3_t
{
	uint64_t process_id;
	void *address;
	void *fake_page;
};

struct allocate_vm_t
{
	uint64_t process_id;
	void *base_address;
};

class kernel_msg
{
public:
	kernel_msg();
	~kernel_msg();

	bool start_debugger(uint64_t debugger_pid, uint64_t debugee_pid);

	bool hook_r3(uint64_t process_id, void *address, void *fake_page);

	bool allocate_vm(uint64_t process_id, void **address);

private:
	HANDLE msg_handle = nullptr;
	MSG_STATE msg_state = MSG_STATE::NORMAL;

	bool is_open()
	{
		return msg_state == MSG_STATE::OPENED;
	};

	bool send_message(uint32_t control_code, void *in_buffer, size_t in_size, void *out_bufer, size_t out_size);

};