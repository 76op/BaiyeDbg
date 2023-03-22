#pragma once
#include <cstdint>

enum BPM_TPYE
{
	BPM_TYPE_INVALID = 0,
	BPM_TYPE_SOFTWARE_BP = 0,
	BPM_TYPE_HADRWARE_BP = 0,
};

typedef struct _BPM_BREAKPOINT
{
	uint64_t DebugeeId;
	uint64_t DebuggerId;

	BPM_TPYE type;
};