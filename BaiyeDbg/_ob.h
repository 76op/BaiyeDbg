#pragma once
#include "_global.h"
#include "_kernel_struct.h"

// begin_ntosp
#define OBJECT_TO_OBJECT_HEADER( o ) \
    CONTAINING_RECORD( (o), OBJECT_HEADER, Body )
// end_ntosp