#pragma once

#ifndef _GLOBAL_H
#define _GLOBAL_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif

#include <cstdint>

#ifdef __cplusplus

extern "C"
{
#endif

#include <ntifs.h>
#include <ntdef.h>
#include <ntddstor.h>
#include <mountdev.h>
#include <ntddvol.h>
#include <ntstrsafe.h>
#include <ntimage.h>
#include <intrin.h>

#ifdef __cplusplus
}
#endif

#endif