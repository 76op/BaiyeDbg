#pragma once
#include "_global.h"

BOOLEAN IsValidPe(PVOID PeData, SIZE_T PeSize);

BOOLEAN FixIat(PVOID SectionData);
BOOLEAN FixBaseRelocation(PVOID SectionData);

NTSTATUS AllocSectionMemory(HANDLE *SectionHandle, PVOID *SectionData, PVOID *SectionAddress, SIZE_T Size);
VOID MapDriverCopy(PVOID PeData, SIZE_T PeSize, PVOID SectionAddress, SIZE_T Size);

BOOLEAN MapDriverInit(PVOID SysData, SIZE_T SysSize);