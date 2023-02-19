#pragma once

#ifdef DBG 
#define Log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "#%d [BaiyeDbg]: " format "\n", KeGetCurrentProcessorNumberEx(0), ##__VA_ARGS__)
#else
#define Log(format, ...)
#endif // DBG 