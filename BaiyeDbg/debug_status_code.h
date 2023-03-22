//
// Defining new debug status code
//
#pragma once
#include <ntstatus.h>

//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//


#define SEVERITY_DEBUGGER	(STATUS_SEVERITY_ERROR << 30)
#define CUSTOM_DEBUGGER		(1 << 29)
#define FACILITY_DEBUGGER	(0x100 << 16)

//
// MessageId: STATUS_ERROR_MULTI_DEBUGEE
//
// MessageText:
//
//  STATUS_ERROR_MULTI_DEBUGEE
//
#define STATUS_ERROR_MULTI_DEBUGEE	(NTSTATUS)(0x1 | SEVERITY_DEBUGGER | CUSTOM_DEBUGGER | FACILITY_DEBUGGER)

//
// MessageId: STATUS_ERROR_DEBUGEE_OBJECT_ALREADY_EXISTS
//
// MessageText:
//
//  STATUS_ERROR_DEBUGEE_OBJECT_ALREADY_EXISTS
//
#define STATUS_ERROR_DEBUGEE_OBJECT_ALREADY_EXISTS	(NTSTATUS)(0x2 | SEVERITY_DEBUGGER | CUSTOM_DEBUGGER | FACILITY_DEBUGGER)