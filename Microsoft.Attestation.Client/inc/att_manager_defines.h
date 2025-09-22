//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @file att_manager_defines.h
 *
 * @brief Defines macros, types, and constants used for attestation.
 *
 * @note You MUST NOT use any symbols (macros, functions, structures, enums, etc.)
 * prefixed with an underscore ('_') directly in your application code. These symbols
 * are part of the SDK's internal implementation and are subject to change in future
 * versions of the SDK which would break your code.
 */

#ifndef _ATT_MANAGER_DEFINES_H
#define _ATT_MANAGER_DEFINES_H

#ifndef STDCALL
#if defined(_WIN32)
#define STDCALL __stdcall
#elif defined(__GNUC__) && defined(__i386__)
#define STDCALL __attribute__((stdcall))
#else
#define STDCALL
#endif
#endif

#if !defined(_WIN32)
#define EXTERN_C extern "C"

#ifndef PENCLAVE_ROUTINE
typedef void* (STDCALL* PENCLAVE_ROUTINE)(void* lpThreadParameter);
#endif // PENCLAVE_ROUTINE

#ifndef LPENCLAVE_ROUTINE
typedef PENCLAVE_ROUTINE LPENCLAVE_ROUTINE;
#endif // LPENCLAVE_ROUTINE

#endif //_WIN32

#endif // _ATT_MANAGER_DEFINES_H
