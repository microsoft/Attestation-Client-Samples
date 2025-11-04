//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @brief This sample enclave provides entry points for attestation configuration, session management,
 * attestation, and report retrieval. These functions invoke the corresponding enclave
 * attestation routines in VTL1.
 *
 * This enclave is compiled with the enclave image that is defined in enclave.c into 
 * vbsenclave.dll. The enclave DLL is intended to be loaded and called by a normal mode application.
 * 
 * vbsenclave.dll must be signed before it is loaded in the enclave host. Please see the VBS Enclaves 
 * Development Guide for more details: https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide
 */

#include <winenclave.h>
#include "att_manager_api_enclave.h"


 // DllMain is the mandatory enclave entry point.
BOOL WINAPI DllMain(HINSTANCE hInstance,
    ULONG     ulReason,
    LPVOID    Reserved)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(ulReason);
    UNREFERENCED_PARAMETER(Reserved);

    return TRUE;
}

extern "C"
{
    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_configure(LPVOID param)
    {
        return att_enclave_configure(param, ATT_ENCLAVE_CONFIG_FLAGS_NONE);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_create_session(LPVOID param)
    {
        return att_enclave_create_session(param, nullptr, 0, 0);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_attest(LPVOID param)
    {
        return att_enclave_attest(param);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_get_report(LPVOID param)
    {
        return att_enclave_get_report(param);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_close_session(LPVOID param)
    {
        return att_enclave_close_session(param);
    }
}