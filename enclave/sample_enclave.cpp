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

#include "precomp.h"
#include "att_manager_api_enclave.h"

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

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_configure(void* param)
    {
        return att_enclave_configure(param, 0);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_create_session(void* param)
    {
        // any payload you want to put in the report which will get signed.
        att_enclave_property properties[1]{};
        properties[0].name = "sample_enclave_property";
        properties[0].value_type = ATT_ENCLAVE_PROPERTY_TYPE_STRING;
        properties[0].string_value = "sample_enclave_string";

        return att_enclave_create_session(param, properties, 1, 0);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_attest(void* param)
    {
        return att_enclave_attest(param);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_get_report(void* param)
    {
        return att_enclave_get_report(param);
    }

    __declspec(dllexport) LPVOID WINAPI sample_att_enclave_close_session(void* param)
    {
        return att_enclave_close_session(param);
    }
}