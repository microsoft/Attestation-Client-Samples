//*********************************************************
//
// Copyright (c) Microsoft. All rights reserved.
// This code is licensed under the MIT License (MIT).
// THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
// IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
// PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/*
    Defines the code that will be loaded into the VBS enclave.
--*/

#include "precomp.h"
#include "attest_enclave.h"

ULONG InitialCookie;

BOOL
DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD dwReason,
    _In_ LPVOID lpvReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpvReserved);

    if (dwReason == DLL_PROCESS_ATTACH) {
        InitialCookie = 0xDADAF00D;
    }

    return TRUE;
}

extern "C"
{

    __declspec(dllexport) void* CALLBACK sample_enclave_att_configure(void* param)
    {
        WCHAR String[32];
        swprintf_s(String, ARRAYSIZE(String), L"%s\n", L"att configure started");
        OutputDebugStringW(String);

        return enclave_att_configure(param, 0);
    }

    __declspec(dllexport) void* CALLBACK sample_enclave_att_create_session(void* param)
    {
        WCHAR String[32];
        swprintf_s(String, ARRAYSIZE(String), L"%s\n", L"att create session started");
        OutputDebugStringW(String);

        // any payload you want to put in the report which will get signed.
        enclave_attestation_property properties[1]{};
        properties[0]._name = "sample_enclave_property";
        properties[0]._value_type = enclave_attestation_property_type::enclave_attestation_property_type_string;
        properties[0]._string = "sample_enclave_string";

        return enclave_att_create_session(param, properties, 1, 0);
    }

    __declspec(dllexport) void* CALLBACK sample_enclave_att_attest(void* param)
    {
        WCHAR String[32];
        swprintf_s(String, ARRAYSIZE(String), L"%s\n", L"att attest started");
        OutputDebugStringW(String);

        return enclave_att_attest(param);
    }

    __declspec(dllexport) void* CALLBACK sample_enclave_att_get_report(void* param)
    {
        WCHAR String[32];
        swprintf_s(String, ARRAYSIZE(String), L"%s\n", L"att get report started");
        OutputDebugStringW(String);

        return enclave_att_get_report(param);
    }

    __declspec(dllexport) void* CALLBACK sample_enclave_att_close_session(void* param)
    {
        WCHAR String[32];
        swprintf_s(String, ARRAYSIZE(String), L"%s\n", L"att close session started");
        OutputDebugStringW(String);

        return enclave_att_close_session(param);
    }
}