// Copyright (c) Microsoft Corporation. All rights reserved.
//

#include <windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <winhttp.h>
#include <ncrypt.h>

#include <att_manager_api_enclave.h>
#include <att_manager_api.h>

#include <attest_enclave.h>
#include <attest.h>
#include <utils.h>

#define AIK_NAME L"att_sample_aik"

using namespace std;

typedef uint64_t ATTESTATION_SESSION_HANDLE;

// initialize_attestation_library configuration flags

// Always use VSM, it will fail ATT_ERROR_NOT_SUPPORTED if VSM is not supported
#define ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_VSM_MODE_ALWAYS       0x0

// Always use normal mode
#define ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_NORMAL_MODE_ALWAYS    0x1

// Use VSM mode if supported, otherwise use normal mode
#define ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_VSM_MODE_IF_SUPPORTED 0x2

void log_and_exit_if_failed(HRESULT hr, LPCWSTR message)
{
    if (FAILED(hr))
    {
        LPWSTR errorText = nullptr;
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&errorText,
            0,
            nullptr);

        std::wcout << message << std::endl << L"HRESULT: " << hr << std::endl;
        if (errorText)
        {
            std::wcout << L"Error: " << errorText << std::endl;
            LocalFree(errorText);
        }
        exit(hr);
    }
}

LPVOID g_enclave_base = nullptr;
 
// Creates an enclave based on the vbsenclave.dll compiled in the enclave/ diretory.
void create_enclave()
{
    ENCLAVE_CREATE_INFO_VBS create_info =
    {
        0,
        { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }
    };

    g_enclave_base = CreateEnclave(GetCurrentProcess(),
        0,
        0x10000000,
        0,
        ENCLAVE_TYPE_VBS,
        &create_info,
        sizeof(create_info),
        nullptr);

    if (g_enclave_base == nullptr)
    {
        log_and_exit_if_failed(HRESULT_FROM_WIN32(GetLastError()), L"CreateEnclave failed");
    }

    else if (!LoadEnclaveImageW(g_enclave_base, L"vbsenclave.dll"))
    {
        log_and_exit_if_failed(HRESULT_FROM_WIN32(GetLastError()), L"LoadEnclaveImage failed");
    }

    ENCLAVE_INIT_INFO_VBS init_info =
    {
        sizeof(init_info),   // length
		1                   // thread_count
    };

    if (!InitializeEnclave(GetCurrentProcess(),
        g_enclave_base,
        &init_info,
        init_info.Length,
        nullptr))
    {
        log_and_exit_if_failed(HRESULT_FROM_WIN32(GetLastError()), L"InitializeEnclave failed");
    }

}

// Returns a function pointer to the address of the specified function within the enclave.
LPENCLAVE_ROUTINE load_enclave_export(LPCSTR procName)
{
    LPENCLAVE_ROUTINE address = reinterpret_cast<LPENCLAVE_ROUTINE>(GetProcAddress(reinterpret_cast<HMODULE>(g_enclave_base), procName));
    if (address == nullptr)
    {
        log_and_exit_if_failed(HRESULT_FROM_WIN32(GetLastError()), L"GetProcAddress failed");
    }

    return address;
}

// Initializes the attestation functions. initialize_attestation_library takes in the function address pointers of the enclave
// functions and maps them such that when you call a normal mode attestation function, it will now call sample_enclave_att version
// of the function instead. This is to maintain the same attestation flow in both VTL0 and VTL1.
void initialize()
{
    enclave_attestation_init_library_configuration init_library_configuration{
            0,
            "att_sample_aik",
            {
                load_enclave_export("sample_enclave_att_configure"),
                load_enclave_export("sample_enclave_att_create_session"),
                load_enclave_export("sample_enclave_att_attest"),
                load_enclave_export("sample_enclave_att_get_report"),
                load_enclave_export("sample_enclave_att_close_session")
            }
    };

    log_and_exit_if_failed(initialize_attestation_library(&init_library_configuration), L"initialize_attestation_library failed");
}

int __cdecl wmain(int, wchar_t* [])
{
    auto tpm_aik = load_tpm_key(AIK_NAME, true);
    auto tpm_key = create_tpm_key(L"att_sample_key", false);

    att_tpm_aik aik = ATT_TPM_AIK_NCRYPT(tpm_aik.get());
    create_enclave();
    initialize();

    vector<BYTE> rp_custom_data{ 0x01, 0x02, 0x03, 0x04 };
    // TODO: Use relying party's id in the line below.
    string rp_id{ "https://contoso.com" };

    ATTESTATION_SESSION_HANDLE session_handle{};
    att_session session{};

    try
    {

        att_tpm_key key = ATT_TPM_KEY_VBS_NCRYPT(tpm_key.get());
        // TODO: Use relying party's per-session nonce below.
        vector<uint8_t> rp_nonce{ 'R', 'E','P','L','A','C','E',' ','W','I','T','H', ' ','R','P', ' ','N','O','N','C','E' };


        att_session_params_tpm params
        {
            rp_nonce.data(), // relying_party_nonce
            rp_nonce.size(), // relying_party_nonce_size
            rp_id.c_str(),   // relying_party_unique_id
            &aik,            // aik
            0,               // request_key
            nullptr,         // other_keys
            0                // other_keys_count
        };

        attest(params, "enclave-att-report.jwt", ATT_SESSION_TYPE_VBS);
    }
    catch (const std::exception& ex)
    {
        cout << ex.what() << endl;
    }

    return 0;
}