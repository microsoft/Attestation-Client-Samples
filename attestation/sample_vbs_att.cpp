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

//
// attestation_configure and attestation_call are address pointers to the export functions exposed by the enclave
// See attest_enclave.h for more detail
//
struct ENCLAVE_ATTESTATION_FUNCTION_TABLE
{
    LPENCLAVE_ROUTINE attestation_configure;
    LPENCLAVE_ROUTINE attestation_create_session;
    LPENCLAVE_ROUTINE attestation_attest;
    LPENCLAVE_ROUTINE attestation_get_report;
    LPENCLAVE_ROUTINE attestation_close_session;
};

// attestation_flag is optional and can be 0. It is used to override the default behavior which is ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_VSM_MODE_ALWAYS flag
//            Currently supports:
//                ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_VSM_MODE_ALWAYS
//                ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_NORMAL_MODE_ALWAYS
//                ENCLAVE_ATTESTATION_INIT_LIBRARY_USE_VSM_MODE_IF_SUPPORTED
// attestation_identity_key_name is optional and can be NULL. If it's NULL, "Windows AIK" will be used.
// attestation_function_table is required. See enclave_attestation_function_table definition for more detail.
struct ENCLAVE_ATTESTATION_INIT_LIBRARY_CONFIGURATION
{
    uint32_t                              attestation_flag;
    const char*                           attestation_identity_key_name;
    enclave_attestation_function_table    attestation_function_table;
};

struct enclave_attestation_callback_function_table
{
    uint32_t          version;
    LPENCLAVE_ROUTINE allocate_params;
    LPENCLAVE_ROUTINE allocate_memory;
    LPENCLAVE_ROUTINE free_memory;
    LPENCLAVE_ROUTINE get_tcg_log;
    LPENCLAVE_ROUTINE trace_log;
    LPENCLAVE_ROUTINE get_metadata;
    LPENCLAVE_ROUTINE get_key_info;
    LPENCLAVE_ROUTINE sign_hash;
};

struct enclave_attestation_configure_params
{
    size_t size;

    // Input params.
    enclave_attestation_callback_function_table callback_function_able;
};

struct create_session_params
{
    size_t size;

    // Input params.
    const uint8_t* relying_party_custom_data;
    uint32_t relying_party_custom_data_size;
    const char* relying_party_unique_id;
    uint32_t relying_party_unique_id_size;
    uint32_t session_flags;
    const att_tpm_aik* attestation_identity_key;
    const att_tpm_key* request_key;
    const att_tpm_key* other_keys;
    uint32_t other_keys_count;

    // Output params.
    ATTESTATION_SESSION_HANDLE attestation_session_handle;
};

struct enclave_attestation_create_session_params
{
    create_session_params params;
    enclave_attestation_property* enclave_properties;
    uint32_t enclave_properties_size;
    uint32_t flags;
};

struct enclave_attestation_attest_params
{
    size_t size;

    // Input params.
    ATTESTATION_SESSION_HANDLE attestation_session_handle;
    const UINT8* input;
    UINT32 input_size;

    // Output params.
    uint8_t* output;
    UINT32 buffer_size;
    UINT32 output_size;
    bool complete;
};

struct enclave_attestation_get_report_params
{
    size_t size;

    // Input params.
    ATTESTATION_SESSION_HANDLE attestation_session_handle;

    // Output params.
    uint8_t* report;
    uint32_t buffer_size;
    uint32_t report_size;
};

struct enclave_attestation_close_session_params
{
    size_t size;

    // Input params.
    ATTESTATION_SESSION_HANDLE attestation_session_handle;
};


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



wil::unique_ncrypt_key create_key(PCWSTR provider_name, PCWSTR key_name, DWORD flags, bool finalize)
{
    wil::unique_ncrypt_prov prov_handle{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(
        &prov_handle,
        provider_name,
        0), "NCryptOpenStorageProvider failed.");

    wil::unique_ncrypt_key key{};
    THROW_IF_FAILED_MSG(NCryptCreatePersistedKey(
        prov_handle.get(),
        &key,
        BCRYPT_RSA_ALGORITHM,
        key_name,
        0,
        flags), "NCryptCreatePersistedKey failed.");

    DWORD key_length = 2048;
    THROW_IF_FAILED_MSG(NCryptSetProperty(
        key.get(),
        NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&key_length,
        sizeof(key_length),
        0), "NCryptSetProperty for key length failed.");

    SECURITY_DESCRIPTOR sec_descr{};
    if (!InitializeSecurityDescriptor(&sec_descr, SECURITY_DESCRIPTOR_REVISION))
    {
        log_and_exit_if_failed(GetLastError(), L"InitializeSecurityDescriptor error: 0x%d");
        THROW_WIN32(GetLastError());
    }

    THROW_IF_FAILED_MSG(NCryptSetProperty(
        key.get(),
        NCRYPT_SECURITY_DESCR_PROPERTY,
        (PBYTE)&sec_descr,
        sizeof(sec_descr),
        DACL_SECURITY_INFORMATION), "NCryptSetProperty for security descriptor failed.");

    if (finalize)
    {
        THROW_IF_FAILED_MSG(NCryptFinalizeKey(key.get(), 0), "NCryptFinalizeKey failed.");
    }

    return key;
}

LPVOID g_enclave_base = nullptr;

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

LPENCLAVE_ROUTINE load_enclave_export(LPCSTR procName)
{
    LPENCLAVE_ROUTINE address = reinterpret_cast<LPENCLAVE_ROUTINE>(GetProcAddress(reinterpret_cast<HMODULE>(g_enclave_base), procName));
    if (address == nullptr)
    {
        log_and_exit_if_failed(HRESULT_FROM_WIN32(GetLastError()), L"GetProcAddress failed");
    }

    return address;
}

void initialize()
{
    ENCLAVE_ATTESTATION_INIT_LIBRARY_CONFIGURATION init_library_configuration{
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


uint8_t* get_report(const ATTESTATION_SESSION_HANDLE& session_handle)
{
    UINT32 outputSize = 0;

    enclave_attestation_get_report_params params;
    params.attestation_session_handle = session_handle;
    params.report = nullptr;
    params.buffer_size = 0;
    params.report_size = 0;
    params.size = sizeof(enclave_attestation_get_report_params);

    uint8_t* report = nullptr;
    size_t report_size = 0;
    att_result hr = att_get_report(session_handle, &report, &report_size);
    string file_name = "enclave-att-report.jwt";
    if (!file_name.empty())
    {
        ofstream out(file_name, ios::binary);
        out.write(reinterpret_cast<char*>(report), report_size);
        cout << "Report saved to " << file_name << "." << endl;
    }
    return report;
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

#ifdef ATTESTV1
        log_and_exit_if_failed(att_create_session(rp_custom_data.data(), (UINT32)rp_custom_data.size(), rp_id.c_str(), (UINT32)rp_id.size() + 1, 0, &session_handle),
            L"CreateSession failed.");
#else
        att_result hr = att_create_session(ATT_SESSION_TYPE_VBS, &params, &session);
        log_and_exit_if_failed(hr, L"CreateSession failed.");

#endif
    }
    catch (const std::exception& ex)
    {
        cout << ex.what() << endl;
    }

    bool complete = false;
    vector<uint8_t> received_from_server{};

    while (!complete)
    {
        att_buffer send_to_server = nullptr;
        size_t send_to_server_size = 0;
        att_result hr = att_attest(session.get(), received_from_server.data(), received_from_server.size(), &send_to_server, &send_to_server_size, &complete);
        log_and_exit_if_failed(hr, L"att_attest");
        if (send_to_server_size > 0)
        {
            received_from_server = send_to_att_service(send_to_server.get(), send_to_server_size);
        }
    }

    wcout << L"Attestation is complete." << endl;

    uint8_t* report = get_report(session.get());
    wcout << L"report with size " << sizeof(report) << L" can now be sent to the replying party for parsing" << endl;

    return 0;
}