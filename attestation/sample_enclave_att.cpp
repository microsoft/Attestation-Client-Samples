// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @brief This sample provides the code implementation to perform VBS enclave attestation,
 * and retrieve an attestation token from Microsoft Azure Attestation.
 *
 * @remark The following environment variables must be set before running the sample.
 *
 * - AZURE_TENANT_ID:     Tenant ID for the Azure account. Used for authenticated calls to the attestation service.
 * - AZURE_CLIENT_ID:     The client ID to authenticate the request. Used for authenticated calls to the attestation service.
 * - AZURE_CLIENT_SECRET: The client secret. Used for authenticated calls to the attestation service.
 * - AZURE_MAA_URI:       Microsoft Azure Attestation provider's Attest URI (as shown in portal). Format is similar to "https://<ProviderName>.<Region>.attest.azure.net".
 *
 * In addition, a TPM attestation identity key named 'att_sample_aik' must be created. See README.md for instructions.
 *
 * Finally, a fixed relying party id and nonce are used in this sample. An application should obtain a per-session nonce from the relying party before making
 * the call to the attestation service. TODOs in the code below mark the locations to be updated.
 *
 */

#include "utils.h"
#include "attest.h"
#include <string>
#include <iostream>
#include <vector>

#include <att_manager.h>
#include <att_manager_logger.h>

using namespace std;

#define AIK_NAME L"att_sample_aik"

void sample_log_listener(att_log_source source, att_log_level level, const char* message)
{
    std::cout << "[LOG] " << message << std::endl;
}

// Creates an enclave based on the vbsenclave.dll compiled in the enclave/ diretory.
HRESULT create_enclave(LPVOID* enclave_base)
{
    ENCLAVE_CREATE_INFO_VBS create_info =
    {
        0,
        { 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F }
    };

    *enclave_base = CreateEnclave(GetCurrentProcess(),
        0,
        0x10000000,
        0,
        ENCLAVE_TYPE_VBS,
        &create_info,
        sizeof(create_info),
        nullptr);

    RETURN_LAST_ERROR_IF_NULL(*enclave_base);

    RETURN_IF_WIN32_BOOL_FALSE(LoadEnclaveImageW(*enclave_base, L"vbsenclave.dll"));


    ENCLAVE_INIT_INFO_VBS init_info =
    {
        sizeof(init_info),   // length
        1                    // thread_count
    };

    RETURN_IF_WIN32_BOOL_FALSE(InitializeEnclave(GetCurrentProcess(),
        *enclave_base,
        &init_info,
        init_info.Length,
        nullptr));

    return S_OK;
}

void log_and_exit_if_failed(HRESULT hr, LPCSTR message)
{
    if (FAILED(hr))
    {
        cout << message << endl << "HRESULT: " << hr << endl;
        exit(hr);
    }
}

void log_and_exit_if_null(LPENCLAVE_ROUTINE proc, LPCSTR message)
{

    if (proc == nullptr)
    {
        log_and_exit_if_failed(HRESULT_FROM_WIN32(GetLastError()), "GetProcAddress failed");
    }
}

// Returns a function pointer to the address of the specified function within the enclave.
LPENCLAVE_ROUTINE load_enclave_export(LPCSTR procName, LPVOID att_enclave_base)
{
    LPENCLAVE_ROUTINE function = reinterpret_cast<LPENCLAVE_ROUTINE>(GetProcAddress(reinterpret_cast<HMODULE>(att_enclave_base), procName));
    log_and_exit_if_null(function, procName);
    return function;
}

int __cdecl wmain(int, wchar_t* [])
{
    att_set_log_listener(sample_log_listener);
    att_set_log_level(att_log_level_telemetry);
    // TODO: Use relying party's id in the line below.
    string rp_id{ "https://contoso.com" };

    // TODO: Use relying party's per-session nonce below.
    vector<uint8_t> rp_nonce{ 'R', 'E','P','L','A','C','E',' ','W','I','T','H', ' ','R','P', ' ','N','O','N','C','E' };

    LPVOID enclave_base = nullptr;
    log_and_exit_if_failed(create_enclave(&enclave_base), "create_enclave failed.");

    try
    {
        auto tpm_aik = load_tpm_key(AIK_NAME, true);
        auto ephemeral_key = create_ephemeral_key();

        att_tpm_aik aik = ATT_TPM_AIK_NCRYPT(tpm_aik.get());
        att_tpm_key key = ATT_TPM_KEY_NCRYPT(ephemeral_key.get());

        att_enclave_function_table function_table = {
            load_enclave_export("sample_att_enclave_configure", enclave_base),
            load_enclave_export("sample_att_enclave_create_session", enclave_base),
            load_enclave_export("sample_att_enclave_attest", enclave_base),
            load_enclave_export("sample_att_enclave_get_report", enclave_base),
            load_enclave_export("sample_att_enclave_close_session", enclave_base),
        };

        att_session_params_enclave params
        {
            rp_nonce.data(),                      // relying_party_nonce
            rp_nonce.size(),                      // relying_party_nonce_size
            rp_id.c_str(),                        // relying_party_unique_id
            &aik,                                 // aik
            &key,                                 // request_key
            nullptr,                              // other_keys
            0,                                    // other_keys_count
            &function_table,                      // att_enclave_function_table
            ATT_ENCLAVE_FLAG_USE_VSM_MODE_ALWAYS  // att_enclave_flags
        };

        attest(ATT_SESSION_TYPE_ENCLAVE, &params, "report_enclave.jwt");
    }
    catch (const std::exception& ex)
    {
        cout << ex.what() << endl;
    }

    return 0;
}