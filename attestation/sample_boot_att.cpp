//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @brief This sample provides the code implementation to perform boot attestation,
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
#include <vector>
#include <iostream>

#include <att_manager.h>

using namespace std;

#define AIK_NAME L"att_sample_key"


wil::unique_ncrypt_key CreateKey(PCWSTR providerName, PCWSTR keyName, DWORD flags, bool finalize)
{
    wil::unique_ncrypt_prov provHandle{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(
        &provHandle,
        providerName,
        0), "NCryptOpenStorageProvider failed.");

    wil::unique_ncrypt_key key{};
    THROW_IF_FAILED_MSG(NCryptCreatePersistedKey(
        provHandle.get(),
        &key,
        BCRYPT_RSA_ALGORITHM,
        keyName,
        0,
        flags), "NCryptCreatePersistedKey failed.");

    DWORD keyLength = 2048;
    THROW_IF_FAILED_MSG(NCryptSetProperty(
        key.get(),
        NCRYPT_LENGTH_PROPERTY,
        (PBYTE)&keyLength,
        sizeof(keyLength),
        0), "NCryptSetProperty for key length failed.");

    SECURITY_DESCRIPTOR secDescr{};
    if (!InitializeSecurityDescriptor(&secDescr, SECURITY_DESCRIPTOR_REVISION))
    {
        wcout << L"InitializeSecurityDescriptor error: " << GetLastError();
        THROW_WIN32(GetLastError());
    }

    THROW_IF_FAILED_MSG(NCryptSetProperty(
        key.get(),
        NCRYPT_SECURITY_DESCR_PROPERTY,
        (PBYTE)&secDescr,
        sizeof(secDescr),
        DACL_SECURITY_INFORMATION), "NCryptSetProperty for security descriptor failed.");

    if (finalize)
    {
        THROW_IF_FAILED_MSG(NCryptFinalizeKey(key.get(), 0), "NCryptFinalizeKey failed.");
    }

    return key;
}


wil::unique_ncrypt_key _CreateAik(PCWSTR aikName)
{
    auto aik = CreateKey(MS_PLATFORM_KEY_STORAGE_PROVIDER, aikName, NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_MACHINE_KEY_FLAG, false);

    DWORD keyUsage = NCRYPT_PCP_IDENTITY_KEY;
    THROW_IF_FAILED(NCryptSetProperty(
        aik.get(),
        NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY,
        (PBYTE)&keyUsage,
        sizeof(keyUsage),
        0));

    THROW_IF_FAILED(NCryptFinalizeKey(aik.get(), 0));

    return aik;
}

int main()
{
    // TODO: Use relying party's id in the line below.
    string rp_id{ "https://contoso.com" };
    // TODO: Use relying party's per-session nonce below.
    vector<uint8_t> rp_nonce{ 'R', 'E','P','L','A','C','E',' ','W','I','T','H', ' ','R','P', ' ','N','O','N','C','E' };

    try
    {
        cout << "Attempting to genrerate the AIK Key" << endl;
        _CreateAik(AIK_NAME);
        cout << "Genrerated Key" << endl;

        auto tpm_aik = load_tpm_key(AIK_NAME, true);

        att_tpm_aik aik = ATT_TPM_AIK_NCRYPT(tpm_aik.get());

        att_session_params_tpm params
        {
            rp_nonce.data(), // relying_party_nonce
            rp_nonce.size(), // relying_party_nonce_size
            rp_id.c_str(),   // relying_party_unique_id
            &aik,            // aik
            nullptr,         // request_key
            nullptr,         // other_keys
            0                // other_keys_count
        };

        attest(params, "report_boot.jwt");
    }
    catch (const std::exception& ex)
    {
        cout << ex.what() << endl;
    }

    return 0;
}
