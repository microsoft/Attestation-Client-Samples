//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @brief This sample provides the code implementation to perform boot and TPM key attestation,
 * and retrieve an attestation token from Microsoft Azure Attestation.
 *
 * @remark The following environment variable must be set before running the sample.
 *
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
#include <att_manager_logger.h>

using namespace std;

#define AIK_NAME L"att_sample_aik"

int main()
{
    // Adjust log level to your desired level of output. 
    att_set_log_level(att_log_level_none);
    att_set_log_listener(sample_log_listener);

    // TODO: Use relying party's id in the line below.
    string rp_id{ "https://contoso.com" };
    // TODO: Use relying party's per-session nonce below.
    vector<uint8_t> rp_nonce{ 'R', 'E','P','L','A','C','E',' ','W','I','T','H', ' ','R','P', ' ','N','O','N','C','E' };

    try
    {
        auto tpm_aik = load_tpm_key(AIK_NAME, true);
        auto tpm_device_key = create_tpm_key(L"att_sample_deviceKey", false);
        auto tpm_idk = create_tpm_key(L"att_sample_IDK", false);
        auto tpm_stk = create_tpm_key(L"att_sample_STK", false);

        att_tpm_aik aik = ATT_TPM_AIK_NCRYPT(tpm_aik.get());
        att_tpm_key device_key = ATT_TPM_KEY_NCRYPT(tpm_device_key.get());
        att_tpm_key idk = ATT_TPM_KEY_NCRYPT(tpm_idk.get());
        att_tpm_key stk = ATT_TPM_KEY_NCRYPT(tpm_stk.get());

        att_tpm_key other_keys[] = { idk, stk };

        att_session_params_tpm params
        {
            rp_nonce.data(), // relying_party_nonce
            rp_nonce.size(), // relying_party_nonce_size
            rp_id.c_str(),   // relying_party_unique_id
            &aik,            // aik
            &device_key,     // request_key (deviceKey)
            other_keys,      // other_keys (IDK, STK)
            2                // other_keys_count
        };

        attest(ATT_SESSION_TYPE_TPM, &params, "report_key.jwt");
    }
    catch (const std::exception& ex)
    {
        cout << ex.what() << endl;
    }

    return 0;

    //
    // Notice that report will contain claim "x-ms-tpm-request-key", which includes the public part of the TPM key in the "jwk" field.
    // In addition, field "info" will contains "tpm_certify" indicating that a TPM key was certified. The fields inside "tpm_certify" attest to the TPM key properties. Those properties 
    // are described in Trusted Computing Group's TPM Library spec (https://trustedcomputinggroup.org/resource/tpm-library-specification/), Part 2: Structures, TPMT_PUBLIC. For example,
    // a relying party can verify that the key's object attributes have bits fixedTPM, fixedParent and sensitiveDataOrigin set to make sure the key was generated inside the TPM and cannot
    // be exported.
    //
}
