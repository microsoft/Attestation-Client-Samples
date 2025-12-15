//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * WARNING: Information regarding VBS-Protected Keys relates to prerelease product that may be substantially modified before it's commercially released. 
 * Microsoft makes no warranties, express or implied, with respect to the information provided here.
 */

/**
 * @brief This sample provides the code implementation to perform VBS-Protected key attestation,
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
        auto vbs_protected_key = create_vbs_protected_key(L"att_sample_vbs_key", false);

        att_tpm_aik aik = ATT_TPM_AIK_NCRYPT(tpm_aik.get());
        att_tpm_key key = ATT_TPM_KEY_VBS_NCRYPT(vbs_protected_key.get());

        att_session_params_tpm params
        {
            rp_nonce.data(), // relying_party_nonce
            rp_nonce.size(), // relying_party_nonce_size
            rp_id.c_str(),   // relying_party_unique_id
            &aik,            // aik
            &key,            // request_key
            nullptr,         // other_keys
            0                // other_keys_count
        };

        attest(ATT_SESSION_TYPE_TPM, &params, "report_vbs_protected_key.jwt");
    }
    catch (const std::exception& ex)
    {
        cout << ex.what() << endl;
    }

    return 0;

    //
    // Notice that the report will contain the claim "x-ms-tpm-request-key", which includes the public part of the VBS-protected key in the "jwk" field.
    // In addition, the "info" section will contain "vbs_ncrypt", indicating that a VBS-protected key was certified. The fields inside "vbs_ncrypt" attest to the VBS-protected key properties.
    // These properties are described in the NCrypt library documentation (https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptverifyclaim#protectingattesting-private-keys-using-virtualization-based-security-vbs).
    // A relying party (RP) should validate several important fields inside "vbs_ncrypt.vbs_trustlet_report" to ensure the key was generated and protected inside a trusted VBS-protected environment:
    //
    //   trustlet_identity - Identifies the VBS trustlet that created or protects the key. The RP should compare this value against an expected trustlet identity to ensure the key originates from a trusted environment.
    //
    //   trustlet_svn - The security version number (SVN) of the trustlet. The RP should verify this meets its minimum required SVN.
    //
    //   flags.trustlet_debugged - Indicates whether the trustlet was debugged during key creation or protection. RPs should reject keys where this value is true, as debugged trustlets cannot be trusted.
    //
    //   trustlet_policy - A set of policy entries describing protections applied to the trustlet. For example, policy entry ID=2 determines whether the trustlet is debuggable. RPs should verify policy values to verify that the trustlet meets its security requirements.
    //
    // These validations allow a relying party to establish that the key is genuinely VBS-backed, it comes from the correct trustlet that has sufficient security level, the environment was not debugged or weakened, and policy constraints match the RP's requirements.
    //

    }