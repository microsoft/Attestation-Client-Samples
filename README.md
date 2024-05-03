# Samples for TPM-based attestation using Microsoft Azure Attestation

These code samples show how attestation can be performed using the TPM. Additionally the sample takes advantage of the https://www.nuget.org/packages/Microsoft.Attestation.Client

## List of Samples

### **Boot attestation (sample_boot_att.exe)**

This sample provides the code implementation to perform boot attestation, and retrieve an attestation token from Microsoft Azure Attestation.

### **TPM key attestation (sample_tpm_key_att.exe)**

This sample provides the code implementation to perform boot and TPM key attestation, and retrieve an attestation token from Microsoft Azure Attestation.
This sample creates a TPM key named "att_sample_key" which is attested by Microsoft Azure Attestation. The creation of a TPM key may take up to a few minutes depending on the TPM hardware.

### **VBS Ncrypt key attestation (sample_vbs_ncrypt_att.exe)**

This sample provides the code implementation to perform VBS NCrypt key attestation, and retrieve an attestation token from Microsoft Azure Attestation.
This sample creates a VBS NCrypt key named "att_sample_key" which is attested by Microsoft Azure Attestation.

## Sample Requirements

* The machine must have a Trusted Platform Module (TPM).

* The following environment variables must be set by the user:

    * **AZURE_TENANT_ID** - Tenant ID for the Azure account. Used for authenticated calls to the attestation service.
    * **AZURE_CLIENT_ID** - The client ID to authenticate the request. Used for authenticated calls to the attestation service.
    * **AZURE_CLIENT_SECRET** - The client secret. Used for authenticated calls to the attestation service.
    * **AZURE_MAA_URI** - Microsoft Azure Attestation provider's Attest URI (as shown in portal). Format is similar to "https://\<ProviderName\>.\<Region\>.attest.azure.net".

* An AIK named "att_sample_aik" must be available. Run the EnrollAik.ps1 script to create the key and retrieve an AIK certificate for it (notice that the command below allows the key to be accessed by all users on the machine):

        EnrollAik.ps1 att_sample_aik BUILTIN\Users

## Running attestation samples

1. Set up an Azure Attestation provider with a **TPM** policy using the instructions at https://docs.microsoft.com/en-us/azure/attestation/quickstart-portal.
2. Build the project (it can be built by opening the folder in Visual Studio 2022).
3. Make sure the sample requirements above are met.
4. Run one of the samples listed above.

## EnrollAik.ps1

This script automates the process of generating an Attestation Identity Key (AIK). It invokes the Cert Request utility which is provided as part of Windows and requests that a new key be generated in the TPM. It then registers this key with the certificate service and gets an AIK certificate that can then be used in the attestation flow. The script also provides an option to set the ACL on the key file (used by the Platform/TPM Key Storage Provider) such that it can be loaded from a user-mode process, as otherwise administrator privileges would be required for the client attestation application. 

Note: EnrollAik.ps1 won't be able to get an AIK certificate on a virtual machine because a virtual TPM does not have a trusted Endorsement Key certificate which is used by Azure Certificate Services to validate the TPM.

## References

* Microsoft Azure Attestation: https://learn.microsoft.com/en-us/azure/attestation/
* TPM attestation: https://learn.microsoft.com/en-us/azure/attestation/tpm-attestation-concepts
* Attestation policy: https://learn.microsoft.com/en-us/azure/attestation/policy-version-1-2
* Trusted Computing Group TPM 2.0 Spec: https://trustedcomputinggroup.org/resource/tpm-library-specification/

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
