//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#ifndef _ATT_SAMPLES_UTILS_H
#define _ATT_SAMPLES_UTILS_H

#include <string>
#include <wil/resource.h>

// Loads a key from the TPM using the Platform Key Storage Provider.
wil::unique_ncrypt_key load_tpm_key(const std::wstring& name, bool machine_key);

// Creates a 2048-bit RSA key in the TPM using the Platform Key Storage Provider.
wil::unique_ncrypt_key create_tpm_key(const PCWSTR& name, bool machine_key);

// Creates a 2048-bit ephemeral software key using the Software Key Storage Provider.
wil::unique_ncrypt_key create_ephemeral_software_key();

// Returns the value of an environment variable.
std::string get_env_var(const std::string& env);

// Creates an enclave based on the vbsenclave.dll compiled in the enclave directory.
LPVOID create_enclave();

// Returns a function pointer to the address of the specified function within the enclave.
LPENCLAVE_ROUTINE load_enclave_export(LPCSTR proc_name, LPVOID enclave_base);

#endif // _ATT_SAMPLES_UTILS_H
