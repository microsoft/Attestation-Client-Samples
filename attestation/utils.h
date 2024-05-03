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
wil::unique_ncrypt_key create_tpm_key(const std::wstring& name, bool machine_key);

// Creates a 2048-bit RSA key
wil::unique_ncrypt_key create_key(PCWSTR providerName, const std::wstring& keyName, DWORD flags, bool finalize);

// Returns true if a Key Guard key can be created.
bool CanCreateKeyGuardKey();

// Returns the value of an environment variable.
std::string get_env_var(const std::string& env);

#endif // _ATT_SAMPLES_UTILS_H
