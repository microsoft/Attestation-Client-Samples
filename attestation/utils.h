//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#ifndef _ATT_SAMPLES_UTILS_H
#define _ATT_SAMPLES_UTILS_H

#include <string>
#include <wil/resource.h>

#include <att_manager_logger.h>

// Loads a key from the TPM using the Platform Key Storage Provider.
wil::unique_ncrypt_key load_tpm_key(const std::wstring& name, bool machine_key);

// Creates a 2048-bit RSA key in the TPM using the Platform Key Storage Provider.
wil::unique_ncrypt_key create_tpm_key(const std::wstring& name, bool machine_key);

// Creates an ephemeral software key.
wil::unique_ncrypt_key create_ephemeral_key();

// Creates a 2048-bit RSA key
wil::unique_ncrypt_key create_key(PCWSTR providerName, const std::wstring& keyName, DWORD flags, bool finalize);

// Creates a sample log listener to enable logging from the MAA SDK.
void sample_log_listener(att_log_source source, att_log_level level, const char* message);

// Returns the value of an environment variable.
std::string get_env_var(const std::string& env);

#endif // _ATT_SAMPLES_UTILS_H
