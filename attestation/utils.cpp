//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#include "utils.h"

#include <string>
#include <iostream>
#include <stdexcept>
#include <stdlib.h>
#include <wil/resource.h>
#include <Windows.h>

using namespace std;

wil::unique_ncrypt_key load_tpm_key(const wstring& name, bool machine_key)
{
    wil::unique_ncrypt_prov tpm_prov{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(&tpm_prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0), "Error opening TPM provider.");

    wil::unique_ncrypt_key tpm_key{};
    THROW_IF_FAILED_MSG(NCryptOpenKey(tpm_prov.get(), &tpm_key, name.c_str(), 0, NCRYPT_SILENT_FLAG | (machine_key ? NCRYPT_MACHINE_KEY_FLAG : 0)), "Error opening TPM key.");

    return tpm_key;
}

static wil::unique_ncrypt_key create_key(PCWSTR provider_name, PCWSTR key_name, DWORD flags)
{
    wil::unique_ncrypt_prov provider_handle{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(
        &provider_handle,
        provider_name,
        0), "Error opening storage provider.");

    wil::unique_ncrypt_key key{};
    THROW_IF_FAILED_MSG(NCryptCreatePersistedKey(
        provider_handle.get(),
        &key,
        BCRYPT_RSA_ALGORITHM,
        key_name,
        0,
        flags), "Error creating key.");

    DWORD key_len = 2048;
    THROW_IF_FAILED_MSG(
        NCryptSetProperty(
            key.get(),
            NCRYPT_LENGTH_PROPERTY,
            reinterpret_cast<PBYTE>(&key_len),
            sizeof(key_len),
            0), "Error setting key length.");


    THROW_IF_FAILED_MSG(NCryptFinalizeKey(key.get(), 0), "Error finalizing key.");

    return key;
}

wil::unique_ncrypt_key create_tpm_key(const PCWSTR& name, bool machine_key)
{
    cout << "Creating TPM key...";

    wil::unique_ncrypt_key tpm_key = create_key(
        MS_PLATFORM_KEY_STORAGE_PROVIDER,
        name,
        NCRYPT_OVERWRITE_KEY_FLAG | (machine_key ? NCRYPT_MACHINE_KEY_FLAG : 0)
    );

    cout << " Done." << endl;

    return tpm_key;
}

wil::unique_ncrypt_key create_ephemeral_software_key()
{
    cout << "Creating ephemeral software key...";

    wil::unique_ncrypt_key ephemeral_software_key = create_key(
        MS_KEY_STORAGE_PROVIDER,
        NULL,
        0
    );

    cout << " Done." << endl; 
    
    return ephemeral_software_key;
}

void sample_log_listener(att_log_source source, att_log_level level, const char* message)
{
    att_log_level current_level = att_get_log_level();

    if (current_level >= level)
    {
        std::cout << "[LOG] " << message << std::endl;
    }
}

std::string get_env_var(const std::string& env)
{
    // Get length of env value.
    size_t len = 0;
    if (getenv_s(&len, nullptr, 0, env.c_str()) || len == 0)
    {
        throw std::runtime_error("Could not find environment variable: '" + std::string(env) + "'");
    }

    // Allocate using a string and get the value.
    std::string val(len, 0);
    if (getenv_s(&len, val.data(), val.size(), env.c_str()) || len == 0)
    {
        throw std::runtime_error("Could not read environment variable: '" + std::string(env) + "'");
    }

    // Remove last character of the string as getenv_s() stores null terminator.
    val.erase(val.end() - 1);

    return val;
}
