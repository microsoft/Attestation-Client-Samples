//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#include "utils.h"

#include <string>
#include <iostream>
#include <stdexcept>
#include <stdlib.h>

using namespace std;

wil::unique_ncrypt_key load_tpm_key(const wstring& name, bool machine_key)
{
    wil::unique_ncrypt_prov tpm_prov{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(&tpm_prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0), "Error opening TPM provider.");

    wil::unique_ncrypt_key tpm_key{};
    THROW_IF_FAILED_MSG(NCryptOpenKey(tpm_prov.get(), &tpm_key, name.c_str(), 0, NCRYPT_SILENT_FLAG | (machine_key ? NCRYPT_MACHINE_KEY_FLAG : 0)), "Error opening TPM key.");

    return tpm_key;
}

wil::unique_ncrypt_key create_tpm_key(const wstring& name, bool machine_key)
{
    cout << "Creating TPM key...";

    wil::unique_ncrypt_prov tpm_prov{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(&tpm_prov, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0), "Error opening TPM provider.");

    wil::unique_ncrypt_key tpm_key{};
    THROW_IF_FAILED_MSG(NCryptCreatePersistedKey(tpm_prov.get(), &tpm_key, BCRYPT_RSA_ALGORITHM, name.c_str(), 0, NCRYPT_OVERWRITE_KEY_FLAG | (machine_key ? NCRYPT_MACHINE_KEY_FLAG : 0)), "Error creating TPM key.");

    DWORD key_len = 2048;
    THROW_IF_FAILED_MSG(NCryptSetProperty(tpm_key.get(), NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&key_len), sizeof(key_len), 0), "Error setting key length.");

    THROW_IF_FAILED_MSG(NCryptFinalizeKey(tpm_key.get(), 0), "Error finalizing TPM key.");

    cout << " Done." << endl;

    return tpm_key;
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
