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

wil::unique_ncrypt_key create_key(PCWSTR provider_name, PCWSTR key_name, DWORD flags)
{
    wil::unique_ncrypt_prov provider{};
    THROW_IF_FAILED_MSG(NCryptOpenStorageProvider(&provider, provider_name, 0), "Error opening storage provider.");

    wil::unique_ncrypt_key key{};
    THROW_IF_FAILED_MSG(NCryptCreatePersistedKey(provider.get(), &key, BCRYPT_RSA_ALGORITHM, key_name, 0, flags), "Error creating key.");

    DWORD key_len = 2048;
    THROW_IF_FAILED_MSG(NCryptSetProperty(key.get(), NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&key_len), sizeof(key_len), 0), "Error setting key length.");

    THROW_IF_FAILED_MSG(NCryptFinalizeKey(key.get(), 0), "Error finalizing key.");

    return key;
}

wil::unique_ncrypt_key create_tpm_key(const wstring& name, bool machine_key)
{
    cout << "Creating TPM key...";

    wil::unique_ncrypt_key tpm_key = create_key(MS_PLATFORM_KEY_STORAGE_PROVIDER, name.c_str(), NCRYPT_OVERWRITE_KEY_FLAG | (machine_key ? NCRYPT_MACHINE_KEY_FLAG : 0));

    cout << " Done." << endl;

    return tpm_key;
}

wil::unique_ncrypt_key create_ephemeral_software_key()
{
    cout << "Creating ephemeral software key...";

    wil::unique_ncrypt_key ephemeral_software_key = create_key(MS_KEY_STORAGE_PROVIDER, nullptr, 0);

    cout << " Done." << endl; 
    
    return ephemeral_software_key;
}

wil::unique_ncrypt_key create_key_guard_key()
{
    cout << "Creating VBS NCrypt (Key Guard) key...";

    wil::unique_ncrypt_key key_guard_key = create_key(MS_KEY_STORAGE_PROVIDER, nullptr, NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_USE_VIRTUAL_ISOLATION_FLAG);
    
    cout << " Done." << endl;

    return key_guard_key;
}

void sample_log_listener(att_log_source, att_log_level, const char* message)
{
    cout << "[LOG] " << message << endl;
}

string get_env_var(const string& env)
{
    // Get length of env value.
    size_t len = 0;
    if (getenv_s(&len, nullptr, 0, env.c_str()) || len == 0)
    {
        throw runtime_error("Could not find environment variable: '" + string(env) + "'");
    }

    // Allocate using a string and get the value.
    string val(len, 0);
    if (getenv_s(&len, val.data(), val.size(), env.c_str()) || len == 0)
    {
        throw runtime_error("Could not read environment variable: '" + string(env) + "'");
    }

    // Remove last character of the string as getenv_s() stores null terminator.
    val.erase(val.end() - 1);

    return val;
}