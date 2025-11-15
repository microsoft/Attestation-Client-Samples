//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @brief The sample enclave image configuration.

 * @remark You must personalize the following fields before building and shipping the enclave:
 * - Enclave family ID
 * - Enclave image ID
 * - Version
 * - SVN
 * - Number of threads
 *
 * Please see https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide for more details.
 */

#include <winenclave.h>

// VBS enclave configuration
const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG),
    IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    0, // change to IMAGE_ENCLAVE_POLICY_DEBUGGABLE if you require a debuggable enclave.
    0,
    0,
    0,
    // The following information must be set before building the enclave.
    { 0xFE, 0xFE },    // family id
    { 0x01, 0x01 },    // image id
    0,                 // version
    0,                 // SVN
    0x10000000,        // size
    16,                // number of threads
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE
};