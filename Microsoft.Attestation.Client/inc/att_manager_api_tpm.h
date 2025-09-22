//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @file att_manager_api_tpm.h
 *
 * @brief Defines the types and functions used for TPM attestation.
 *
 * @note You MUST NOT use any symbols (macros, functions, structures, enums, etc.)
 * prefixed with an underscore ('_') directly in your application code. These symbols
 * are part of the SDK's internal implementation; we do not document these symbols
 * and they are subject to change in future versions of the SDK which would break your code.
 */

#ifndef _ATT_MANAGER_API_TPM_H
#define _ATT_MANAGER_API_TPM_H

#include <stdint.h>
#include <stddef.h>
#include "att_result.h"

#if defined(_WIN32)
#include <Windows.h>
#include <ncrypt.h>
#endif // _WIN32

typedef uint32_t att_tss_handle ;
typedef uintptr_t att_tss_context ;
/**
 * Attestation tss key null handle.
 */
#define ATT_TSS_NULL_HANDLE 0

#if defined(_WIN32)

/**
* Represents an NCrypt handle to a key stored in the TPM.
*/
typedef struct _att_ncrypt_key_handle
{
    /**
     * NCrypt handle. If this type of key is passed to the library using att_create_session, the caller is
     * expected to keep the handle valid until att_close_session is called.
     */
    NCRYPT_KEY_HANDLE handle;
} att_ncrypt_key_handle;

/*
* Represents an NCrypt handle to a key stored in a VBS trustlet.
* The handle will be used to retrieve a NCRYPT_CLAIM_VBS_ROOT claim.
*/
typedef struct _att_vbs_ncrypt_key_handle
{
    /**
     * NCrypt handle. If this type of key is passed to the library using att_create_session, the caller is
     * expected to keep the handle valid until att_close_session is called.
     */
    NCRYPT_KEY_HANDLE handle;
} att_vbs_ncrypt_key_handle;

/*
* Represents an IVM report.
*/
typedef struct _att_ivm_report
{
    /**
     * Report data. The report is a byte array that contains the IVM report.
     */
    const uint8_t* report;
    /**
     * Size of report data in bytes.
     */
    uint32_t report_size;
} att_ivm_report;

#endif // _WIN32

/*
* Represents a TSS Library handle to TSS ESYS object.
*/
typedef struct _att_tss_context_handle
{
    /**
     * ESYS_TR handle. If this type of handle is passed to the library using att_create_session, the caller is
     * expected to keep the handle valid until att_close_session is called.
     */
    att_tss_handle handle;
    /**
     * TSS context. This context must match the handle and stay valid until att_close_session is called.
     */
    att_tss_context context;
} att_tss_context_handle;

/**
 * Type of the TPM Attestation Identity Key (AIK).
*/
typedef enum _att_tpm_aik_type
{
    /// Invalid type.
    ATT_TPM_AIK_TYPE_INVALID,
#if defined(_WIN32)
    /// NCrypt handle.
    ATT_TPM_AIK_TYPE_NCRYPT,
#endif // _WIN32
    /// TSS handle.
    ATT_TPM_AIK_TYPE_TSS,
} att_tpm_aik_type;

/**
 * Represents a TPM Attestation Identity Key (AIK).
 *
 * Use one of the ATT_TPM_AIK_* macros to initialize an instance of this structure.
 */
typedef struct _att_tpm_aik
{
    /// Type of the AIK.
    att_tpm_aik_type type;
    union
    {
#if defined(_WIN32)
        /// Value for NCrypt type.
        att_ncrypt_key_handle ncrypt_aik;
#endif // _WIN32
        att_tss_context_handle tss_aik;
    };

    const uint8_t* aik_cert; // Optional field. If this is \c NULL, the AIK certificate will be retrieved from the OS when supported.
    size_t aik_cert_length;
} att_tpm_aik;

#if defined(_WIN32)
ATT_INLINE att_tpm_aik __create_att_tpm_aik_ncrypt(const NCRYPT_KEY_HANDLE& ncrypt_aik)
{
    att_tpm_aik aik{};
    aik.type = ATT_TPM_AIK_TYPE_NCRYPT;
    aik.ncrypt_aik.handle = ncrypt_aik;
    return aik;
}

/**
 * Initializes an \ref att_tpm_aik with an NCrypt key handle.
 *
 * @param[in] handle NCrypt key handle to the AIK.
 */
#define ATT_TPM_AIK_NCRYPT(handle) __create_att_tpm_aik_ncrypt(handle)
#endif // _WIN32

ATT_INLINE att_tpm_aik __create_att_tpm_aik_tss(const att_tss_handle& handle, const att_tss_context& context)
{
    att_tpm_aik aik{};
    aik.type = ATT_TPM_AIK_TYPE_TSS;
    aik.tss_aik.handle = handle;
    aik.tss_aik.context = context;
    return aik;
}

/**
 * Initializes an \ref att_tpm_aik with a TSS handle.
 *
 * @param[in] handle TSS handle to the AIK.
 * @param[in] context TSS context for handle.
 */
#define ATT_TPM_AIK_TSS(handle, context) __create_att_tpm_aik_tss(handle, context)

/**
 * Type of the TPM key.
 */
typedef enum _att_tpm_key_type
{
    /// Invalid type.
    ATT_TPM_KEY_TYPE_INVALID,

#if defined(_WIN32)
    /// NCrypt handle.
    ATT_TPM_KEY_TYPE_NCRYPT,

    // VBS Ncrypt handle.
    ATT_TPM_KEY_TYPE_VBS_NCRYPT,

    /// IVM Report data.
    ATT_TPM_KEY_TYPE_IVM_REPORT,
#endif // _WIN32

    /// TSS handle.
    ATT_TPM_KEY_TYPE_TSS,
} att_tpm_key_type;

/**
 * Represents a TPM key.
 *
 * Use one of the ATT_TPM_KEY_* macros to initialize an instance of this structure.
 */
typedef struct _att_tpm_key
{
    /// Type of the Key.
    att_tpm_key_type type;
    union
    {
#if defined(_WIN32)
        /// Value for NCrypt type.
        att_ncrypt_key_handle tpm_ncrypt;
        att_vbs_ncrypt_key_handle tpm_vbs_ncrypt;
        att_ivm_report ivm_report;
#endif // _WIN32
        att_tss_context_handle tpm_tss;
    };
} att_tpm_key;

#if defined(_WIN32)
ATT_INLINE att_tpm_key __create_att_tpm_key_ncrypt(const NCRYPT_KEY_HANDLE& ncrypt_key)
{
    att_tpm_key key{};
    key.type = ATT_TPM_KEY_TYPE_NCRYPT;
    key.tpm_ncrypt.handle = ncrypt_key;
    return key;
}

ATT_INLINE att_tpm_key __create_att_tpm_key_vbs(const NCRYPT_KEY_HANDLE& vbs_ncrypt)
{
    att_tpm_key key{};
    key.type = ATT_TPM_KEY_TYPE_VBS_NCRYPT;
    key.tpm_vbs_ncrypt.handle = vbs_ncrypt;
    return key;
}

ATT_INLINE att_tpm_key __create_att_tpm_key_ivm_report(const uint8_t* report, uint32_t report_size)
{
    att_tpm_key key{};
    key.type = ATT_TPM_KEY_TYPE_IVM_REPORT;
    key.ivm_report.report = report;
    key.ivm_report.report_size = report_size;
    return key;
}

/**
 * Initializes an \ref att_tpm_key with an NCrypt key handle.
 *
 * @param[in] handle NCrypt key handle to the TPM key.
 */
#define ATT_TPM_KEY_NCRYPT(handle) __create_att_tpm_key_ncrypt(handle)

/**
 * Initializes an \ref att_tpm_key with a VBS NCrypt key handle.
 *
 * @param[in] handle NCrypt handle to a key stored in a VBS trustlet.
 */
#define ATT_TPM_KEY_VBS_NCRYPT(handle) __create_att_tpm_key_vbs(handle)

/**
 * Initializes an \ref att_tpm_key with an IVM report.
 *
 * @param[in] report IVM report.
 * @param[in] report_size Size of the IVM report.
 */
#define ATT_TPM_KEY_IVM_REPORT(report, report_size) __create_att_tpm_key_ivm_report(report, report_size)
#endif // _WIN32

ATT_INLINE att_tpm_key __create_att_tpm_key_tss(const att_tss_handle& handle, const att_tss_context& context)
{
    att_tpm_key key{};
    key.type = ATT_TPM_KEY_TYPE_TSS;
    key.tpm_tss.handle = handle;
    key.tpm_tss.context = context;
    return key;
}

/**
 * Initializes an \ref att_tpm_key with a TSS handle.
 *
 * @param[in] handle TSS handle to the TPM key.
 * @param[in] context TSS context for handle.
 */
#define ATT_TPM_KEY_TSS(handle, context) __create_att_tpm_key_tss(handle, context)

/**
 * Parameters for creation of a TPM attestation session.
 */
typedef struct _att_session_params_tpm
{
    /**
     * Optional byte array that will be passed to the attestation service. This is normally a nonce from the relying party to guarantee freshness of the report.
     * Included as is in the final attestation report issued by the attestation service.
     */
    const uint8_t* relying_party_nonce;

    /**
     * The number of bytes in the /ref relying_party_nonce buffer.
     */
    size_t relying_party_nonce_size;

    /**
     * An optional string that will be passed to the attestation service. This identifies the relying party.
     */
    const char* relying_party_unique_id;

    /**
     * An attestation identity key used in the attestation of TPM keys or quote.
     */
    const att_tpm_aik* aik;

    /**
     * The key to sign the request with, and to be sent to the attestation service for attestation.
     */
    const att_tpm_key* request_key;

    /**
     * Optional other keys to be sent to the attestation service for attestation.
     */
    const att_tpm_key* other_keys;

    /**
     * The number of keys in the \ref other_keys array. The attestation service may limit the number of keys allowed in the request.
     */
    size_t other_keys_count;
} att_session_params_tpm;

#endif  // _ATT_MANAGER_API_TPM_H
