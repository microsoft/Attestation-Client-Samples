//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

/**
 * @file att_manager_api_enclave.h
 *
 * @brief Defines the types and functions used for VBS Enclave attestation.
 *
 * @note You MUST NOT use any symbols (macros, functions, structures, enums, etc.)
 * prefixed with an underscore ('_') directly in your application code. These symbols
 * are part of the SDK's internal implementation; we do not document these symbols
 * and they are subject to change in future versions of the SDK which would break your code.
 */

#ifndef _ATT_MANAGER_API_ENCLAVE_H
#define _ATT_MANAGER_API_ENCLAVE_H

#include <stdint.h>
#include <stddef.h>
#include "att_result.h"
#include "att_manager_api.h"
#include "att_manager_api_tpm.h"

#include "att_manager_defines.h"
/**
 * att_manager_api_enclave.h is used within the enclave and should be linked against AzureAttest.lib
 */

/**
 * Enclave functions that need to be exported by the enclave to the normal mode kernel (VTL0)
 * Below is an example code to expose the functions in the enclave.
 * The following functions will be the enclave exports:
 *
 * sample_att_enclave_configure
 * sample_att_enclave_create_session
 * sample_att_enclave_attest
 * sample_att_enclave_get_report
 * sample_att_enclave_close_session
 */

/*
extern "C"
{
    __declspec(dllexport)
    void* STDCALL sample_att_enclave_configure(void* param)
    {
        return att_enclave_configure(param, 0);
    }

    __declspec(dllexport)
    void* STDCALL sample_att_enclave_create_session(void* param)
    {
        return att_enclave_create_session(param, nullptr, 0, 0);
    }

    __declspec(dllexport)
    void* STDCALL sample_att_enclave_attest(void* param)
    {
        return att_enclave_attest(param);
    }

    __declspec(dllexport)
    void* STDCALL sample_att_enclave_get_report(void* param)
    {
        return att_enclave_get_report(param);
    }

    __declspec(dllexport)
    void* STDCALL sample_att_enclave_close_session(void* param)
    {
        return att_enclave_close_session(param);
    }
}
*/

/**
 * att_enclave_function_table
 * Contains pointers to the export functions exposed by the enclave.
 */
typedef struct _att_enclave_function_table
{
    /**
     * This function is invoked when the user initializes an attestation library from VTL0
     */
    LPENCLAVE_ROUTINE attestation_configure;

    /**
     * This function is invoked when the user calls att_create_session from VTL0.
     */
    LPENCLAVE_ROUTINE attestation_create_session;

    /**
     * This function is invoked when the user calls att_attest from VTL0.
     */
    LPENCLAVE_ROUTINE attestation_attest;

    /**
     * This function is invoked when the user calls att_get_report from VTL0.
     */
    LPENCLAVE_ROUTINE attestation_get_report;

    /**
     * This function is invoked when the user calls att_close_session from VTL0.
     */
    LPENCLAVE_ROUTINE attestation_close_session;

} att_enclave_function_table;

/**
 * Enum for attestation mode flag.
 */
typedef enum _att_enclave_flag
{
    /**
     * Always use VSM mode. Fails with ATT_ERROR_NOT_SUPPORTED if VSM is not supported.
     */
    ATT_ENCLAVE_FLAG_USE_VSM_MODE_ALWAYS = 0x0,

    /**
     * Always use normal mode.
     */
    ATT_ENCLAVE_FLAG_USE_NORMAL_MODE_ALWAYS,

    /**
     * Use VSM mode if supported, otherwise use normal mode.
     */
    ATT_ENCLAVE_FLAG_USE_VSM_MODE_IF_SUPPORTED

} att_enclave_flag;

/**
 * Bit mask for the Enclave configuration flags.
 */
typedef enum _att_enclave_config_flags
{
    /**
     * Default.
     */
    ATT_ENCLAVE_CONFIG_FLAGS_NONE = 0x0,

    /**
     * Config AzureAttest.dll to not send any tracing information back to VTL0/AttestManager. Default is to send tracing information back to VTL0/AttestManager. 
     */
    ATT_ENCLAVE_CONFIG_FLAGS_DISABLE_TRACING = 0x1
} att_enclave_config_flags;

/**
 * Parameters for creation of a VBS Enclave attestation session.
 */
typedef struct _att_session_params_enclave
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

    /**
     * The table of function pointers to the enclave functions that will be used for attestation.
     */
    const att_enclave_function_table* function_table;

    /**
     * The flag determining if attestation will be performed in normal mode or VSM mode.
     */
    att_enclave_flag enclave_flag;

} att_session_params_enclave;

/**
 * Enumerates the supported types for enclave attestation properties.
 *
 * This enum specifies the type of value that an enclave property can hold.
 */
typedef enum _att_enclave_property_type
{
    /**
     * Boolean property type.
     */
    ATT_ENCLAVE_PROPERTY_TYPE_BOOL,

    /**
     * 32-bit signed integer property type.
     */
    ATT_ENCLAVE_PROPERTY_TYPE_INT32,

    /**
     * Null-terminated string property type. All property strings must not contain quotes, carriage returns, or new lines.
     */
    ATT_ENCLAVE_PROPERTY_TYPE_STRING
} att_enclave_property_type;

/**
 * Represents a single property used for enclave attestation.
 *
 * This structure defines a property that can be associated with an enclave attestation session.
 * Each property has a name, a type (as defined by att_enclave_property_type), and a value.
 * The value is stored in a union and must match the specified value_type.
 */
typedef struct _att_enclave_property
{
    /// The name of the property as a null-terminated string.
    const char* name;

    /// The type of the property value (boolean, int32, or string).
    att_enclave_property_type value_type;

    union
    {
        /// The boolean value of the property (valid if value_type is ATT_ENCLAVE_PROPERTY_TYPE_BOOL).
        bool bool_value;

        /// The 32-bit signed integer value of the property (valid if value_type is ATT_ENCLAVE_PROPERTY_TYPE_INT32).
        int32_t int32_value;

        /// The string value of the property as a null-terminated string (valid if value_type is ATT_ENCLAVE_PROPERTY_TYPE_STRING).
        const char* string_value;
    };
} att_enclave_property;

/**
 * This function is invoked when the user calls att_create_session from VTL0.
 * The enclave writer can pass in configuration flags in addition to the VTL0 parameters.
 *
 * @param[in] param The VTL0 parameters. This is opaque to the enclave writer.
 *
 * @param[in] config_flags The bitwise flags to configure the attestation library.
 *
 * @return A pointer cast from att_result.
 */
EXTERN_C void* STDCALL att_enclave_configure(
    void* param,
    att_enclave_config_flags config_flags);

/**
 * This function is invoked when the user calls att_create_session from VTL0.
 * The enclave writer can pass in enclave properties that will be associated with the new session.
 *
 * @param[in] param The VTL0 parameters. This is opaque to the enclave writer.
 *
 * @param[in] enclave_properties An optional array pointer of enclave properties.
 *
 * @param[in] enclave_properties_size The number of enclave properties in \p enclave_properties.
 *
 * @param[in] flags Unused.
 *
 * @return A pointer cast from att_result.
 */
EXTERN_C void* STDCALL att_enclave_create_session(
    void* param,
    const att_enclave_property* enclave_properties,
    uint32_t enclave_properties_size,
    uint32_t flags);

/**
 * This function is invoked when the user calls att_attest from VTL0.
 *
 * @param[in] param The VTL0 parameters. This is opaque to the enclave writer.
 *
 * @return A pointer cast from att_result.
 */
EXTERN_C void* STDCALL att_enclave_attest(
    void* param);

/**
 * This function is invoked when the user calls att_get_report from VTL0.
 *
 * @param[in] param The VTL0 parameters. This is opaque to the enclave writer.
 *
 * @return A pointer cast from att_result.
 */
EXTERN_C void* STDCALL att_enclave_get_report(
    void* param);

/**
 * This function is invoked when the user calls att_close_session from VTL0.
 *
 * @param[in] param The VTL0 parameters. This is opaque to the enclave writer.
 *
 * @return A pointer cast from att_result.
 */
EXTERN_C void* STDCALL att_enclave_close_session(
    void* param);

#endif  // _ATT_MANAGER_API_ENCLAVE_H
