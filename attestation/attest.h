//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#ifndef _ATT_SAMPLES_ATTEST_H
#define _ATT_SAMPLES_ATTEST_H

#include <string>
#include <stdint.h>
#include <wil/resource.h>

#include <att_manager.h>

// att_session automatically closes the session.
using att_session = wil::unique_any<att_session_handle, decltype(&att_close_session), att_close_session>;

// att_buffer automatically frees the buffer.
using att_buffer = wil::unique_any<uint8_t*, decltype(&att_free_buffer), att_free_buffer>;

// Performs the tpm attestation loop.
void attest(const char* session_type, const void* params, const std::string& file_name);

#endif // _ATT_SAMPLES_ATTEST_H