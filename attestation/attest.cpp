//
// Copyright (c) Microsoft Corporation. All rights reserved.
//

#include "attest.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <string>
#include <stdlib.h>
#include <azure/core.hpp>
#include <azure/attestation.hpp>

#include <att_manager.h>

using namespace std;
using namespace Azure::Core;
using namespace Azure::Security::Attestation;
using namespace Azure::Security::Attestation::Models;

// The following must be set before calling send_to_att_service().
std::string get_maa_provider_uri() { return get_env_var("AZURE_MAA_URI"); } // Microsoft Azure Attestation provider's Attest URI (as shown in portal). Format is similar to "https://<ProviderName>.<Region>.attest.azure.net".

void exit_if_failed(const att_result result, const string& function_name)
{
    if (att_result_failed(result))
    {
        cout << "Failed while calling " << function_name << ". Result: " << result << endl;
        exit(-3);
    }
}

vector<uint8_t> send_to_att_service(const uint8_t* data, size_t size)
{
    try
    {
        auto att_client = AttestationClient::Create(get_maa_provider_uri());

        auto response = att_client.AttestTpm(vector<uint8_t>(data, data + size));

        return response.Value.TpmResult;
    }
    catch (const Azure::Core::RequestFailedException& e)
    {
        std::cout << "Request Failed Exception happened:" << std::endl << e.what() << std::endl;
        if (e.RawResponse)
        {
            std::cout << "Error Code: " << e.ErrorCode << std::endl;
            std::cout << "Error Message: " << e.Message << std::endl;
        }
        exit(-2);
    }
}

void attest(const char* session_type, const void* params, const string& file_name)
{
    cout << "Starting attestation..." << endl;

    att_session session{};
    exit_if_failed(att_create_session(session_type, params, &session), "att_create_session");

    bool complete = false;
    vector<uint8_t> received_from_server{};

    while (!complete)
    {
        att_buffer send_to_server = nullptr;
        size_t send_to_server_size = 0;
        exit_if_failed(att_attest(session.get(), received_from_server.data(), received_from_server.size(), &send_to_server, &send_to_server_size, &complete), "att_attest");
        if (send_to_server_size > 0)
        {
            received_from_server = send_to_att_service(send_to_server.get(), send_to_server_size);
        }
    }

    att_buffer report = nullptr;
    size_t report_size = 0;
    exit_if_failed(att_get_report(session.get(), &report, &report_size), "att_get_report");

    cout << "Attestation is complete. Report size: " << report_size << endl;

    if (!file_name.empty())
    {
        ofstream out(file_name, ios::binary);
        out.write(reinterpret_cast<char*>(report.get()), report_size);
        cout << "Report saved to " << file_name << "." << endl;
    }
}
