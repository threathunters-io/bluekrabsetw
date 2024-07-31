// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with an ETL file
#pragma once

#include <iostream>
#include <chrono>
#include <thread>

#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"


/// <summary>
/// Note: This example demonstrates:
///       1. Enabling a provider and running for 10 seconds
///       2. Enabling an additional provider during runtime and run for another 10 seconds
///       3. Disabling a provider during runtime and running for another 10 seconds
/// </summary>
void user_trace_016_update_provider::start()
{
    krabs::user_trace trace(L"update_provider");
    krabs::provider<> provider_api(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    provider_api.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        krabs::parser parser(schema);

        std::wcout << L" ProviderID=" << schema.provider_name() << std::endl;
        std::wcout << L" EventID=" << schema.event_id() << std::endl;

        });

    trace.enable(provider_api);
    std::thread workerThread([&]() {
        trace.start();
        });
    
    const int durationInSeconds = 10;
    std::this_thread::sleep_for(std::chrono::seconds(durationInSeconds));

    krabs::provider<> provider_power(L"Microsoft-Windows-PowerShell");
    provider_power.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        krabs::parser parser(schema);

        std::wcout << L" ProviderID=" << schema.provider_name() << std::endl;
        std::wcout << L" EventID=" << schema.event_id() << std::endl;

        });

    trace.enable(provider_power);
    std::this_thread::sleep_for(std::chrono::seconds(durationInSeconds));
    trace.disable(provider_api);
    std::this_thread::sleep_for(std::chrono::seconds(durationInSeconds));    
    trace.stop();
    workerThread.join();
    
}
