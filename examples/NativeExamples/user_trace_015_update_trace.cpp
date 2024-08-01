// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with an ETL file
#pragma once

#include <iostream>
#include <chrono>
#include <thread>

#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"


/// <summary>
/// start session
/// </summary>
void user_trace_015_update_trace::start()
{
    krabs::user_trace trace(L"update_trace");
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);

        krabs::parser parser(schema);

        //std::wcout << L" ProviderID=" << schema.provider_name() << std::endl;
        //std::wcout << L" EventID=" << schema.event_id() << std::endl;

    });

    auto show_config = [&trace]() {
        auto config = trace.query_stats();
        std::cout << "current config:" << std::endl;
        std::cout << "min buffer:" << config.minimum_buffers << std::endl;
        std::cout << "max buffer:" << config.maximum_buffers << std::endl;
        std::cout << "max flush:" << config.flush_timer << std::endl;
    };

    trace.enable(provider);   
    std::thread workerThread([&]() {
        trace.start();
        });
    const int durationInSeconds = 10;
    std::this_thread::sleep_for(std::chrono::seconds(durationInSeconds));
    show_config();
    EVENT_TRACE_PROPERTIES etp = { 0 };
    //etp.MinimumBuffers = 32;
    etp.MaximumBuffers = 128;
    etp.FlushTimer = 10;
    trace.set_trace_properties(&etp);
    trace.update();
    show_config();
    trace.stop();
    workerThread.join();
}