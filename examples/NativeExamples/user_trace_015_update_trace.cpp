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
void user_trace_015_update_trace::start1()
{

	krabs::user_trace trace(L"test_sense");

    krabs::provider<> provider(krabs::guid(L"{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}"));




    provider.enable_property(provider.enable_property() | EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_SID | EVENT_ENABLE_PROPERTY_TS_ID);

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);


        // We then have the ability to ask a few questions of the event.
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;
        krabs::parser parser(schema);

        auto extended_data_count = record.ExtendedDataCount;
        for (USHORT i = 0; i < extended_data_count; i++)
        {
            auto& extended_data = record.ExtendedData[i];

            if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_TS_ID)
            {
                auto result = (reinterpret_cast<_EVENT_EXTENDED_ITEM_TS_ID*>(extended_data.DataPtr))->SessionId;
                std::wcout << L"(" << "EVENT_EXTENDED_ITEM_TS_ID" << L") received." << result << std::endl;
            }
            if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_SID)
            {

            }
            if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY)
            {
                auto result = (reinterpret_cast<_EVENT_EXTENDED_ITEM_PROCESS_START_KEY*>(extended_data.DataPtr))->ProcessStartKey;
                std::wcout << L"(" << "EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY" << L") received." << result << std::endl;
            }
        }

        });



	
}

/// <summary>
/// open session 
/// </summary>
void user_trace_015_update_trace::start2()
{

    krabs::user_trace trace(L"test_sense");

    krabs::provider<> provider(krabs::guid(L"{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}"));

    //provider.enable_property(provider.enable_property() | EVENT_ENABLE_PROPERTY_PROCESS_START_KEY | EVENT_ENABLE_PROPERTY_SID | EVENT_ENABLE_PROPERTY_TS_ID);

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);


        // We then have the ability to ask a few questions of the event.
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;
        krabs::parser parser(schema);

        /*auto extended_data_count = record.ExtendedDataCount;
        for (USHORT i = 0; i < extended_data_count; i++)
        {
            auto& extended_data = record.ExtendedData[i];

            if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_TS_ID)
            {
                auto result = (reinterpret_cast<_EVENT_EXTENDED_ITEM_TS_ID*>(extended_data.DataPtr))->SessionId;
                std::wcout << L"(" << "EVENT_EXTENDED_ITEM_TS_ID" << L") received." << result << std::endl;
            }
            if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_SID)
            {

            }
            if (extended_data.ExtType == EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY)
            {
                auto result = (reinterpret_cast<_EVENT_EXTENDED_ITEM_PROCESS_START_KEY*>(extended_data.DataPtr))->ProcessStartKey;
                std::wcout << L"(" << "EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY" << L") received." << result << std::endl;
            }
        }*/


        });

    trace.enable(provider);

    /*std::thread workerThread([&]() {
        trace.start();
        });*/
    //Sleep(1000);
    auto tmp = trace.query_config();
    std::cout << "current config:"  << std::endl;
    std::cout << "min buffer:" << tmp.minimum_buffers << std::endl;
    std::cout << "max buffer:" << tmp.maximum_buffers << std::endl;
    std::cout << "max flush:" << tmp.flush_timer << std::endl;
   
    

    trace.open();
    
    EVENT_TRACE_PROPERTIES etp = {};
    //etp.MinimumBuffers = 32;
    etp.MaximumBuffers = 128;
    etp.FlushTimer = 10;
    trace.set_trace_properties(&etp);
    //trace.update(); 
    auto tmp2 = trace.query_config();
    std::thread workerThread([&]() {
        trace.process();
        });
    std::cout << "new config:" << std::endl;
    std::cout << "min buffer:" << tmp2.minimum_buffers << std::endl;
    std::cout << "max buffer:" << tmp2.maximum_buffers << std::endl;
    std::cout << "max flush:" << tmp2.flush_timer << std::endl;
    
    const int durationInSeconds = 30;
    std::this_thread::sleep_for(std::chrono::seconds(durationInSeconds));
    trace.enable(provider);
    trace.stop();

    workerThread.join();
}






