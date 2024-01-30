// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use the any_of/all_of/none_of filter predicate vectors.

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_010_direct_filter::start()
{
    krabs::user_trace trace(L"My Named Trace");
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Registry");
    krabs::predicates::id_is eventid_is_5 = krabs::predicates::id_is(5);

    auto custom_filter = std::make_shared<krabs::system_flags_event_filter>(0xFFFFFFFFFFFF, 4);// krabs::none_type_filter((unsigned long long)0xFFFFFFFFFFFF, 4);
    auto eventid = std::make_shared<krabs::event_id_event_filter>(std::set<unsigned short>{ 5 }, true);
    //auto eventname = std::make_shared<krabs::event_name_event_filter>(std::set<std::string>{ "name1", "name2" }, true);
    //auto eventid = krabs::event_id_type_filter({ 5 }, true);

    krabs::direct_event_filters direct_filter({
        eventid,
        //eventname,
        custom_filter
        });

    krabs::event_filter filter(
        krabs::predicates::any_of({
            &eventid_is_5
            })
    );
    /*
        filter.add_custom_filter(0xFFFFFFFFFFFF, 4);*/

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        assert(schema.event_id() == 5);
        krabs::parser parser(schema);

        auto t = parser.parse<krabs::binary>(L"CapturedData");
        std::wcout << L" EventID=" << schema.event_id() << std::endl;
        std::wcout << L" KeyName=" << parser.parse<std::wstring>(L"KeyName") << std::endl;
        std::wcout << L" ValueName=" << parser.parse<std::wstring>(L"ValueName") << std::endl;
        std::wcout << L" CapturedDataSize=" << parser.parse<unsigned short>(L"CapturedDataSize") << std::endl;
        std::wcout << L" PreviousDataCapturedSize=" << parser.parse<unsigned short>(L"PreviousDataCapturedSize") << std::endl;
        
        

        });

    provider.add_filter(direct_filter);
    //provider.add_filter(filter);
    trace.enable(provider);

    std::thread workerThread([&]() {
        trace.start();
        });

    const int durationInSeconds = 30;
    std::this_thread::sleep_for(std::chrono::seconds(durationInSeconds));
    trace.stop();

    workerThread.join();

    //std::wcout << L" DirectFilter: Events in 30s =" << trace.query_stats().eventsTotal << std::endl;
    std::wcout << L" IndirectFilter: Events in 30s =" << trace.query_stats().eventsTotal << std::endl;
}