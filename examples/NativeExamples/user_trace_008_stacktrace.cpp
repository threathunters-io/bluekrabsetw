// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates collecting stack traces as part of events.

#include <iostream>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_008_stacktrace::start()
{
    krabs::user_trace trace(L"user_trace_008_stacktrace");
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    process_provider.any(0x10);  // WINEVENT_KEYWORD_PROCESS
    process_provider.enable_property(process_provider.enable_property() | EVENT_ENABLE_PROPERTY_STACK_TRACE);


//#define EVENT_ENABLE_PROPERTY_SID                       0x00000001
//#define EVENT_ENABLE_PROPERTY_TS_ID                     0x00000002
//#define EVENT_ENABLE_PROPERTY_STACK_TRACE               0x00000004
//#define EVENT_ENABLE_PROPERTY_PSM_KEY                   0x00000008
//#define EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0          0x00000010
//#define EVENT_ENABLE_PROPERTY_PROVIDER_GROUP            0x00000020
//#define EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0          0x00000040
//#define EVENT_ENABLE_PROPERTY_PROCESS_START_KEY         0x00000080
//#define EVENT_ENABLE_PROPERTY_EVENT_KEY                 0x00000100
//#define EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE         0x00000200
//#define EVENT_ENABLE_PROPERTY_ENABLE_SILOS              0x00000400
//#define EVENT_ENABLE_PROPERTY_SOURCE_CONTAINER_TRACKING 0x00000800 

    krabs::event_filter process_filter(krabs::predicates::id_is(1));  // ProcessStart
    process_filter.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        auto pid = parser.parse<uint32_t>(L"ProcessID");
        auto image_name = parser.parse<std::wstring>(L"ImageName");
        auto stack_trace = schema.stack_trace();

        std::wcout << std::endl << schema.task_name();
        std::wcout << L" ProcessID=" << pid;
        std::wcout << L" ImageName=" << image_name;
        std::wcout << std::endl << L"Call Stack:" << std::endl;
        for (auto& return_address : stack_trace)
        {
            std::wcout << L"   0x" << std::hex << return_address << std::endl;
        }
        });
    process_provider.add_filter(process_filter);

    trace.enable(process_provider);
    trace.start();
}