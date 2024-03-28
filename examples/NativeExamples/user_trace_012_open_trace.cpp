// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with an ETL file
#include <iostream>

#include "..\..\krabs\krabs.hpp"
#include "examples.h"

void user_trace_012_open_trace::start()
{
    krabs::user_trace trace(L"test_sense");
    krabs::provider<> provider(krabs::guid(L"{16c6501a-ff2d-46ea-868d-8f96cb0cb52d}"));

    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);

        // We then have the ability to ask a few questions of the event.
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;
        krabs::parser parser(schema);
        
        
    });

    trace.enable(provider);
    trace.open();
    trace.process();
}