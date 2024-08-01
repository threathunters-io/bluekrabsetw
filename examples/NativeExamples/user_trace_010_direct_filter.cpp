// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use the any_of/all_of/none_of filter predicate vectors.

#include <iostream>
#include <cassert>
#include <chrono>
#include <thread>

#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"

void user_trace_010_direct_filter::start()
{
    krabs::user_trace trace(L"My Named Trace");
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");

    //auto custom_filter = std::make_shared<krabs::system_flags_event_filter>(0xFFFFFFFFFFFF, 4);// krabs::none_type_filter((unsigned long long)0xFFFFFFFFFFFF, 4);
    //auto eventid = std::make_shared<krabs::event_id_event_filter>(std::set<unsigned short>{ 5 }, true);
    //auto pid = std::make_shared<krabs::event_pid_event_filter>(std::set<unsigned short>{ 4 }, true);
    //auto eventname = std::make_shared<krabs::event_name_event_filter>(std::set<std::string>{ "name1", "name2" }, true);
    //auto eventid = krabs::event_id_type_filter({ 5 }, true);
    //auto payload_filter = std::make_shared<krabs::event_payload_event_filter>(L"DesiredAccess", (unsigned short)PAYLOADFIELD_GE, L"12288");
    //auto sy = krabs::system_flags_descriptor(0xFFFFFFFFFFFF, 4);
    //auto id = krabs::event_id_descriptor(std::set<unsigned short>{ 5, 12, 31, 131, 133 }, true);
    //auto d1 = sy();
    //auto d2 = id();
    //krabs::direct_event_filters1 direct_filter1({ &sy,&id });
    //auto a = direct_filter1();
    //krabs::direct_event_filters direct_filter({
     //   eventid,
      //  payload_filter,
      //  custom_filter,
      //  pid
        //eventname
      //  });

    auto a1 = std::make_shared<krabs::system_flags>(0xFFFFFFFFFFFF, 4);
    auto a2 = std::make_shared<krabs::event_ids>(std::set<unsigned short>{ 5, 12, 31, 131, 133 }, true);
    krabs::pre_event_filter pre_filter({ a1,a2 });



    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        assert(schema.event_id() == 5);
        krabs::parser parser(schema);
        
        std::wcout << L" ProviderID=" << schema.provider_name() << std::endl;
        std::wcout << L" EventID=" << schema.event_id() << std::endl;
        });

    provider.add_filter(pre_filter);
    trace.enable(provider);
    trace.start();
}