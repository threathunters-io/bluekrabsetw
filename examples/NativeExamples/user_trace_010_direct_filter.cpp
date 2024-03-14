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
    krabs::provider<> provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    //krabs::provider<> provider(L"Microsoft-Windows-PowerShell");
    krabs::predicates::id_is eventid_is_5 = krabs::predicates::id_is(5);

    /*
    
    - <System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /> 
  <EventID>53504</EventID> 
  <Version>1</Version> 
  <Level>4</Level> 
  <Task>111</Task> 
  <Opcode>10</Opcode> 
  <Keywords>0x0</Keywords> 
  <TimeCreated SystemTime="2024-01-31T11:47:07.7135091Z" /> 
  <EventRecordID>31</EventRecordID> 
  <Correlation ActivityID="{76722ce4-53d4-0008-6e1b-7376d453da01}" /> 
  <Execution ProcessID="17916" ThreadID="10184" /> 
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel> 
  <Computer>DESKTOP-L5HRUTP</Computer> 
  <Security UserID="S-1-5-21-2100305094-2521724483-1926615856-1001" /> 
  </System>
- <EventData>
  <Data Name="param1">17916</Data> 
  <Data Name="param2">DefaultAppDomain</Data> 
    */

    auto custom_filter = std::make_shared<krabs::system_flags_event_filter>(0xFFFFFFFFFFFF, 4);// krabs::none_type_filter((unsigned long long)0xFFFFFFFFFFFF, 4);
    auto eventid = std::make_shared<krabs::event_id_event_filter>(std::set<unsigned short>{ 5 }, true);
    auto pid = std::make_shared<krabs::event_pid_event_filter>(std::set<unsigned short>{ 4 }, true);

    auto eventname = std::make_shared<krabs::event_name_event_filter>(std::set<std::string>{ "name1", "name2" }, true);
    //auto eventid = krabs::event_id_type_filter({ 5 }, true);
    auto payload_filter = std::make_shared<krabs::event_payload_event_filter>(L"DesiredAccess", (unsigned short)PAYLOADFIELD_GE, L"12288");
    krabs::direct_event_filters direct_filter({
        eventid,
        payload_filter,
        custom_filter,
        pid
        //eventname
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
        
        std::wcout << L" PID=" << schema.process_id() << std::endl;
        std::wcout << L" EventID=" << schema.event_id() << std::endl;
        std::wcout << L" TargetProcessId=" << parser.parse<unsigned int>(L"TargetProcessId");
        std::wcout << L" DesiredAccess=" << parser.parse<unsigned int>(L"DesiredAccess");
        std::wcout << L" ReturnCode=" << parser.parse<unsigned int>(L"ReturnCode");
            /*
             std::wcout << L" ContextInfo=" << parser.parse<std::wstring>(L"ContextInfo") << std::endl;
             std::wcout << L" UserData=" << parser.parse<std::wstring>(L"UserData") << std::endl;
             std::wcout << L" Payload=" << parser.parse<std::wstring>(L"Payload") << std::endl;*/
       
        

             /*auto t = parser.parse<krabs::binary>(L"CapturedData");
             std::wcout << L" EventID=" << schema.event_id() << std::endl;
             std::wcout << L" KeyName=" << parser.parse<std::wstring>(L"KeyName") << std::endl;
             std::wcout << L" ValueName=" << parser.parse<std::wstring>(L"ValueName") << std::endl;
             std::wcout << L" CapturedDataSize=" << parser.parse<unsigned short>(L"CapturedDataSize") << std::endl;
             std::wcout << L" PreviousDataCapturedSize=" << parser.parse<unsigned short>(L"PreviousDataCapturedSize") << std::endl;*/

       
        

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