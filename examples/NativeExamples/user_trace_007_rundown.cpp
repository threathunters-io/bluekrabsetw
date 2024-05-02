// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example demonstrates rundown events that capture system state.

#include <iostream>

#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"

void user_trace_007_rundown::start()
{
    krabs::user_trace trace(L"user_trace_007");

    // Rundown events are not true real-time tracing events. Instead they describe the state
    // of the system - either at the start or end of a trace.

    // Usually these are just extra events in the provider. For example, Microsoft-Windows-Kernel-Process
    // has ProcessRundown events as well as ProcessStart events.
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    process_provider.any(0x10);  // WINEVENT_KEYWORD_PROCESS
    // ...but the rundown events often cannot be enabled by keyword alone.
    // The trace needs to be sent EVENT_CONTROL_CODE_CAPTURE_STATE.
    // This is what enable_rundown_events() does.
    process_provider.enable_rundown_events();

    auto process_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        uint32_t pid = parser.parse<uint32_t>(L"ProcessID");
        std::wstring image_name = parser.parse<std::wstring>(L"ImageName");
        std::wcout << schema.provider_name();
        std::wcout << L" task_name=" << schema.task_name();
        std::wcout << L" ProcessID=" << pid;
        std::wcout << L" ImageName=" << image_name;
        std::wcout << std::endl;
    };

    // real-time process start events
    krabs::event_filter process_filter(krabs::predicates::id_is(1));  // ProcessStart
    process_filter.add_on_event_callback(process_callback);
    process_provider.add_filter(process_filter);

    // process rundown events - i.e. running processes
    krabs::event_filter process_rundown_filter(krabs::predicates::id_is(15));  // ProcessRundown
    process_rundown_filter.add_on_event_callback(process_callback);
    process_provider.add_filter(process_rundown_filter);
    
    trace.enable(process_provider);

    
    // Some providers don't follow this pattern and instead split this functionality
    // into a seperate provider. For example, Microsoft-Windows-DotNETRuntime and
    // Microsoft-Windows-DotNETRuntimeRundown.
    krabs::provider<> dotnet_provider(L"Microsoft-Windows-DotNETRuntime");
    krabs::provider<> dotnet_rundown_provider(L"Microsoft-Windows-DotNETRuntimeRundown");

    auto assembly_callback = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        std::wstring assembly_name = parser.parse<std::wstring>(L"FullyQualifiedAssemblyName");
        std::wcout << schema.provider_name();
        std::wcout << L" opcode_name=" << schema.opcode_name();
        std::wcout << L" ProcessId=" << record.EventHeader.ProcessId;
        std::wcout << L" FullyQualifiedAssemblyName=" << assembly_name;
        std::wcout << std::endl;
    };
    
    // real-time assembly load events
    dotnet_provider.any(0x8);  // LoaderKeyword
    krabs::event_filter assembly_filter(krabs::predicates::id_is(154));  // LoaderAssemblyLoad
    assembly_filter.add_on_event_callback(assembly_callback);
    dotnet_provider.add_filter(assembly_filter);
    trace.enable(dotnet_provider);
    
    // assembly rundown events - i.e. loaded assemblies
    // Note - use StartRundownKeyword / EndRundownKeyword to control whether the state is enumerated
    // at the start or the end of the trace.
    dotnet_rundown_provider.any(0x8 |   // LoaderRundownKeyword
                                0x40);  // StartRundownKeyword
    krabs::event_filter assembly_rundown_filter(krabs::predicates::id_is(155));  // LoaderAssemblyDCStart
    assembly_rundown_filter.add_on_event_callback(assembly_callback);
    dotnet_rundown_provider.add_filter(assembly_rundown_filter);
    trace.enable(dotnet_rundown_provider);

    trace.start();
}


void user_trace_007_rundown::start2()
{
    krabs::user_trace trace(L"user_trace_007");

    
    krabs::provider<> provider1(L"Microsoft-Windows-DotNETRuntimeRundown");
    krabs::provider<> provider2(L"Microsoft-Windows-Kernel-Power");
    krabs::provider<> provider3(L"Microsoft-Windows-DotNETRuntime");
    krabs::provider<> provider4(L"Microsoft-JScript");
    krabs::provider<> provider5(L"Microsoft-Windows-Win32k");
    krabs::provider<> provider6(L"Microsoft-Windows-UserModePowerService");
    krabs::provider<> provider7(L"Microsoft-Windows-Networking-Correlation");
    krabs::provider<> provider8(L"Microsoft-Windows-Kernel-Processor-Power");
    krabs::provider<> provider9(L"Microsoft-Windows-RPC");
    krabs::provider<> provider10(L"Microsoft-Windows-Kernel-EventTracing");
    krabs::provider<> provider11(L"Microsoft-Antimalware-Engine");
    krabs::provider<> provider12(L"Microsoft-Windows-Search-Core");
    krabs::provider<> provider13(L"Microsoft-Antimalware-AMFilter");
    krabs::provider<> provider14(L"Microsoft-Windows-Performance-Recorder-Control");
    krabs::provider<> provider20(krabs::guid(L"{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}"));
    krabs::provider<> provider15(L"Microsoft-Windows-Kernel-StoreMgr");
    krabs::provider<> provider16(L"Microsoft-Antimalware-RTP");
    krabs::provider<> provider17(L"Microsoft-Antimalware-Service");
    krabs::provider<> provider18(L"Microsoft-Windows-ProcessStateManager");
    krabs::provider<> provider19(L"Microsoft-Windows-ReadyBoostDriver");
    krabs::provider<> provider21(L"Microsoft-Windows-COMRuntime");


    // user_trace providers typically have any and all flags, whose meanings are
    // unique to the specific providers that are being invoked. To understand these
    // flags, you'll need to look to the ETW event producer.
    //provider.any(0xf0010000000003ff);

    // providers should be wired up with functions (or functors) that are called when
    // events from that provider are fired.
    provider1.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider2.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider3.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider4.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider5.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider6.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider7.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider8.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider9.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider10.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider11.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider12.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider13.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider14.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider15.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider16.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider17.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider18.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider19.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider20.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider21.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    /*  provider22.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

          });
      provider23.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

          });
      provider24.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

          });*/



          // the user_trace needs to know about the provider that we've set up.
    trace.enable(provider1);
    trace.enable(provider2);
    trace.enable(provider3);
    trace.enable(provider4);
    trace.enable(provider5);
    trace.enable(provider6);
    trace.enable(provider7);
    trace.enable(provider8);
    trace.enable(provider10);
    trace.enable(provider11);
    trace.enable(provider12);
    trace.enable(provider13);
    trace.enable(provider14);
    trace.enable(provider15);
    trace.enable(provider16);
    trace.enable(provider17);
    trace.enable(provider18);
    trace.enable(provider19);
    trace.enable(provider20);
    trace.enable(provider21);
    /*   trace.enable(provider22);
       trace.enable(provider23);
       trace.enable(provider24);*/
       // specify a filename to read from, will disable realtime and source from file instead
    

    // begin listening for events. This call blocks until the end of file is reached, so if
    // you want to do other things while this runs, you'll need to call this on another thread.
    trace.start();

}