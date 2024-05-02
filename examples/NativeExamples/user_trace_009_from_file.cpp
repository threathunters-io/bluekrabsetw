// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// This example shows how to use a user_trace with an ETL file

#include <iostream>
#include <thread>
#include <condition_variable>
#include "..\..\bluekrabs\krabs.hpp"
#include "examples.h"

void user_trace_009_from_file::start()
{
    // user_trace instances should be used for any non-kernel traces that are defined
// by components or programs in Windows.
    krabs::user_trace trace;

    // A trace can have any number of providers, which are identified by GUID. These
    // GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil).
    krabs::provider<> provider(krabs::guid(L"{A0C1853B-5C40-4B15-8766-3CF1C58F985A}"));

    // user_trace providers typically have any and all flags, whose meanings are
    // unique to the specific providers that are being invoked. To understand these
    // flags, you'll need to look to the ETW event producer.
    provider.any(0xf0010000000003ff);

    // providers should be wired up with functions (or functors) that are called when
    // events from that provider are fired.
    provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {

        // Once an event is received, if we want krabs to help us analyze it, we need
        // to snap in a schema to ask it for information.
        krabs::schema schema(record, trace_context.schema_locator);

        // We then have the ability to ask a few questions of the event.
        std::wcout << L"Event " << schema.event_id();
        std::wcout << L"(" << schema.event_name() << L") received." << std::endl;

        if (schema.event_id() == 7937) {
            // The event we're interested in has a field that contains a bunch of
            // info about what it's doing. We can snap in a parser to help us get
            // the property information out.
            krabs::parser parser(schema);

            // We have to explicitly name the type that we're parsing in a template
            // argument.
            // We could alternatively use try_parse if we didn't want an exception to
            // be thrown in the case of failure.
            std::wstring context = parser.parse<std::wstring>(L"ContextInfo");
            std::wcout << L"\tContext: " << context << std::endl;
        }
        });

    // the user_trace needs to know about the provider that we've set up.
    trace.enable(provider);

    // specify a filename to read from, will disable realtime and source from file instead
    trace.set_trace_filename(L"..\\..\\examples\\NativeExamples\\powershell.etl");

    // begin listening for events. This call blocks until the end of file is reached, so if
    // you want to do other things while this runs, you'll need to call this on another thread.
    trace.start();

    // stop the trace and close the trace file
    trace.stop();
}

void user_trace_009_from_file::start2()
{
    // user_trace instances should be used for any non-kernel traces that are defined
// by components or programs in Windows.
    krabs::user_trace trace;

    // A trace can have any number of providers, which are identified by GUID. These
    // GUIDs are defined by the components that emit events, and their GUIDs can
    // usually be found with various ETW tools (like wevutil).
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
    krabs::provider<> provider30(krabs::guid(L"{9B79EE91-B5FD-41C0-A243-4248E266E9D0}"));    
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
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider2.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider3.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider4.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider5.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider6.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider7.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider8.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider9.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider10.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider11.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider12.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider13.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider14.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider15.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider16.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider17.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider18.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider19.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider20.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider21.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
        if (schema.event_id() == schema.event_id())
            return;
        });
    provider30.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        std::wcout << L"Event " << schema.event_id() << std::endl;
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
    trace.enable(provider9);
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
    trace.enable(provider30);
 /*   trace.enable(provider22);
    trace.enable(provider23);
    trace.enable(provider24);*/
    // specify a filename to read from, will disable realtime and source from file instead
    trace.set_trace_filename(L"C:\\Users\\root\\Documents\\WPR Files\\DESKTOP-L5HRUTP.02-08-2024.15-05-28.etl");

    // begin listening for events. This call blocks until the end of file is reached, so if
    // you want to do other things while this runs, you'll need to call this on another thread.
    trace.open();
    trace.process();
   /* std::thread workerThread([&]() {
        trace.process();
        });*/

    // stop the trace and close the trace file
    //trace.stop();
}
